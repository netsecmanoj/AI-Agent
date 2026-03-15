"""Deterministic CI policy evaluation for completed scans."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from backend.app.core.config import get_settings
from backend.app.models.project import Project
from backend.app.models.scan import ScanJob
from backend.app.schemas.scan import PolicyEvaluationRead, PolicyRuleRead


@dataclass(slots=True)
class PolicyConfig:
    """Resolved policy thresholds and rule toggles."""

    fail_severity_threshold: str = "critical"
    fail_on_new_critical: bool = True
    max_new_high_findings: int = 0
    max_weighted_risk_delta: int = 5
    warn_on_any_high_findings: bool = True
    warn_on_partial_scan: bool = True

    @classmethod
    def from_settings(cls) -> "PolicyConfig":
        """Build policy defaults from application settings."""
        settings = get_settings()
        fail_threshold = settings.ci_default_fail_severity.strip().lower() or "critical"
        return cls(
            fail_severity_threshold=fail_threshold,
            fail_on_new_critical=settings.policy_fail_on_new_critical,
            max_new_high_findings=settings.policy_max_new_high_findings,
            max_weighted_risk_delta=settings.policy_max_weighted_risk_delta,
            warn_on_any_high_findings=settings.policy_warn_on_any_high_findings,
            warn_on_partial_scan=settings.policy_warn_on_partial_scan,
        )


@dataclass(slots=True)
class ResolvedPolicyConfig:
    """Policy config plus source metadata for UI, reports, and APIs."""

    config: PolicyConfig
    preset: str | None = None
    source: str = "global_default"
    overrides: dict[str, Any] = field(default_factory=dict)

    def payload(self) -> dict[str, Any]:
        payload = asdict(self.config)
        payload.update(
            {
                "preset": self.preset,
                "source": self.source,
                "overrides": self.overrides,
            }
        )
        return payload


class PolicyEvaluationService:
    """Evaluate a scan against deterministic CI-oriented policy rules."""

    severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
    severity_rank = {severity: index for index, severity in enumerate(severity_order)}
    severity_options = ["disabled", *severity_order]
    policy_presets: dict[str, PolicyConfig] = {
        "strict": PolicyConfig(
            fail_severity_threshold="high",
            fail_on_new_critical=True,
            max_new_high_findings=0,
            max_weighted_risk_delta=0,
            warn_on_any_high_findings=True,
            warn_on_partial_scan=True,
        ),
        "balanced": PolicyConfig(
            fail_severity_threshold="critical",
            fail_on_new_critical=True,
            max_new_high_findings=0,
            max_weighted_risk_delta=5,
            warn_on_any_high_findings=True,
            warn_on_partial_scan=True,
        ),
        "advisory": PolicyConfig(
            fail_severity_threshold="disabled",
            fail_on_new_critical=False,
            max_new_high_findings=999999,
            max_weighted_risk_delta=999999,
            warn_on_any_high_findings=True,
            warn_on_partial_scan=True,
        ),
    }

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.default_config = config

    @classmethod
    def preset_names(cls) -> list[str]:
        """Return supported preset names in stable order."""
        return ["strict", "balanced", "advisory"]

    def resolve_project_policy(self, project: Project | None) -> ResolvedPolicyConfig:
        """Resolve the effective policy for a project using defaults, preset, and overrides."""
        config = self.default_config or PolicyConfig.from_settings()
        preset: str | None = None
        source = "global_default"
        overrides: dict[str, Any] = {}

        if project and project.policy_preset:
            preset_name = project.policy_preset.strip().lower()
            preset_config = self.policy_presets.get(preset_name)
            if preset_config is not None:
                config = PolicyConfig(**asdict(preset_config))
                preset = preset_name
                source = "project_preset"

        if project:
            override_map = {
                "fail_severity_threshold": self._normalize_severity_override(project.policy_fail_severity_threshold),
                "max_new_high_findings": project.policy_max_new_high_findings,
                "max_weighted_risk_delta": project.policy_max_weighted_risk_delta,
                "warn_on_partial_scan": project.policy_warn_on_partial_scan,
                "warn_on_any_high_findings": project.policy_warn_on_any_high_findings,
            }
            for key, value in override_map.items():
                if value is None:
                    continue
                setattr(config, key, value)
                overrides[key] = value
            if overrides:
                source = "project_override"

        return ResolvedPolicyConfig(config=config, preset=preset, source=source, overrides=overrides)

    def evaluate_scan(
        self,
        scan_job: ScanJob,
        comparison: dict[str, Any] | None = None,
        *,
        project: Project | None = None,
    ) -> PolicyEvaluationRead:
        """Evaluate one scan using persisted findings and optional comparison data."""
        resolved = self.resolve_project_policy(project or scan_job.project)
        config = resolved.config
        comparison_available = bool(comparison and comparison.get("comparison_available"))
        if scan_job.status in {"queued", "running"}:
            return PolicyEvaluationRead(
                status="pending",
                decision_ready=False,
                should_fail_ci=False,
                comparison_available=comparison_available,
                reasons=[f"Policy evaluation is pending while scan status is {scan_job.status}."],
                rules=[],
                config=resolved.payload(),
                metrics={},
            )

        if scan_job.status == "failed":
            failed_rule = PolicyRuleRead(
                rule_id="scan_execution_failed",
                outcome="failed",
                triggered=True,
                reason="The scan job failed before a complete policy evaluation could be produced.",
            )
            return PolicyEvaluationRead(
                status="fail",
                decision_ready=True,
                should_fail_ci=True,
                comparison_available=comparison_available,
                reasons=[failed_rule.reason],
                rules=[failed_rule],
                config=resolved.payload(),
                metrics={},
            )

        severity_counts = Counter(finding.severity for finding in scan_job.findings)
        new_groups = comparison.get("new_groups", []) if comparison_available else []
        current_threshold_count = self._count_at_or_above(
            severity_counts,
            config.fail_severity_threshold,
        )
        current_high_count = severity_counts.get("high", 0) + severity_counts.get("critical", 0)
        new_critical_count = sum(
            int(group.get("current_member_count", 0))
            for group in new_groups
            if group.get("severity") == "critical"
        )
        new_high_count = sum(
            int(group.get("current_member_count", 0))
            for group in new_groups
            if group.get("severity") == "high"
        )
        risk_delta = None
        if comparison_available:
            risk_delta = comparison.get("grouped_delta", {}).get("delta_risk_score")

        rules = [
            self._current_severity_rule(config, current_threshold_count),
            self._new_critical_rule(config, comparison_available, new_critical_count),
            self._new_high_rule(config, comparison_available, new_high_count),
            self._weighted_risk_rule(config, comparison_available, risk_delta),
            self._partial_scan_rule(config, scan_job.partial),
            self._warn_high_rule(config, current_high_count),
        ]

        failed_rules = [rule for rule in rules if rule.outcome == "failed" and rule.triggered]
        warned_rules = [rule for rule in rules if rule.outcome == "warned" and rule.triggered]
        if failed_rules:
            status = "fail"
        elif warned_rules:
            status = "warn"
        else:
            status = "pass"

        reasons = [rule.reason for rule in [*failed_rules, *warned_rules]] or ["No policy rules triggered."]
        return PolicyEvaluationRead(
            status=status,
            decision_ready=True,
            should_fail_ci=status == "fail",
            comparison_available=comparison_available,
            reasons=reasons,
            rules=rules,
            config=resolved.payload(),
            metrics={
                "current_fail_threshold_count": current_threshold_count,
                "current_high_or_critical_count": current_high_count,
                "new_critical_count": new_critical_count,
                "new_high_count": new_high_count,
                "weighted_risk_delta": risk_delta,
            },
        )

    def _current_severity_rule(self, config: PolicyConfig, current_threshold_count: int) -> PolicyRuleRead:
        threshold = config.fail_severity_threshold
        if threshold == "disabled":
            return PolicyRuleRead(
                rule_id="current_severity_threshold",
                outcome="skipped",
                triggered=False,
                reason="Current severity threshold failures are disabled for this policy.",
            )
        if threshold not in self.severity_rank:
            return PolicyRuleRead(
                rule_id="current_severity_threshold",
                outcome="skipped",
                triggered=False,
                reason=f"Severity threshold {threshold!r} is not recognized.",
            )
        if current_threshold_count > 0:
            return PolicyRuleRead(
                rule_id="current_severity_threshold",
                outcome="failed",
                triggered=True,
                reason=(
                    f"The scan contains {current_threshold_count} finding(s) at or above the "
                    f"{threshold} severity threshold."
                ),
            )
        return PolicyRuleRead(
            rule_id="current_severity_threshold",
            outcome="passed",
            triggered=False,
            reason=f"No findings at or above the {threshold} severity threshold were detected.",
        )

    def _new_critical_rule(
        self,
        config: PolicyConfig,
        comparison_available: bool,
        new_critical_count: int,
    ) -> PolicyRuleRead:
        if not config.fail_on_new_critical:
            return PolicyRuleRead(
                rule_id="new_critical_findings",
                outcome="skipped",
                triggered=False,
                reason="The new critical findings rule is disabled.",
            )
        if not comparison_available:
            return PolicyRuleRead(
                rule_id="new_critical_findings",
                outcome="skipped",
                triggered=False,
                reason="No previous scan is available, so new critical findings cannot be evaluated.",
            )
        if new_critical_count > 0:
            return PolicyRuleRead(
                rule_id="new_critical_findings",
                outcome="failed",
                triggered=True,
                reason=f"The scan introduced {new_critical_count} new critical finding(s).",
            )
        return PolicyRuleRead(
            rule_id="new_critical_findings",
            outcome="passed",
            triggered=False,
            reason="No new critical findings were introduced.",
        )

    def _new_high_rule(
        self,
        config: PolicyConfig,
        comparison_available: bool,
        new_high_count: int,
    ) -> PolicyRuleRead:
        if not comparison_available:
            return PolicyRuleRead(
                rule_id="new_high_threshold",
                outcome="skipped",
                triggered=False,
                reason="No previous scan is available, so new high-severity findings cannot be evaluated.",
            )
        if new_high_count > config.max_new_high_findings:
            return PolicyRuleRead(
                rule_id="new_high_threshold",
                outcome="failed",
                triggered=True,
                reason=(
                    f"The scan introduced {new_high_count} new high-severity finding(s), "
                    f"which exceeds the configured allowance of {config.max_new_high_findings}."
                ),
            )
        return PolicyRuleRead(
            rule_id="new_high_threshold",
            outcome="passed",
            triggered=False,
            reason=(
                f"New high-severity findings stayed within the configured allowance of "
                f"{config.max_new_high_findings}."
            ),
        )

    def _weighted_risk_rule(
        self,
        config: PolicyConfig,
        comparison_available: bool,
        risk_delta: int | None,
    ) -> PolicyRuleRead:
        if not comparison_available or risk_delta is None:
            return PolicyRuleRead(
                rule_id="weighted_risk_delta",
                outcome="skipped",
                triggered=False,
                reason="No previous scan is available, so weighted risk delta cannot be evaluated.",
            )
        if risk_delta > config.max_weighted_risk_delta:
            return PolicyRuleRead(
                rule_id="weighted_risk_delta",
                outcome="failed",
                triggered=True,
                reason=(
                    f"Weighted risk increased by {risk_delta}, which exceeds the configured allowance "
                    f"of {config.max_weighted_risk_delta}."
                ),
            )
        return PolicyRuleRead(
            rule_id="weighted_risk_delta",
            outcome="passed",
            triggered=False,
            reason=(
                f"Weighted risk delta {risk_delta} stayed within the configured allowance of "
                f"{config.max_weighted_risk_delta}."
            ),
        )

    def _partial_scan_rule(self, config: PolicyConfig, partial: bool) -> PolicyRuleRead:
        if not config.warn_on_partial_scan:
            return PolicyRuleRead(
                rule_id="partial_scan_warning",
                outcome="skipped",
                triggered=False,
                reason="Partial scan warnings are disabled.",
            )
        if partial:
            return PolicyRuleRead(
                rule_id="partial_scan_warning",
                outcome="warned",
                triggered=True,
                reason="The scan completed with partial tool coverage or tool errors.",
            )
        return PolicyRuleRead(
            rule_id="partial_scan_warning",
            outcome="passed",
            triggered=False,
            reason="The scan completed without partial coverage warnings.",
        )

    def _warn_high_rule(self, config: PolicyConfig, current_high_count: int) -> PolicyRuleRead:
        if not config.warn_on_any_high_findings:
            return PolicyRuleRead(
                rule_id="high_findings_warning",
                outcome="skipped",
                triggered=False,
                reason="High-severity warning mode is disabled.",
            )
        if current_high_count > 0:
            return PolicyRuleRead(
                rule_id="high_findings_warning",
                outcome="warned",
                triggered=True,
                reason=f"The scan still contains {current_high_count} high or critical finding(s).",
            )
        return PolicyRuleRead(
            rule_id="high_findings_warning",
            outcome="passed",
            triggered=False,
            reason="No high or critical findings remain in the current scan.",
        )

    def _count_at_or_above(self, severity_counts: Counter, threshold: str) -> int:
        if threshold == "disabled" or threshold not in self.severity_rank:
            return 0
        threshold_rank = self.severity_rank[threshold]
        return sum(
            count
            for severity, count in severity_counts.items()
            if self.severity_rank.get(severity, len(self.severity_order)) <= threshold_rank
        )

    @staticmethod
    def _normalize_severity_override(value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip().lower()
        return candidate or None
