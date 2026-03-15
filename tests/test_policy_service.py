"""Tests for deterministic CI policy evaluation."""

from __future__ import annotations

from datetime import datetime, timezone

from backend.app.models.project import Project
from backend.app.models.scan import Finding, ScanJob
from backend.app.services.policy_service import PolicyConfig, PolicyEvaluationService


def test_policy_fails_when_critical_findings_exist() -> None:
    project = Project(id="project-1", name="demo", source_type="manual", source_value="")
    scan_job = ScanJob(
        id="scan-critical",
        project_id=project.id,
        project=project,
        status="completed",
        source_type="local_path",
        source_value="/tmp/demo",
        created_at=datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc),
    )
    scan_job.findings = [
        Finding(
            id="finding-1",
            project_id=project.id,
            scan_job_id=scan_job.id,
            title="Critical issue",
            description="Critical issue",
            severity="critical",
            category="code",
            tool_name="semgrep",
            raw_payload={},
        )
    ]

    policy = PolicyEvaluationService(
        PolicyConfig(
            fail_severity_threshold="critical",
            fail_on_new_critical=True,
            max_new_high_findings=0,
            max_weighted_risk_delta=5,
            warn_on_any_high_findings=True,
            warn_on_partial_scan=True,
        )
    ).evaluate_scan(scan_job)

    assert policy.status == "fail"
    assert policy.should_fail_ci is True
    assert any(rule.rule_id == "current_severity_threshold" and rule.triggered for rule in policy.rules)


def test_policy_warns_without_previous_scan_when_high_findings_remain() -> None:
    project = Project(id="project-1", name="demo", source_type="manual", source_value="")
    scan_job = ScanJob(
        id="scan-high",
        project_id=project.id,
        project=project,
        status="completed",
        partial=True,
        source_type="local_path",
        source_value="/tmp/demo",
        created_at=datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc),
    )
    scan_job.findings = [
        Finding(
            id="finding-1",
            project_id=project.id,
            scan_job_id=scan_job.id,
            title="High issue",
            description="High issue",
            severity="high",
            category="code",
            tool_name="semgrep",
            raw_payload={},
        )
    ]

    policy = PolicyEvaluationService(
        PolicyConfig(
            fail_severity_threshold="critical",
            fail_on_new_critical=True,
            max_new_high_findings=0,
            max_weighted_risk_delta=5,
            warn_on_any_high_findings=True,
            warn_on_partial_scan=True,
        )
    ).evaluate_scan(scan_job)

    assert policy.status == "warn"
    assert policy.should_fail_ci is False
    assert any(rule.rule_id == "new_critical_findings" and rule.outcome == "skipped" for rule in policy.rules)
    assert any(rule.rule_id == "partial_scan_warning" and rule.triggered for rule in policy.rules)


def test_policy_fails_when_regression_thresholds_are_exceeded() -> None:
    project = Project(id="project-1", name="demo", source_type="manual", source_value="")
    scan_job = ScanJob(
        id="scan-regression",
        project_id=project.id,
        project=project,
        status="completed",
        source_type="local_path",
        source_value="/tmp/demo",
        created_at=datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc),
    )
    scan_job.findings = [
        Finding(
            id="finding-1",
            project_id=project.id,
            scan_job_id=scan_job.id,
            title="High issue",
            description="High issue",
            severity="high",
            category="code",
            tool_name="semgrep",
            raw_payload={},
        )
    ]
    comparison = {
        "comparison_available": True,
        "new_groups": [
            {"severity": "critical", "current_member_count": 1},
            {"severity": "high", "current_member_count": 2},
        ],
        "grouped_delta": {"delta_risk_score": 9},
    }

    policy = PolicyEvaluationService(
        PolicyConfig(
            fail_severity_threshold="critical",
            fail_on_new_critical=True,
            max_new_high_findings=1,
            max_weighted_risk_delta=5,
            warn_on_any_high_findings=False,
            warn_on_partial_scan=False,
        )
    ).evaluate_scan(scan_job, comparison=comparison)

    assert policy.status == "fail"
    assert any(rule.rule_id == "new_critical_findings" and rule.triggered for rule in policy.rules)
    assert any(rule.rule_id == "new_high_threshold" and rule.triggered for rule in policy.rules)
    assert any(rule.rule_id == "weighted_risk_delta" and rule.triggered for rule in policy.rules)


def test_policy_resolves_preset_and_project_overrides() -> None:
    project = Project(
        id="project-policy",
        name="demo",
        source_type="manual",
        source_value="",
        policy_preset="strict",
        policy_max_weighted_risk_delta=4,
        policy_warn_on_any_high_findings=False,
    )

    resolved = PolicyEvaluationService().resolve_project_policy(project)

    assert resolved.preset == "strict"
    assert resolved.source == "project_override"
    assert resolved.config.fail_severity_threshold == "high"
    assert resolved.config.max_weighted_risk_delta == 4
    assert resolved.config.warn_on_any_high_findings is False
    assert resolved.overrides == {
        "max_weighted_risk_delta": 4,
        "warn_on_any_high_findings": False,
    }


def test_policy_falls_back_to_global_defaults_when_no_project_override(monkeypatch) -> None:
    settings = __import__("backend.app.core.config", fromlist=["get_settings"]).get_settings()
    monkeypatch.setattr(settings, "ci_default_fail_severity", "medium")
    monkeypatch.setattr(settings, "policy_max_new_high_findings", 2)
    monkeypatch.setattr(settings, "policy_warn_on_partial_scan", False)

    resolved = PolicyEvaluationService().resolve_project_policy(None)

    assert resolved.preset is None
    assert resolved.source == "global_default"
    assert resolved.config.fail_severity_threshold == "medium"
    assert resolved.config.max_new_high_findings == 2
    assert resolved.config.warn_on_partial_scan is False


def test_policy_evaluation_uses_project_specific_settings() -> None:
    project = Project(
        id="project-advisory",
        name="demo",
        source_type="manual",
        source_value="",
        policy_preset="advisory",
        policy_warn_on_partial_scan=False,
    )
    scan_job = ScanJob(
        id="scan-advisory",
        project_id=project.id,
        project=project,
        status="completed",
        partial=False,
        source_type="local_path",
        source_value="/tmp/demo",
        created_at=datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc),
    )
    scan_job.findings = [
        Finding(
            id="finding-1",
            project_id=project.id,
            scan_job_id=scan_job.id,
            title="Critical issue",
            description="Critical issue",
            severity="critical",
            category="code",
            tool_name="semgrep",
            raw_payload={},
        )
    ]

    policy = PolicyEvaluationService().evaluate_scan(scan_job, comparison={"comparison_available": False})

    assert policy.status == "warn"
    assert policy.should_fail_ci is False
    assert policy.config["preset"] == "advisory"
    assert policy.config["fail_severity_threshold"] == "disabled"
    assert any(rule.rule_id == "current_severity_threshold" and rule.outcome == "skipped" for rule in policy.rules)
