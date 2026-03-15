"""Deterministic explanation and classification helpers for findings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

DEPENDENCY_TOOLS = {
    "pip-audit",
    "npm-audit",
    "dart-pub-outdated",
    "maven-pom-review",
    "composer-review",
    "go-mod-review",
    "dotnet-project-review",
}

DART_DIAGNOSTIC_REFERENCES = {
    "unused_import": {
        "reference_title": "Dart analyzer: unused_import",
        "reference_type": "official_docs",
        "reference_url": "https://dart.dev/tools/diagnostics/unused_import",
    },
    "undefined_identifier": {
        "reference_title": "Dart analyzer: undefined_identifier",
        "reference_type": "official_docs",
        "reference_url": "https://dart.dev/tools/diagnostics/undefined_identifier",
    },
    "undefined_getter": {
        "reference_title": "Dart analyzer: undefined_getter",
        "reference_type": "official_docs",
        "reference_url": "https://dart.dev/tools/diagnostics/undefined_getter",
    },
    "undefined_method": {
        "reference_title": "Dart analyzer: undefined_method",
        "reference_type": "official_docs",
        "reference_url": "https://dart.dev/tools/diagnostics/undefined_method",
    },
}


class FindingIntelligenceService:
    """Derive plain-language finding context without modifying raw evidence."""

    def enrich_finding(self, finding: Any) -> dict[str, Any]:
        """Return an additive intelligence payload for one finding."""
        payload = self._base_payload(finding)
        intelligence = self._derive(payload)
        return {**payload, **intelligence}

    def enrich_group(self, group: dict[str, Any]) -> dict[str, Any]:
        """Return an additive intelligence payload for one grouped finding."""
        intelligence = self._derive(group)
        return {**group, **intelligence}

    def sort_key(self, finding_or_group: dict[str, Any]) -> tuple[int, int, int, str]:
        """Return a triage-first sort key."""
        intelligence = self._derive(finding_or_group)
        priority_rank = {
            "security_risk": 0,
            "code_correctness": 1,
            "configuration_risk": 2,
            "dependency_hygiene": 3,
            "tooling_or_coverage": 4,
        }.get(intelligence["finding_type"], 5)
        impact_rank = {
            "security_exposure": 0,
            "build_failure": 1,
            "runtime_bug": 2,
            "compliance_or_hardening": 3,
            "scan_coverage_gap": 4,
        }.get(intelligence["impact_summary"], 5)
        severity_rank = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
            "unknown": 5,
        }.get(str(finding_or_group.get("severity", "unknown")).lower(), 5)
        return (
            priority_rank,
            impact_rank,
            severity_rank,
            str(finding_or_group.get("title", "")).lower(),
        )

    def _base_payload(self, finding: Any) -> dict[str, Any]:
        created_at = getattr(finding, "created_at", None)
        return {
            "id": getattr(finding, "id", None),
            "title": getattr(finding, "title", ""),
            "description": getattr(finding, "description", ""),
            "severity": getattr(finding, "severity", "unknown"),
            "category": getattr(finding, "category", ""),
            "tool_name": getattr(finding, "tool_name", ""),
            "file_path": getattr(finding, "file_path", None),
            "line_number": getattr(finding, "line_number", None),
            "remediation": getattr(finding, "remediation", None),
            "ai_status": getattr(finding, "ai_status", None),
            "ai_explanation": getattr(finding, "ai_explanation", None),
            "ai_remediation": getattr(finding, "ai_remediation", None),
            "ai_error": getattr(finding, "ai_error", None),
            "raw_payload": getattr(finding, "raw_payload", {}) or {},
            "created_at": created_at.isoformat() if created_at else None,
        }

    def _derive(self, data: dict[str, Any]) -> dict[str, Any]:
        title = str(data.get("title", ""))
        description = str(data.get("description", ""))
        severity = str(data.get("severity", "unknown")).lower()
        category = str(data.get("category", "")).lower()
        tool_name = str(data.get("tool_name", "")).lower()
        raw_payload = data.get("raw_payload") or {}
        rule_code = str(raw_payload.get("rule_code") or "").lower()
        tokens = " ".join(
            [
                title.lower(),
                description.lower(),
                category,
                tool_name,
                rule_code,
                str(raw_payload).lower(),
            ]
        )
        advisory_flag = self._has_advisory_flag(raw_payload, tokens)

        finding_type = self._classify_type(category, tool_name, tokens, advisory_flag)
        security_relevance = self._classify_security_relevance(finding_type, advisory_flag, tokens)
        impact_summary = self._classify_impact(category, tool_name, rule_code, finding_type, security_relevance, tokens)

        return {
            "finding_type": finding_type,
            "security_relevance": security_relevance,
            "impact_summary": impact_summary,
            "plain_explanation": self._plain_explanation(title, description, tool_name, rule_code, finding_type, tokens),
            "why_flagged": self._why_flagged(category, tool_name, rule_code, title, tokens),
            "app_impact": self._app_impact(impact_summary, security_relevance),
            "why_severity": self._why_severity(severity, finding_type, security_relevance, impact_summary),
            "recommended_action": self._recommended_action(data.get("remediation"), finding_type, impact_summary, title, rule_code),
            **self._reference_payload(category, tool_name, rule_code, finding_type, tokens),
        }

    def _classify_type(self, category: str, tool_name: str, tokens: str, advisory_flag: bool) -> str:
        if tool_name in {"tooling", "coverage"}:
            return "tooling_or_coverage"
        if tool_name == "dart-flutter-analyze" or category == "static_analysis":
            return "code_correctness"
        if category.startswith("dependency") or tool_name in DEPENDENCY_TOOLS:
            return "dependency_hygiene"
        security_tokens = (
            "cleartext",
            "transport security",
            "arbitrary loads",
            "hardcoded secret",
            "secret",
            "actuator",
            "management endpoint",
            "exported",
            "debuggable",
            "app_debug",
            "trust proxy",
            "httponly: false",
            "secure: false",
            "http://",
        )
        if advisory_flag or any(token in tokens for token in security_tokens):
            return "security_risk"
        if "config" in category or category.startswith("mobile_") or tool_name in {"framework-review", "flutter-mobile-config"}:
            return "configuration_risk"
        return "code_correctness"

    def _classify_security_relevance(self, finding_type: str, advisory_flag: bool, tokens: str) -> str:
        if finding_type == "code_correctness":
            return "none"
        if finding_type == "dependency_hygiene":
            return "direct" if advisory_flag else "indirect"
        if finding_type == "configuration_risk":
            return "indirect"
        if finding_type == "security_risk":
            if advisory_flag or any(token in tokens for token in ("hardcoded secret", "cleartext", "arbitrary loads", "http://", "actuator", "exported")):
                return "direct"
            return "indirect"
        return "none"

    def _classify_impact(
        self,
        category: str,
        tool_name: str,
        rule_code: str,
        finding_type: str,
        security_relevance: str,
        tokens: str,
    ) -> str:
        if finding_type == "tooling_or_coverage":
            return "scan_coverage_gap"
        if finding_type == "dependency_hygiene":
            return "security_exposure" if security_relevance == "direct" else "compliance_or_hardening"
        if finding_type in {"security_risk", "configuration_risk"}:
            if any(token in tokens for token in ("cleartext", "arbitrary loads", "hardcoded secret", "http://", "actuator", "exported")):
                return "security_exposure"
            return "compliance_or_hardening"
        if tool_name == "dart-flutter-analyze" or category == "static_analysis":
            if rule_code.startswith("undefined_"):
                return "build_failure"
            return "runtime_bug"
        return "runtime_bug"

    def _plain_explanation(
        self,
        title: str,
        description: str,
        tool_name: str,
        rule_code: str,
        finding_type: str,
        tokens: str,
    ) -> str:
        if tool_name == "dart-flutter-analyze" and rule_code == "undefined_identifier":
            return "The Dart analyzer found code that refers to a name that does not exist in the current scope."
        if tool_name == "dart-flutter-analyze" and rule_code == "unused_import":
            return "The Dart analyzer found an import that is no longer used by the file."
        if "cleartext" in tokens:
            return "The app configuration allows network traffic without transport encryption."
        if "arbitrary loads" in tokens:
            return "The iOS app configuration allows broad exceptions to App Transport Security."
        if finding_type == "dependency_hygiene":
            return "This dependency is behind, retracted, or otherwise flagged as needing review."
        if finding_type == "configuration_risk":
            return "This configuration choice weakens the app’s default hardening or operational safety."
        if finding_type == "security_risk":
            return "This finding points to a security-relevant weakness that may expose the application or data."
        return description or title

    def _why_flagged(self, category: str, tool_name: str, rule_code: str, title: str, tokens: str) -> str:
        if tool_name == "dart-flutter-analyze" and rule_code:
            return f"The Dart/Flutter analyzer emitted the `{rule_code}` diagnostic for this source location."
        if tool_name in DEPENDENCY_TOOLS:
            return f"{tool_name} flagged this dependency state from lockfile or manifest metadata."
        if "cleartext" in tokens:
            return "The scanner saw an explicit configuration that allows unencrypted HTTP traffic."
        if "actuator" in tokens:
            return "The framework review saw management or actuator settings that appear broadly exposed."
        return f"The finding was normalized from the `{tool_name}` result in category `{category}`."

    def _app_impact(self, impact_summary: str, security_relevance: str) -> str:
        if impact_summary == "build_failure":
            return "This is likely to break builds or prevent the application from compiling cleanly."
        if impact_summary == "runtime_bug":
            return "This is more likely to cause incorrect behavior, crashes, or maintenance friction than a direct security issue."
        if impact_summary == "security_exposure":
            return "This can increase the chance of data exposure, insecure behavior, or reachable attack surface in production."
        if impact_summary == "scan_coverage_gap":
            return "This does not describe app code risk directly; it means scan coverage was incomplete."
        if security_relevance == "indirect":
            return "This mainly affects hardening, upgrade posture, or long-term maintainability rather than being an immediate exploit."
        return "This affects operational hardening, compliance posture, or maintainability."

    def _why_severity(
        self,
        severity: str,
        finding_type: str,
        security_relevance: str,
        impact_summary: str,
    ) -> str:
        if finding_type == "code_correctness":
            return (
                f"The `{severity}` severity reflects likely correctness or build impact, "
                "not that the issue is automatically a security vulnerability."
            )
        if security_relevance == "direct":
            return f"The `{severity}` severity reflects a direct security or exposure concern."
        if impact_summary == "compliance_or_hardening":
            return f"The `{severity}` severity reflects hardening or maintenance risk more than immediate exploitability."
        return f"The `{severity}` severity reflects the normalized scanner output and expected application impact."

    def _recommended_action(
        self,
        remediation: Any,
        finding_type: str,
        impact_summary: str,
        title: str,
        rule_code: str,
    ) -> str:
        if remediation:
            return str(remediation)
        if finding_type == "dependency_hygiene":
            return "Review the affected dependency version, upgrade when safe, and document any accepted risk."
        if finding_type == "configuration_risk":
            return "Tighten the configuration to the safest production-ready setting and keep any exception narrow and documented."
        if finding_type == "security_risk":
            return "Address the exposed behavior first, then verify the safer setting with a targeted retest."
        if rule_code.startswith("undefined_"):
            return "Fix the missing symbol or incorrect API usage so the file builds cleanly again."
        return f"Review `{title}` with the owning team and resolve the underlying code or config issue."

    def _reference_payload(
        self,
        category: str,
        tool_name: str,
        rule_code: str,
        finding_type: str,
        tokens: str,
    ) -> dict[str, str | None]:
        if tool_name == "dart-flutter-analyze" and rule_code in DART_DIAGNOSTIC_REFERENCES:
            return DART_DIAGNOSTIC_REFERENCES[rule_code]
        if "cleartext" in tokens:
            return {
                "reference_title": "Android cleartext traffic guidance",
                "reference_type": "platform_docs",
                "reference_url": "https://developer.android.com/privacy-and-security/risks/cleartext-communications",
            }
        if "arbitrary loads" in tokens or "app transport security" in tokens:
            return {
                "reference_title": "Apple App Transport Security",
                "reference_type": "platform_docs",
                "reference_url": "https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity",
            }
        if "hardcoded secret" in tokens or ("secret" in tokens and finding_type == "security_risk"):
            return {
                "reference_title": "OWASP Secrets Management Cheat Sheet",
                "reference_type": "owasp",
                "reference_url": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            }
        if "actuator" in tokens:
            return {
                "reference_title": "Spring Boot Actuator endpoints",
                "reference_type": "framework_docs",
                "reference_url": "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html",
            }
        if tool_name == "dart-pub-outdated":
            return {
                "reference_title": "Dart pub outdated",
                "reference_type": "official_docs",
                "reference_url": "https://dart.dev/tools/pub/cmd/pub-outdated",
            }
        if tool_name == "npm-audit":
            return {
                "reference_title": "npm audit",
                "reference_type": "official_docs",
                "reference_url": "https://docs.npmjs.com/cli/v10/commands/npm-audit",
            }
        if tool_name == "pip-audit":
            return {
                "reference_title": "pip-audit",
                "reference_type": "official_docs",
                "reference_url": "https://github.com/pypa/pip-audit",
            }
        if tool_name == "framework-review" and "trust proxy" in tokens:
            return {
                "reference_title": "Express behind proxies",
                "reference_type": "framework_docs",
                "reference_url": "https://expressjs.com/en/guide/behind-proxies.html",
            }
        if tool_name == "framework-review" and "app_debug" in tokens:
            return {
                "reference_title": "Laravel configuration",
                "reference_type": "framework_docs",
                "reference_url": "https://laravel.com/docs/configuration",
            }
        return {
            "reference_title": None,
            "reference_type": None,
            "reference_url": None,
        }

    @staticmethod
    def _has_advisory_flag(raw_payload: dict[str, Any], tokens: str) -> bool:
        risk_flags = raw_payload.get("risk_flags") or {}
        if any(bool(value) for value in risk_flags.values()):
            return True
        return any(token in tokens for token in ("advisory", "vulnerab", "retracted", "discontinued"))
