"""Deterministic framework-aware configuration and source review checks."""

from __future__ import annotations

from pathlib import Path
import re

from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.ecosystem_service import EcosystemDetectionService, EcosystemInventory


class FrameworkReviewScannerAdapter(ScannerAdapter):
    """Review supported framework configs and source files for first-pass risky patterns."""

    tool_name = "framework-review"

    _SPRING_PATTERNS = (
        (
            re.compile(r"management\.endpoints\.web\.exposure\.include\s*[:=]\s*['\"]?\*['\"]?"),
            "Spring actuator web endpoints are broadly exposed",
            (
                "Spring management endpoint exposure includes `*`, which can expose operational "
                "or sensitive actuator endpoints over HTTP."
            ),
            "high",
            "management_exposure",
            "Restrict exposed actuator endpoints to the minimal reviewed set required for operations.",
            "actuator-exposure-all",
        ),
        (
            re.compile(r"(management\.server\.address|server\.address)\s*[:=]\s*['\"]?0\.0\.0\.0['\"]?"),
            "Spring service binds broadly on all interfaces",
            (
                "Spring configuration binds the application or management server to 0.0.0.0, "
                "which broadens network exposure and should be reviewed."
            ),
            "medium",
            "framework_configuration",
            "Bind services only to the required interfaces and review exposure through upstream ingress controls.",
            "broad-bind-address",
        ),
        (
            re.compile(r"spring\.profiles\.active\s*[:=]\s*['\"]?dev['\"]?"),
            "Spring dev profile is enabled in configuration",
            (
                "Spring configuration explicitly activates the `dev` profile, which can enable "
                "development-only behavior in shared environments."
            ),
            "medium",
            "debug_configuration",
            "Remove dev profile defaults from committed configuration and activate them only in controlled local environments.",
            "dev-profile",
        ),
    )
    _LARAVEL_ENV_PATTERNS = (
        (
            re.compile(r"APP_DEBUG\s*=\s*true", re.IGNORECASE),
            "Laravel APP_DEBUG is enabled",
            (
                "Laravel environment configuration enables APP_DEBUG, which can expose stack traces "
                "and internal details if used outside local development."
            ),
            "high",
            "debug_configuration",
            "Set APP_DEBUG=false for shared and production-like environments.",
            "app-debug",
        ),
        (
            re.compile(r"APP_URL\s*=\s*http://", re.IGNORECASE),
            "Laravel APP_URL uses HTTP",
            (
                "Laravel environment configuration uses an HTTP APP_URL, which may encourage insecure "
                "transport assumptions in generated links or callbacks."
            ),
            "medium",
            "insecure_transport",
            "Use an HTTPS APP_URL for deployed environments unless the application is strictly internal and transport is otherwise protected.",
            "app-url-http",
        ),
    )
    _LARAVEL_PROXY_PATTERN = re.compile(r"protected\s+\$proxies\s*=\s*['\"]\*['\"]", re.IGNORECASE)
    _EXPRESS_PATTERNS = (
        (
            re.compile(r"app\.set\(\s*['\"]trust proxy['\"]\s*,\s*true\s*\)"),
            "Express trust proxy is globally enabled",
            (
                "Express sets `trust proxy` to true, which trusts upstream proxy headers and should "
                "be limited to known reverse-proxy deployments."
            ),
            "medium",
            "framework_configuration",
            "Scope `trust proxy` to the known proxy hop count or reviewed proxy ranges instead of enabling it globally.",
            "trust-proxy-true",
        ),
        (
            re.compile(r"httpOnly\s*:\s*false"),
            "Express cookie/session configuration disables httpOnly",
            (
                "Express cookie or session configuration sets `httpOnly: false`, which allows client-side "
                "scripts to access session cookies."
            ),
            "high",
            "framework_configuration",
            "Set `httpOnly: true` for session and authentication cookies unless a reviewed exception exists.",
            "cookie-http-only-disabled",
        ),
        (
            re.compile(r"secure\s*:\s*false"),
            "Express cookie/session configuration disables secure cookies",
            (
                "Express cookie or session configuration sets `secure: false`, which permits cookies "
                "to be sent over unencrypted HTTP."
            ),
            "medium",
            "insecure_transport",
            "Set `secure: true` for session and authentication cookies in deployed environments.",
            "cookie-secure-disabled",
        ),
    )
    _FLUTTER_HTTP_PATTERN = re.compile(r"['\"]http://[^'\"]+['\"]")
    _FLUTTER_SECRET_PATTERN = re.compile(
        r"\b(?:const\s+)?(?:final\s+)?(?:String\s+)?(?:api[_-]?key|secret|token|password|clientSecret)\b"
        r"[A-Za-z0-9_]*\s*[:=]\s*['\"][A-Za-z0-9_\-\/+=]{12,}['\"]",
        re.IGNORECASE,
    )
    _FLUTTER_LOGGING_PATTERN = re.compile(
        r"\b(?:print|debugPrint)\s*\([^)]*\b(?:token|secret|password|api[_-]?key|authorization)\b",
        re.IGNORECASE,
    )

    def __init__(self, ecosystem_service: EcosystemDetectionService | None = None) -> None:
        self.ecosystem_service = ecosystem_service or EcosystemDetectionService()

    def scan(self, target_path: Path) -> ToolExecutionResult:
        inventory = self.ecosystem_service.detect(target_path)
        if not inventory.frameworks:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message=None,
            )

        findings: list[NormalizedFinding] = []
        errors: list[str] = []

        if "spring" in inventory.frameworks:
            findings.extend(self._scan_spring(target_path, inventory, errors))
        if "laravel" in inventory.frameworks:
            findings.extend(self._scan_laravel(target_path, inventory, errors))
        if "express" in inventory.frameworks:
            findings.extend(self._scan_express(target_path, inventory, errors))
        if "flutter_app" in inventory.frameworks:
            findings.extend(self._scan_flutter(target_path, inventory, errors))

        status = "completed" if findings or not errors else "failed"
        return ToolExecutionResult(
            tool_name=self.tool_name,
            status=status,
            command="framework-review:file-and-source",
            findings=findings,
            partial=bool(errors),
            error_message="\n".join(errors) if errors else None,
        )

    def _scan_spring(
        self,
        target_path: Path,
        inventory: EcosystemInventory,
        errors: list[str],
    ) -> list[NormalizedFinding]:
        detail = inventory.framework_detail_for("spring")
        findings: list[NormalizedFinding] = []
        for config_path in detail.audit_files:
            findings.extend(
                self._scan_text_patterns(
                    target_path=target_path,
                    file_path=config_path,
                    errors=errors,
                    framework="spring",
                    patterns=self._SPRING_PATTERNS,
                )
            )
        return findings

    def _scan_laravel(
        self,
        target_path: Path,
        inventory: EcosystemInventory,
        errors: list[str],
    ) -> list[NormalizedFinding]:
        detail = inventory.framework_detail_for("laravel")
        findings: list[NormalizedFinding] = []
        for config_path in detail.audit_files:
            if config_path.name in {".env", ".env.example"}:
                findings.extend(
                    self._scan_text_patterns(
                        target_path=target_path,
                        file_path=config_path,
                        errors=errors,
                        framework="laravel",
                        patterns=self._LARAVEL_ENV_PATTERNS,
                    )
                )

        for trust_proxy_path in target_path.rglob("TrustProxies.php"):
            content = self._safe_read_text(trust_proxy_path, errors)
            if content is None:
                continue
            for line_number, line in enumerate(content.splitlines(), start=1):
                if not self._LARAVEL_PROXY_PATTERN.search(line):
                    continue
                findings.append(
                    self._build_finding(
                        framework="laravel",
                        title="Laravel trusts all proxies",
                        description=(
                            "Laravel TrustProxies configuration trusts all proxy addresses, which can "
                            "increase reliance on untrusted forwarded headers."
                        ),
                        severity="medium",
                        category="framework_configuration",
                        file_path=self._relative_path(target_path, trust_proxy_path),
                        line_number=line_number,
                        remediation="Restrict trusted proxies to the reviewed proxy addresses or infrastructure ranges actually used in deployment.",
                        check_id="trust-all-proxies",
                        evidence=line.strip(),
                    )
                )
        return findings

    def _scan_express(
        self,
        target_path: Path,
        inventory: EcosystemInventory,
        errors: list[str],
    ) -> list[NormalizedFinding]:
        detail = inventory.framework_detail_for("express")
        findings: list[NormalizedFinding] = []
        for entrypoint_path in detail.audit_files:
            findings.extend(
                self._scan_text_patterns(
                    target_path=target_path,
                    file_path=entrypoint_path,
                    errors=errors,
                    framework="express",
                    patterns=self._EXPRESS_PATTERNS,
                )
            )
        return findings

    def _scan_flutter(
        self,
        target_path: Path,
        inventory: EcosystemInventory,
        errors: list[str],
    ) -> list[NormalizedFinding]:
        detail = inventory.framework_detail_for("flutter_app")
        findings: list[NormalizedFinding] = []
        for source_path in detail.audit_files:
            content = self._safe_read_text(source_path, errors)
            if content is None:
                continue
            relative_path = self._relative_path(target_path, source_path)
            for line_number, line in enumerate(content.splitlines(), start=1):
                stripped = line.strip()
                if self._FLUTTER_HTTP_PATTERN.search(line):
                    findings.append(
                        self._build_finding(
                            framework="flutter_app",
                            title="Flutter source uses a cleartext HTTP endpoint",
                            description=(
                                "Dart source includes a literal `http://` endpoint, which suggests "
                                "cleartext transport in application networking code."
                            ),
                            severity="medium",
                            category="insecure_transport",
                            file_path=relative_path,
                            line_number=line_number,
                            remediation="Prefer HTTPS endpoints and keep non-production cleartext endpoints out of committed source files.",
                            check_id="http-endpoint",
                            evidence=stripped,
                        )
                    )
                if self._FLUTTER_SECRET_PATTERN.search(line):
                    findings.append(
                        self._build_finding(
                            framework="flutter_app",
                            title="Flutter source appears to contain a hardcoded secret",
                            description=(
                                "Dart source contains a high-confidence secret-like assignment for an "
                                "API key, token, password, or similar credential."
                            ),
                            severity="high",
                            category="hardcoded_secret",
                            file_path=relative_path,
                            line_number=line_number,
                            remediation="Move secrets out of source control and load them from a reviewed runtime secret source.",
                            check_id="hardcoded-secret",
                            evidence=stripped,
                        )
                    )
                if self._FLUTTER_LOGGING_PATTERN.search(line):
                    findings.append(
                        self._build_finding(
                            framework="flutter_app",
                            title="Flutter source logs sensitive authentication material",
                            description=(
                                "Dart source logs token, secret, password, API key, or authorization data, "
                                "which can leak sensitive values into device logs."
                            ),
                            severity="medium",
                            category="sensitive_logging",
                            file_path=relative_path,
                            line_number=line_number,
                            remediation="Remove sensitive values from logging statements or replace them with reviewed redaction-safe placeholders.",
                            check_id="sensitive-logging",
                            evidence=stripped,
                        )
                    )
        return findings

    def _scan_text_patterns(
        self,
        *,
        target_path: Path,
        file_path: Path,
        errors: list[str],
        framework: str,
        patterns: tuple[tuple[re.Pattern[str], str, str, str, str, str, str], ...],
    ) -> list[NormalizedFinding]:
        content = self._safe_read_text(file_path, errors)
        if content is None:
            return []
        findings: list[NormalizedFinding] = []
        relative_path = self._relative_path(target_path, file_path)
        for line_number, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            for (
                pattern,
                title,
                description,
                severity,
                category,
                remediation,
                check_id,
            ) in patterns:
                if not pattern.search(line):
                    continue
                findings.append(
                    self._build_finding(
                        framework=framework,
                        title=title,
                        description=description,
                        severity=severity,
                        category=category,
                        file_path=relative_path,
                        line_number=line_number,
                        remediation=remediation,
                        check_id=check_id,
                        evidence=stripped,
                    )
                )
        return findings

    def _build_finding(
        self,
        *,
        framework: str,
        title: str,
        description: str,
        severity: str,
        category: str,
        file_path: str,
        line_number: int,
        remediation: str,
        check_id: str,
        evidence: str,
    ) -> NormalizedFinding:
        return NormalizedFinding(
            title=title,
            description=description,
            severity=severity,
            category=category,
            tool_name=self.tool_name,
            file_path=file_path,
            line_number=line_number,
            remediation=remediation,
            raw_payload={
                "framework": framework,
                "check": check_id,
                "evidence": evidence,
            },
        )

    @staticmethod
    def _safe_read_text(path: Path, errors: list[str]) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{path.name}: file could not be read ({exc}).")
            return None

    @staticmethod
    def _relative_path(target_path: Path, file_path: Path) -> str:
        try:
            return str(file_path.relative_to(target_path))
        except ValueError:
            return file_path.name
