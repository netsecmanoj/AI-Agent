"""npm audit scanner adapter for Node/JavaScript dependency vulnerability auditing."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

from backend.app.core.config import get_settings
from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.ecosystem_service import EcosystemDetectionService
from backend.app.services.severity import normalize_severity

settings = get_settings()


class NpmAuditScannerAdapter(ScannerAdapter):
    """Run npm audit when Node manifests and lockfiles are present."""

    tool_name = "npm-audit"

    def __init__(self, ecosystem_service: EcosystemDetectionService | None = None) -> None:
        self.ecosystem_service = ecosystem_service or EcosystemDetectionService()

    def scan(self, target_path: Path) -> ToolExecutionResult:
        inventory = self.ecosystem_service.detect(target_path)
        if not inventory.has("node"):
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message=None,
            )

        lockfiles = self.ecosystem_service.find_node_lockfiles(target_path)
        if not lockfiles:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message="Node ecosystem detected but no package-lock.json or npm-shrinkwrap.json was found for npm audit.",
            )

        if shutil.which(settings.npm_command) is None:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=f"{settings.npm_command} audit --json",
                findings=[],
                partial=True,
                error_message="npm is not installed or not available in PATH.",
            )

        findings: list[NormalizedFinding] = []
        errors: list[str] = []
        executed_commands: list[str] = []
        successful_runs = 0
        executed_directories: set[Path] = set()

        for lockfile in lockfiles:
            working_directory = lockfile.parent
            if working_directory in executed_directories:
                continue
            executed_directories.add(working_directory)
            command = [settings.npm_command, "audit", "--json"]
            executed_commands.append(f"(cd {working_directory} && {' '.join(command)})")
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    cwd=working_directory,
                    timeout=settings.npm_audit_timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                errors.append(f"{working_directory.name or '.'}: npm audit execution timed out.")
                continue

            stdout = completed.stdout.strip()
            stderr = completed.stderr.strip()
            if completed.returncode not in {0, 1}:
                errors.append(
                    f"{working_directory.name or '.'}: {stderr or 'npm audit returned a non-zero exit code.'}"
                )
                continue

            try:
                payload = json.loads(stdout or "{}")
            except json.JSONDecodeError:
                errors.append(f"{working_directory.name or '.'}: npm audit output was not valid JSON.")
                continue

            successful_runs += 1
            findings.extend(self._parse_results(payload, target_path=target_path, working_directory=working_directory))
            if stderr:
                errors.append(f"{working_directory.name or '.'}: {stderr}")

        if successful_runs == 0:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="failed",
                command=" ; ".join(executed_commands) if executed_commands else None,
                findings=[],
                partial=True,
                error_message="\n".join(errors) if errors else "npm audit did not complete successfully.",
            )

        return ToolExecutionResult(
            tool_name=self.tool_name,
            status="completed",
            command=" ; ".join(executed_commands),
            findings=findings,
            partial=bool(errors),
            error_message="\n".join(errors) if errors else None,
        )

    def _parse_results(
        self,
        payload: dict,
        *,
        target_path: Path,
        working_directory: Path,
    ) -> list[NormalizedFinding]:
        if "vulnerabilities" in payload:
            return self._parse_modern_results(payload, target_path=target_path, working_directory=working_directory)
        if "advisories" in payload:
            return self._parse_legacy_results(payload, target_path=target_path, working_directory=working_directory)
        return []

    def _parse_modern_results(
        self,
        payload: dict,
        *,
        target_path: Path,
        working_directory: Path,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        manifest_label = self._manifest_label(target_path, working_directory)
        vulnerabilities = payload.get("vulnerabilities") or {}
        for package_name, vulnerability in vulnerabilities.items():
            via_entries = vulnerability.get("via") or []
            if not via_entries:
                findings.append(self._build_modern_finding(package_name, vulnerability, None, manifest_label))
                continue
            produced = False
            for via_entry in via_entries:
                if isinstance(via_entry, dict):
                    findings.append(self._build_modern_finding(package_name, vulnerability, via_entry, manifest_label))
                    produced = True
            if not produced:
                findings.append(self._build_modern_finding(package_name, vulnerability, None, manifest_label))
        return findings

    def _build_modern_finding(
        self,
        package_name: str,
        vulnerability: dict,
        advisory: dict | None,
        manifest_label: str,
    ) -> NormalizedFinding:
        advisory_id = str((advisory or {}).get("source") or package_name)
        severity = normalize_severity((advisory or {}).get("severity") or vulnerability.get("severity"))
        dependency_version = vulnerability.get("range") or "unknown"
        title = (advisory or {}).get("title") or f"{package_name} {advisory_id}"
        description = (advisory or {}).get("url") or f"Dependency vulnerability detected in {package_name}."
        remediation = self._build_modern_remediation(package_name, vulnerability)
        return NormalizedFinding(
            title=title,
            description=description,
            severity=severity,
            category="dependency:node",
            tool_name=self.tool_name,
            file_path=manifest_label,
            remediation=remediation,
            raw_payload={
                "ecosystem": "node",
                "manifest": manifest_label,
                "dependency": {
                    "name": package_name,
                    "version": dependency_version,
                    "direct": vulnerability.get("isDirect"),
                },
                "advisory": advisory or vulnerability,
                "vulnerability": vulnerability,
            },
        )

    def _parse_legacy_results(
        self,
        payload: dict,
        *,
        target_path: Path,
        working_directory: Path,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        manifest_label = self._manifest_label(target_path, working_directory)
        advisories = payload.get("advisories") or {}
        for advisory_id, advisory in advisories.items():
            findings_data = advisory.get("findings") or []
            dependency_version = "unknown"
            if findings_data and findings_data[0].get("version"):
                dependency_version = findings_data[0]["version"]
            findings.append(
                NormalizedFinding(
                    title=advisory.get("title") or f"{advisory.get('module_name', 'package')} {advisory_id}",
                    description=advisory.get("overview")
                    or advisory.get("recommendation")
                    or f"Dependency vulnerability detected in {advisory.get('module_name', 'package')}.",
                    severity=normalize_severity(advisory.get("severity")),
                    category="dependency:node",
                    tool_name=self.tool_name,
                    file_path=manifest_label,
                    remediation=advisory.get("recommendation"),
                    raw_payload={
                        "ecosystem": "node",
                        "manifest": manifest_label,
                        "dependency": {
                            "name": advisory.get("module_name"),
                            "version": dependency_version,
                        },
                        "advisory": advisory,
                    },
                )
            )
        return findings

    @staticmethod
    def _build_modern_remediation(package_name: str, vulnerability: dict) -> str | None:
        fix_available = vulnerability.get("fixAvailable")
        if isinstance(fix_available, dict):
            name = fix_available.get("name") or package_name
            version = fix_available.get("version")
            if version:
                return f"Upgrade {name} to {version}"
        if fix_available is True:
            return f"Run npm audit fix for {package_name} after review."
        return None

    @staticmethod
    def _manifest_label(target_path: Path, working_directory: Path) -> str:
        candidate = working_directory / "package-lock.json"
        if not candidate.exists():
            candidate = working_directory / "npm-shrinkwrap.json"
        try:
            return str(candidate.relative_to(target_path))
        except ValueError:
            return candidate.name
