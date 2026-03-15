"""pip-audit scanner adapter for Python dependency vulnerability auditing."""

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


class PipAuditScannerAdapter(ScannerAdapter):
    """Run pip-audit when Python requirements manifests are detected."""

    tool_name = "pip-audit"

    def __init__(self, ecosystem_service: EcosystemDetectionService | None = None) -> None:
        self.ecosystem_service = ecosystem_service or EcosystemDetectionService()

    def scan(self, target_path: Path) -> ToolExecutionResult:
        inventory = self.ecosystem_service.detect(target_path)
        if not inventory.has("python"):
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message=None,
            )

        requirement_files = self.ecosystem_service.find_python_requirements(target_path)
        if not requirement_files:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message="Python ecosystem detected but no requirements-style file was found for pip-audit.",
            )

        if shutil.which(settings.pip_audit_command) is None:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=f"{settings.pip_audit_command} -f json -r <requirements-file>",
                findings=[],
                partial=True,
                error_message="pip-audit is not installed or not available in PATH.",
            )

        findings: list[NormalizedFinding] = []
        errors: list[str] = []
        executed_commands: list[str] = []
        successful_runs = 0
        for requirement_file in requirement_files:
            command = [
                settings.pip_audit_command,
                "-f",
                "json",
                "-r",
                str(requirement_file),
            ]
            executed_commands.append(" ".join(command))
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=settings.pip_audit_timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                errors.append(f"{requirement_file.name}: pip-audit execution timed out.")
                continue

            stdout = completed.stdout.strip()
            stderr = completed.stderr.strip()
            if completed.returncode not in {0, 1}:
                errors.append(
                    f"{requirement_file.name}: {stderr or 'pip-audit returned a non-zero exit code.'}"
                )
                continue

            try:
                payload = json.loads(stdout or "[]")
            except json.JSONDecodeError:
                errors.append(f"{requirement_file.name}: pip-audit output was not valid JSON.")
                continue

            successful_runs += 1
            findings.extend(self._parse_results(payload, target_path=target_path, manifest_path=requirement_file))
            if stderr:
                errors.append(f"{requirement_file.name}: {stderr}")

        if successful_runs == 0:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="failed",
                command=" ; ".join(executed_commands) if executed_commands else None,
                findings=[],
                partial=True,
                error_message="\n".join(errors) if errors else "pip-audit did not complete successfully.",
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
        payload: list[dict],
        target_path: Path,
        manifest_path: Path,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        manifest_label = str(manifest_path.relative_to(target_path))
        for package in payload:
            package_name = package.get("name", "unknown-package")
            package_version = package.get("version", "unknown")
            for vulnerability in package.get("vulns", []):
                fix_versions = vulnerability.get("fix_versions") or []
                remediation = (
                    f"Upgrade {package_name} to {fix_versions[0]}" if fix_versions else None
                )
                findings.append(
                    NormalizedFinding(
                        title=f"{package_name} {vulnerability.get('id', 'advisory')}",
                        description=vulnerability.get("description")
                        or f"Dependency vulnerability detected in {package_name} {package_version}.",
                        severity=normalize_severity(vulnerability.get("severity") or "high"),
                        category="dependency:python",
                        tool_name=self.tool_name,
                        file_path=manifest_label,
                        remediation=remediation,
                        raw_payload={
                            "ecosystem": "python",
                            "manifest": manifest_label,
                            "dependency": {
                                "name": package_name,
                                "version": package_version,
                            },
                            "advisory": vulnerability,
                            "package": package,
                            "vulnerability": vulnerability,
                        },
                    )
                )
        return findings
