"""Trivy filesystem scanner adapter with graceful fallback handling."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

from backend.app.core.config import get_settings
from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.severity import normalize_severity

settings = get_settings()


class TrivyScannerAdapter(ScannerAdapter):
    """Run Trivy filesystem scans and normalize the JSON output."""

    tool_name = "trivy"

    def scan(self, target_path: Path) -> ToolExecutionResult:
        command = [
            settings.trivy_command,
            "fs",
            "--format",
            "json",
            str(target_path),
        ]
        if shutil.which(settings.trivy_command) is None:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=" ".join(command),
                findings=[],
                partial=True,
                error_message="Trivy is not installed or not available in PATH.",
            )

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=settings.trivy_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="timeout",
                command=" ".join(command),
                findings=[],
                partial=True,
                error_message="Trivy execution timed out.",
            )

        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()
        if completed.returncode not in {0, 1}:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="failed",
                command=" ".join(command),
                findings=[],
                partial=True,
                error_message=stderr or "Trivy returned a non-zero exit code.",
            )

        try:
            payload = json.loads(stdout or "{}")
        except json.JSONDecodeError:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="failed",
                command=" ".join(command),
                findings=[],
                partial=True,
                error_message="Trivy output was not valid JSON.",
            )

        findings = self._parse_results(payload)
        return ToolExecutionResult(
            tool_name=self.tool_name,
            status="completed",
            command=" ".join(command),
            findings=findings,
            partial=False,
            error_message=stderr or None,
        )

    def _parse_results(self, payload: dict) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for result in payload.get("Results", []):
            target = result.get("Target")
            result_type = result.get("Type") or result.get("Class") or "filesystem"
            for vulnerability in result.get("Vulnerabilities", []):
                findings.append(
                    NormalizedFinding(
                        title=vulnerability.get("Title")
                        or vulnerability.get("VulnerabilityID")
                        or "Trivy vulnerability",
                        description=vulnerability.get("Description")
                        or "Trivy reported a dependency vulnerability.",
                        severity=normalize_severity(vulnerability.get("Severity")),
                        category=f"dependency:{result_type}",
                        tool_name=self.tool_name,
                        file_path=target,
                        remediation=vulnerability.get("FixedVersion")
                        and f"Upgrade to {vulnerability['FixedVersion']}",
                        raw_payload=vulnerability,
                    )
                )
            for misconfiguration in result.get("Misconfigurations", []):
                findings.append(
                    NormalizedFinding(
                        title=misconfiguration.get("Title")
                        or misconfiguration.get("ID")
                        or "Trivy misconfiguration",
                        description=misconfiguration.get("Description")
                        or misconfiguration.get("Message")
                        or "Trivy reported a configuration issue.",
                        severity=normalize_severity(misconfiguration.get("Severity")),
                        category=f"misconfiguration:{result_type}",
                        tool_name=self.tool_name,
                        file_path=target,
                        remediation=misconfiguration.get("Resolution"),
                        raw_payload=misconfiguration,
                    )
                )
            for secret in result.get("Secrets", []):
                findings.append(
                    NormalizedFinding(
                        title=secret.get("Title") or secret.get("RuleID") or "Trivy secret",
                        description=secret.get("Description")
                        or "Trivy detected a possible secret exposure.",
                        severity=normalize_severity(secret.get("Severity")),
                        category=f"secret:{result_type}",
                        tool_name=self.tool_name,
                        file_path=target,
                        line_number=secret.get("StartLine"),
                        remediation=secret.get("Resolution"),
                        raw_payload=secret,
                    )
                )
        return findings

