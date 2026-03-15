"""Semgrep scanner adapter with graceful fallback when the binary is missing."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

from backend.app.core.config import get_settings
from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.severity import normalize_severity

settings = get_settings()


class SemgrepScannerAdapter(ScannerAdapter):
    """Run Semgrep and normalize its JSON results into the shared finding schema."""

    tool_name = "semgrep"

    def scan(self, target_path: Path) -> ToolExecutionResult:
        command = [
            settings.semgrep_command,
            "scan",
            "--config",
            settings.semgrep_config,
            "--json",
            str(target_path),
        ]
        if shutil.which(settings.semgrep_command) is None:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=" ".join(command),
                findings=[],
                partial=True,
                error_message="Semgrep is not installed or not available in PATH.",
            )

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=settings.semgrep_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="timeout",
                command=" ".join(command),
                findings=[],
                partial=True,
                error_message="Semgrep execution timed out.",
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
                error_message=stderr or "Semgrep returned a non-zero exit code.",
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
                error_message="Semgrep output was not valid JSON.",
            )

        findings = self._parse_results(payload)
        return ToolExecutionResult(
            tool_name=self.tool_name,
            status="completed",
            command=" ".join(command),
            findings=findings,
            partial=bool(stderr),
            error_message=stderr or None,
        )

    def _parse_results(self, payload: dict) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for result in payload.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            findings.append(
                NormalizedFinding(
                    title=result.get("check_id", "Semgrep finding"),
                    description=extra.get("message", "Semgrep reported a potential issue."),
                    severity=normalize_severity(extra.get("severity")),
                    category=metadata.get("category", "code"),
                    tool_name=self.tool_name,
                    file_path=result.get("path"),
                    line_number=(result.get("start") or {}).get("line"),
                    remediation=metadata.get("fix") or metadata.get("shortlink"),
                    raw_payload=result,
                )
            )
        return findings

