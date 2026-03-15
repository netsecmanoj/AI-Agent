"""Dart/Flutter static analysis adapter."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess

from backend.app.core.config import get_settings
from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.ecosystem_service import EcosystemDetectionService
from backend.app.services.severity import normalize_severity

settings = get_settings()


class DartAnalyzeScannerAdapter(ScannerAdapter):
    """Run Flutter or Dart static analysis when supported project markers are present."""

    tool_name = "dart-flutter-analyze"
    _issue_pattern = re.compile(
        r"^\s*(error|warning|info)\s*[•|-]\s*(.*?)\s*[•|-]\s*(.+?):(\d+):(\d+)\s*[•|-]\s*(\S+)\s*$"
    )

    def __init__(self, ecosystem_service: EcosystemDetectionService | None = None) -> None:
        self.ecosystem_service = ecosystem_service or EcosystemDetectionService()

    def scan(self, target_path: Path) -> ToolExecutionResult:
        inventory = self.ecosystem_service.detect(target_path)
        if not inventory.has("dart") and not inventory.has("flutter"):
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message=None,
            )

        command = self._build_command(target_path, inventory)
        if command is None:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=True,
                error_message="Neither Flutter nor Dart is installed or available in PATH.",
            )

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                cwd=target_path,
                timeout=settings.dart_analyze_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="failed",
                command=" ".join(command),
                findings=[],
                partial=True,
                error_message="Static analysis timed out.",
            )

        combined_output = "\n".join(part for part in [completed.stdout.strip(), completed.stderr.strip()] if part).strip()
        findings = self._parse_output(combined_output, target_path=target_path, command_name=command[0])
        if completed.returncode == 0 or findings:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="completed",
                command=" ".join(command),
                findings=findings,
                partial=False,
                error_message=None if findings or completed.returncode == 0 else combined_output or None,
            )
        return ToolExecutionResult(
            tool_name=self.tool_name,
            status="failed",
            command=" ".join(command),
            findings=[],
            partial=True,
            error_message=combined_output or "Static analysis returned a non-zero exit code.",
        )

    def _build_command(self, target_path: Path, inventory) -> list[str] | None:
        if inventory.has("flutter") and shutil.which(settings.flutter_command):
            return [settings.flutter_command, "analyze", "--no-pub"]
        if inventory.has("dart") and shutil.which(settings.dart_command):
            return [settings.dart_command, "analyze"]
        return None

    def _parse_output(
        self,
        output: str,
        *,
        target_path: Path,
        command_name: str,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        configured_flutter_name = Path(settings.flutter_command).name
        runtime_command_name = Path(command_name).name
        ecosystem = "flutter" if runtime_command_name == configured_flutter_name else "dart"
        for line in output.splitlines():
            match = self._issue_pattern.match(line)
            if not match:
                continue
            severity_label, message, file_path, line_number, column_number, rule_code = match.groups()
            resolved_file = self._normalize_file_path(file_path, target_path)
            findings.append(
                NormalizedFinding(
                    title=f"{rule_code} in {resolved_file or file_path}",
                    description=message,
                    severity=normalize_severity(severity_label),
                    category="static_analysis",
                    tool_name=self.tool_name,
                    file_path=resolved_file or file_path,
                    line_number=int(line_number),
                    remediation=self._build_remediation(rule_code, ecosystem),
                    raw_payload={
                        "ecosystem": ecosystem,
                        "rule_code": rule_code,
                        "column_number": int(column_number),
                        "severity_label": severity_label,
                        "line": line,
                    },
                )
            )
        return findings

    @staticmethod
    def _normalize_file_path(file_path: str, target_path: Path) -> str | None:
        candidate = Path(file_path)
        if not candidate.is_absolute():
            return file_path
        try:
            return str(candidate.relative_to(target_path))
        except ValueError:
            return candidate.name

    @staticmethod
    def _build_remediation(rule_code: str, ecosystem: str) -> str:
        if ecosystem == "flutter":
            return f"Review the {rule_code} Flutter analyzer guidance and update the affected source."
        return f"Review the {rule_code} Dart analyzer guidance and update the affected source."
