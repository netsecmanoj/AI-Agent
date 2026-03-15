"""Dart/Flutter dependency visibility adapter using pub outdated output."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

from backend.app.core.config import get_settings
from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.ecosystem_service import EcosystemDetectionService

settings = get_settings()
PUB_OUTDATED_JSON_ARGS = ("pub", "outdated", "--json", "--no-up-to-date")


class DartPubOutdatedScannerAdapter(ScannerAdapter):
    """Run Dart or Flutter pub outdated without mutating the workspace."""

    tool_name = "dart-pub-outdated"

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

        lockfiles = self.ecosystem_service.find_dart_lockfiles(target_path)
        if not lockfiles:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message="Dart or Flutter ecosystem detected but no pubspec.lock was found for pub outdated.",
            )

        command = self._build_command(inventory)
        if command is None:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=True,
                error_message="Neither Flutter nor Dart is installed or available in PATH.",
            )

        manifest_roots = sorted({lockfile.parent for lockfile in lockfiles})
        findings: list[NormalizedFinding] = []
        errors: list[str] = []
        executed_commands: list[str] = []
        successful_runs = 0

        for manifest_root in manifest_roots:
            executed_commands.append(f"(cd {manifest_root} && {' '.join(command)})")
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    cwd=manifest_root,
                    timeout=settings.dart_pub_outdated_timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                errors.append(f"{manifest_root.name or '.'}: dart pub outdated execution timed out.")
                continue

            stdout = completed.stdout.strip()
            stderr = completed.stderr.strip()
            if completed.returncode not in {0, 1}:
                errors.append(
                    f"{manifest_root.name or '.'}: {stderr or 'dart pub outdated returned a non-zero exit code.'}"
                )
                continue

            try:
                payload = json.loads(stdout or "{}")
            except json.JSONDecodeError:
                errors.append(f"{manifest_root.name or '.'}: dart pub outdated output was not valid JSON.")
                continue

            successful_runs += 1
            findings.extend(
                self._parse_results(
                    payload,
                    target_path=target_path,
                    manifest_root=manifest_root,
                    ecosystem="flutter" if inventory.has("flutter") else "dart",
                )
            )
            if stderr:
                errors.append(f"{manifest_root.name or '.'}: {stderr}")

        if successful_runs == 0:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="failed",
                command=" ; ".join(executed_commands) if executed_commands else None,
                findings=[],
                partial=True,
                error_message="\n".join(errors) if errors else "dart pub outdated did not complete successfully.",
            )

        return ToolExecutionResult(
            tool_name=self.tool_name,
            status="completed",
            command=" ; ".join(executed_commands),
            findings=findings,
            partial=bool(errors),
            error_message="\n".join(errors) if errors else None,
        )

    def _build_command(self, inventory) -> list[str] | None:
        # Current Dart/Flutter CLI rejects JSON mode when combined with
        # transitive-selection flags. Keep this command read-only and compatible.
        if inventory.has("flutter") and shutil.which(settings.flutter_command):
            return [settings.flutter_command, *PUB_OUTDATED_JSON_ARGS]
        if inventory.has("dart") and shutil.which(settings.dart_command):
            return [settings.dart_command, *PUB_OUTDATED_JSON_ARGS]
        return None

    def _parse_results(
        self,
        payload: dict[str, Any],
        *,
        target_path: Path,
        manifest_root: Path,
        ecosystem: str,
    ) -> list[NormalizedFinding]:
        manifest_label = self._manifest_label(target_path, manifest_root)
        findings: list[NormalizedFinding] = []
        for package in self._iter_packages(payload):
            package_name = str(package.get("package") or package.get("packageName") or package.get("name") or "unknown")
            current_version = self._version_value(package.get("current"))
            upgradable_version = self._version_value(package.get("upgradable"))
            resolvable_version = self._version_value(package.get("resolvable"))
            latest_version = self._version_value(package.get("latest"))
            latest_relevant_version = latest_version or resolvable_version or upgradable_version
            if not latest_relevant_version or latest_relevant_version == current_version:
                continue

            advisory_flag = bool(
                package.get("isCurrentAffectedByAdvisory")
                or package.get("isCurrentRetracted")
                or package.get("isDiscontinued")
            )
            severity = "high" if advisory_flag else "low"
            kind = str(package.get("kind") or package.get("dependencyType") or "unknown")
            title = f"{package_name} is behind the latest available release"
            description = (
                f"{package_name} is currently at {current_version or 'unknown'}; "
                f"latest available is {latest_relevant_version}."
            )
            if advisory_flag:
                description += " The current dependency state is flagged as higher risk by pub metadata."
            findings.append(
                NormalizedFinding(
                    title=title,
                    description=description,
                    severity=severity,
                    category="dependency_outdated",
                    tool_name=self.tool_name,
                    file_path=manifest_label,
                    remediation=self._build_remediation(package_name, latest_relevant_version, advisory_flag),
                    raw_payload={
                        "ecosystem": ecosystem,
                        "manifest": manifest_label,
                        "dependency": {
                            "name": package_name,
                            "version": current_version,
                            "kind": kind,
                        },
                        "versions": {
                            "current": current_version,
                            "upgradable": upgradable_version,
                            "resolvable": resolvable_version,
                            "latest": latest_version,
                        },
                        "risk_flags": {
                            "isCurrentAffectedByAdvisory": bool(package.get("isCurrentAffectedByAdvisory")),
                            "isCurrentRetracted": bool(package.get("isCurrentRetracted")),
                            "isDiscontinued": bool(package.get("isDiscontinued")),
                        },
                        "package": package,
                    },
                )
            )
        return findings

    @staticmethod
    def _iter_packages(payload: dict[str, Any]) -> list[dict[str, Any]]:
        if isinstance(payload.get("packages"), list):
            return [item for item in payload["packages"] if isinstance(item, dict)]
        packages: list[dict[str, Any]] = []
        for key in ("directDependencies", "devDependencies", "transitiveDependencies"):
            section = payload.get(key)
            if isinstance(section, list):
                packages.extend(item for item in section if isinstance(item, dict))
        return packages

    @staticmethod
    def _version_value(value: Any) -> str | None:
        if isinstance(value, dict):
            return str(value.get("version") or value.get("constraint") or "").strip() or None
        if value is None:
            return None
        return str(value).strip() or None

    @staticmethod
    def _build_remediation(package_name: str, target_version: str, advisory_flag: bool) -> str:
        if advisory_flag:
            return f"Prioritize upgrading {package_name} to {target_version} after validating compatibility."
        return f"Plan an upgrade of {package_name} to {target_version} to reduce dependency drift."

    @staticmethod
    def _manifest_label(target_path: Path, manifest_root: Path) -> str:
        candidate = manifest_root / "pubspec.lock"
        try:
            return str(candidate.relative_to(target_path))
        except ValueError:
            return candidate.name
