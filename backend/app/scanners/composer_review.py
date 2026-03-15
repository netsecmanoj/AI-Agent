"""Composer manifest review adapter using deterministic composer file inspection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.ecosystem_service import EcosystemDetectionService


class ComposerReviewScannerAdapter(ScannerAdapter):
    """Review Composer manifests and lockfiles for dependency and config risks."""

    tool_name = "composer-review"

    def __init__(self, ecosystem_service: EcosystemDetectionService | None = None) -> None:
        self.ecosystem_service = ecosystem_service or EcosystemDetectionService()

    def scan(self, target_path: Path) -> ToolExecutionResult:
        inventory = self.ecosystem_service.detect(target_path)
        if not inventory.has("composer"):
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message=None,
            )

        composer_json_files = self.ecosystem_service.find_composer_manifests(target_path)
        composer_lockfiles = self.ecosystem_service.find_composer_lockfiles(target_path)
        if not composer_json_files and not composer_lockfiles:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message="Composer ecosystem detected but no composer.json or composer.lock manifest was found for review.",
            )

        findings: list[NormalizedFinding] = []
        errors: list[str] = []

        for composer_json in composer_json_files:
            try:
                findings.extend(self._parse_composer_json(target_path=target_path, manifest_path=composer_json))
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"{composer_json.name}: composer.json could not be parsed ({exc}).")

        for composer_lock in composer_lockfiles:
            try:
                findings.extend(self._parse_composer_lock(target_path=target_path, lockfile_path=composer_lock))
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"{composer_lock.name}: composer.lock could not be parsed ({exc}).")

        status = "completed" if findings or not errors else "failed"
        return ToolExecutionResult(
            tool_name=self.tool_name,
            status=status,
            command="manifest-review:composer.json,composer.lock",
            findings=findings,
            partial=bool(errors),
            error_message="\n".join(errors) if errors else None,
        )

    def _parse_composer_json(self, *, target_path: Path, manifest_path: Path) -> list[NormalizedFinding]:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        findings: list[NormalizedFinding] = []
        manifest_label = self._manifest_label(target_path, manifest_path)
        config = payload.get("config") or {}
        secure_http = config.get("secure-http")
        if secure_http is False:
            findings.append(
                NormalizedFinding(
                    title="Composer secure-http is disabled",
                    description=(
                        "composer.json disables secure-http, which allows package metadata or archives to be "
                        "fetched over plain HTTP."
                    ),
                    severity="high",
                    category="build_configuration",
                    tool_name=self.tool_name,
                    file_path=manifest_label,
                    remediation="Set config.secure-http to true and remove any HTTP-only repositories.",
                    raw_payload={
                        "ecosystem": "composer",
                        "manifest": manifest_label,
                        "config": {"secure-http": secure_http},
                        "check": "secure-http-disabled",
                    },
                )
            )

        allow_plugins = config.get("allow-plugins")
        if isinstance(allow_plugins, dict) and "*" in allow_plugins and allow_plugins["*"] is True:
            findings.append(
                NormalizedFinding(
                    title="Composer allow-plugins permits all plugins",
                    description=(
                        "composer.json enables allow-plugins for all packages, which broadens the set of Composer "
                        "plugins that may execute during dependency operations."
                    ),
                    severity="medium",
                    category="build_configuration",
                    tool_name=self.tool_name,
                    file_path=manifest_label,
                    remediation="Restrict allow-plugins to the specific trusted plugin packages that are required.",
                    raw_payload={
                        "ecosystem": "composer",
                        "manifest": manifest_label,
                        "config": {"allow-plugins": allow_plugins},
                        "check": "allow-plugins-wildcard",
                    },
                )
            )
        return findings

    def _parse_composer_lock(self, *, target_path: Path, lockfile_path: Path) -> list[NormalizedFinding]:
        payload = json.loads(lockfile_path.read_text(encoding="utf-8"))
        manifest_label = self._manifest_label(target_path, lockfile_path)
        findings: list[NormalizedFinding] = []
        for package in self._iter_packages(payload):
            abandoned = package.get("abandoned")
            if not abandoned:
                continue
            package_name = str(package.get("name") or "unknown-package")
            version = str(package.get("version") or "unknown")
            replacement = abandoned if isinstance(abandoned, str) else None
            remediation = (
                f"Replace {package_name} with {replacement} and update composer.lock after validation."
                if replacement
                else f"Replace or remove abandoned package {package_name} and refresh composer.lock after review."
            )
            findings.append(
                NormalizedFinding(
                    title=f"{package_name} is marked abandoned",
                    description=(
                        f"The Composer package {package_name} ({version}) is marked abandoned in composer.lock."
                        + (f" Suggested replacement: {replacement}." if replacement else "")
                    ),
                    severity="high" if replacement is None else "medium",
                    category="dependency_risk",
                    tool_name=self.tool_name,
                    file_path=manifest_label,
                    remediation=remediation,
                    raw_payload={
                        "ecosystem": "composer",
                        "manifest": manifest_label,
                        "dependency": {
                            "name": package_name,
                            "version": version,
                        },
                        "abandoned": abandoned,
                        "package": package,
                        "check": "abandoned-package",
                    },
                )
            )
        return findings

    @staticmethod
    def _iter_packages(payload: dict[str, Any]) -> list[dict[str, Any]]:
        packages: list[dict[str, Any]] = []
        for key in ("packages", "packages-dev"):
            section = payload.get(key)
            if isinstance(section, list):
                packages.extend(item for item in section if isinstance(item, dict))
        return packages

    @staticmethod
    def _manifest_label(target_path: Path, manifest_path: Path) -> str:
        try:
            return str(manifest_path.relative_to(target_path))
        except ValueError:
            return manifest_path.name
