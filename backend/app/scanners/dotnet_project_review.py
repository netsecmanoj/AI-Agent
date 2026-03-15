"""Deterministic .NET / NuGet project review adapter."""

from __future__ import annotations

from pathlib import Path
import re
import xml.etree.ElementTree as ET

from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.ecosystem_service import EcosystemDetectionService


class DotnetProjectReviewScannerAdapter(ScannerAdapter):
    """Review .NET project manifests for dependency and package configuration risks."""

    tool_name = "dotnet-project-review"

    def __init__(self, ecosystem_service: EcosystemDetectionService | None = None) -> None:
        self.ecosystem_service = ecosystem_service or EcosystemDetectionService()

    def scan(self, target_path: Path) -> ToolExecutionResult:
        inventory = self.ecosystem_service.detect(target_path)
        if not inventory.has("dotnet"):
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message=None,
            )

        manifest_files = [
            *self.ecosystem_service.find_dotnet_project_files(target_path),
            *[
                path
                for path in self.ecosystem_service.find_dotnet_lockfiles(target_path)
                if path.name == "Directory.Packages.props"
            ],
        ]
        if not manifest_files:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message="Dotnet ecosystem detected but no project manifest was found for review.",
            )

        findings: list[NormalizedFinding] = []
        errors: list[str] = []
        for manifest_file in manifest_files:
            try:
                findings.extend(self._parse_manifest(target_path=target_path, manifest_file=manifest_file))
            except ET.ParseError as exc:
                errors.append(f"{manifest_file.name}: project XML could not be parsed ({exc}).")
            except OSError as exc:
                errors.append(f"{manifest_file.name}: project XML could not be read ({exc}).")

        status = "completed" if findings or not errors else "failed"
        return ToolExecutionResult(
            tool_name=self.tool_name,
            status=status,
            command="manifest-review:csproj,Directory.Packages.props",
            findings=findings,
            partial=bool(errors),
            error_message="\n".join(errors) if errors else None,
        )

    def _parse_manifest(self, *, target_path: Path, manifest_file: Path) -> list[NormalizedFinding]:
        tree = ET.parse(manifest_file)
        root = tree.getroot()
        findings: list[NormalizedFinding] = []
        manifest_label = self._manifest_label(target_path, manifest_file)

        for package_reference in self._iter_elements(root, "PackageReference"):
            package_name = package_reference.attrib.get("Include") or package_reference.attrib.get("Update") or "unknown-package"
            version = package_reference.attrib.get("Version") or self._child_text(package_reference, "Version")
            if not version:
                continue
            line_number = getattr(package_reference, "sourceline", None)
            if "*" in version or version.endswith(".*") or version.startswith("[") or version.startswith("("):
                findings.append(
                    NormalizedFinding(
                        title=f"{package_name} uses a floating NuGet version",
                        description=(
                            f"The package {package_name} uses the version expression {version}, which can make "
                            "restores less deterministic."
                        ),
                        severity="medium",
                        category="dependency_risk",
                        tool_name=self.tool_name,
                        file_path=manifest_label,
                        line_number=line_number,
                        remediation=f"Pin {package_name} to an explicit reviewed package version.",
                        raw_payload={
                            "ecosystem": "dotnet",
                            "manifest": manifest_label,
                            "dependency": {"name": package_name, "version": version},
                            "check": "floating-version",
                        },
                    )
                )
            if self._is_prerelease(version):
                findings.append(
                    NormalizedFinding(
                        title=f"{package_name} uses a pre-release NuGet version",
                        description=(
                            f"The package {package_name} uses the pre-release version {version}, which may not have "
                            "the same stability or support guarantees as a final release."
                        ),
                        severity="low",
                        category="dependency_risk",
                        tool_name=self.tool_name,
                        file_path=manifest_label,
                        line_number=line_number,
                        remediation=f"Prefer a stable reviewed release for {package_name} when possible.",
                        raw_payload={
                            "ecosystem": "dotnet",
                            "manifest": manifest_label,
                            "dependency": {"name": package_name, "version": version},
                            "check": "prerelease-version",
                        },
                    )
                )

        for restore_source in self._iter_elements(root, "RestoreSources"):
            value = (restore_source.text or "").strip()
            if "http://" in value.lower():
                findings.append(
                    NormalizedFinding(
                        title="Dotnet restore sources include insecure HTTP",
                        description=(
                            "A project or central package file configures restore sources that include HTTP URLs, "
                            "which weakens package transport security."
                        ),
                        severity="high",
                        category="package_configuration",
                        tool_name=self.tool_name,
                        file_path=manifest_label,
                        line_number=getattr(restore_source, "sourceline", None),
                        remediation="Update package restore sources to HTTPS-only feeds or remove insecure entries.",
                        raw_payload={
                            "ecosystem": "dotnet",
                            "manifest": manifest_label,
                            "restore_sources": value,
                            "check": "insecure-restore-source",
                        },
                    )
                )

        return findings

    def _iter_elements(self, root: ET.Element, local_name: str) -> list[ET.Element]:
        return [element for element in root.iter() if self._local_name(element.tag) == local_name]

    @staticmethod
    def _child_text(element: ET.Element, local_name: str) -> str | None:
        for child in element:
            if DotnetProjectReviewScannerAdapter._local_name(child.tag) == local_name:
                value = (child.text or "").strip()
                return value or None
        return None

    @staticmethod
    def _is_prerelease(version: str) -> bool:
        return bool(re.search(r"-[0-9A-Za-z]", version))

    @staticmethod
    def _local_name(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    @staticmethod
    def _manifest_label(target_path: Path, manifest_file: Path) -> str:
        try:
            return str(manifest_file.relative_to(target_path))
        except ValueError:
            return manifest_file.name
