"""Maven manifest review adapter using deterministic pom.xml inspection."""

from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.ecosystem_service import EcosystemDetectionService


class MavenPomReviewScannerAdapter(ScannerAdapter):
    """Review Maven pom.xml files for dependency and build configuration risks."""

    tool_name = "maven-pom-review"

    def __init__(self, ecosystem_service: EcosystemDetectionService | None = None) -> None:
        self.ecosystem_service = ecosystem_service or EcosystemDetectionService()

    def scan(self, target_path: Path) -> ToolExecutionResult:
        inventory = self.ecosystem_service.detect(target_path)
        if not inventory.has("maven"):
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message=None,
            )

        pom_files = self.ecosystem_service.find_maven_poms(target_path)
        if not pom_files:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message="Maven ecosystem detected but no pom.xml manifest was found for review.",
            )

        findings: list[NormalizedFinding] = []
        errors: list[str] = []
        for pom_file in pom_files:
            try:
                findings.extend(self._parse_pom(target_path=target_path, pom_file=pom_file))
            except ET.ParseError as exc:
                errors.append(f"{pom_file.name}: pom.xml could not be parsed ({exc}).")
            except OSError as exc:
                errors.append(f"{pom_file.name}: pom.xml could not be read ({exc}).")

        status = "completed" if findings or not errors else "failed"
        return ToolExecutionResult(
            tool_name=self.tool_name,
            status=status,
            command="manifest-review:pom.xml",
            findings=findings,
            partial=bool(errors),
            error_message="\n".join(errors) if errors else None,
        )

    def _parse_pom(self, *, target_path: Path, pom_file: Path) -> list[NormalizedFinding]:
        tree = ET.parse(pom_file)
        root = tree.getroot()
        findings: list[NormalizedFinding] = []
        manifest_label = self._manifest_label(target_path, pom_file)

        for dependency in self._iter_elements(root, "dependency"):
            group_id = self._child_text(dependency, "groupId")
            artifact_id = self._child_text(dependency, "artifactId")
            version = self._child_text(dependency, "version")
            scope = self._child_text(dependency, "scope")
            dependency_name = ":".join(part for part in (group_id, artifact_id) if part) or "unknown-dependency"
            line_number = getattr(dependency, "sourceline", None)

            if version and version.upper() in {"LATEST", "RELEASE"}:
                findings.append(
                    NormalizedFinding(
                        title=f"{dependency_name} uses a floating Maven version",
                        description=(
                            f"The dependency {dependency_name} uses the Maven version token {version}, "
                            "which can make builds non-deterministic and harder to audit."
                        ),
                        severity="medium",
                        category="dependency_risk",
                        tool_name=self.tool_name,
                        file_path=manifest_label,
                        line_number=line_number,
                        remediation=f"Pin {dependency_name} to an explicit reviewed version in pom.xml.",
                        raw_payload={
                            "ecosystem": "maven",
                            "manifest": manifest_label,
                            "dependency": {
                                "group_id": group_id,
                                "artifact_id": artifact_id,
                                "version": version,
                                "scope": scope,
                            },
                            "check": "floating-version",
                        },
                    )
                )
            elif version and "SNAPSHOT" in version.upper():
                findings.append(
                    NormalizedFinding(
                        title=f"{dependency_name} uses a SNAPSHOT Maven version",
                        description=(
                            f"The dependency {dependency_name} uses {version}, which indicates a non-final build "
                            "that may drift over time."
                        ),
                        severity="low",
                        category="dependency_risk",
                        tool_name=self.tool_name,
                        file_path=manifest_label,
                        line_number=line_number,
                        remediation=f"Prefer a stable released version for {dependency_name} in pom.xml.",
                        raw_payload={
                            "ecosystem": "maven",
                            "manifest": manifest_label,
                            "dependency": {
                                "group_id": group_id,
                                "artifact_id": artifact_id,
                                "version": version,
                                "scope": scope,
                            },
                            "check": "snapshot-version",
                        },
                    )
                )

            if (scope or "").lower() == "system":
                findings.append(
                    NormalizedFinding(
                        title=f"{dependency_name} uses system scope",
                        description=(
                            f"The dependency {dependency_name} uses Maven system scope, which can bypass normal "
                            "dependency resolution and reduce build reproducibility."
                        ),
                        severity="medium",
                        category="build_configuration",
                        tool_name=self.tool_name,
                        file_path=manifest_label,
                        line_number=line_number,
                        remediation="Avoid system-scoped dependencies where possible and use managed repository dependencies instead.",
                        raw_payload={
                            "ecosystem": "maven",
                            "manifest": manifest_label,
                            "dependency": {
                                "group_id": group_id,
                                "artifact_id": artifact_id,
                                "version": version,
                                "scope": scope,
                            },
                            "check": "system-scope",
                        },
                    )
                )

        findings.extend(self._build_repository_findings(root, manifest_label, "repositories", "repository"))
        findings.extend(self._build_repository_findings(root, manifest_label, "pluginRepositories", "pluginRepository"))
        return findings

    def _build_repository_findings(
        self,
        root: ET.Element,
        manifest_label: str,
        parent_name: str,
        repository_name: str,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for parent in self._iter_elements(root, parent_name):
            for repository in self._iter_elements(parent, repository_name):
                url = self._child_text(repository, "url")
                repo_id = self._child_text(repository, "id") or repository_name
                if not url or not url.lower().startswith("http://"):
                    continue
                findings.append(
                    NormalizedFinding(
                        title=f"Maven repository {repo_id} uses insecure HTTP",
                        description=(
                            f"The Maven repository {repo_id} is configured with {url}, which allows dependency "
                            "metadata and artifacts to be fetched without transport encryption."
                        ),
                        severity="high",
                        category="build_configuration",
                        tool_name=self.tool_name,
                        file_path=manifest_label,
                        line_number=getattr(repository, "sourceline", None),
                        remediation=f"Update the repository URL for {repo_id} to HTTPS or remove the repository if it is no longer needed.",
                        raw_payload={
                            "ecosystem": "maven",
                            "manifest": manifest_label,
                            "repository": {
                                "id": repo_id,
                                "url": url,
                                "section": parent_name,
                            },
                            "check": "insecure-repository-url",
                        },
                    )
                )
        return findings

    def _iter_elements(self, root: ET.Element, local_name: str) -> list[ET.Element]:
        return [element for element in root.iter() if self._local_name(element.tag) == local_name]

    @staticmethod
    def _child_text(element: ET.Element, local_name: str) -> str | None:
        for child in element:
            if MavenPomReviewScannerAdapter._local_name(child.tag) == local_name:
                value = (child.text or "").strip()
                return value or None
        return None

    @staticmethod
    def _local_name(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    @staticmethod
    def _manifest_label(target_path: Path, pom_file: Path) -> str:
        try:
            return str(pom_file.relative_to(target_path))
        except ValueError:
            return pom_file.name
