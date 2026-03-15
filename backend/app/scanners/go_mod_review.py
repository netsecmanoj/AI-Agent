"""Go module review adapter using deterministic go.mod inspection."""

from __future__ import annotations

from pathlib import Path

from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.ecosystem_service import EcosystemDetectionService


class GoModReviewScannerAdapter(ScannerAdapter):
    """Review Go module manifests for dependency and module configuration risks."""

    tool_name = "go-mod-review"

    def __init__(self, ecosystem_service: EcosystemDetectionService | None = None) -> None:
        self.ecosystem_service = ecosystem_service or EcosystemDetectionService()

    def scan(self, target_path: Path) -> ToolExecutionResult:
        inventory = self.ecosystem_service.detect(target_path)
        if not inventory.has("go"):
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message=None,
            )

        go_mod_files = self.ecosystem_service.find_go_mod_files(target_path)
        if not go_mod_files:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message="Go ecosystem detected but no go.mod manifest was found for review.",
            )

        findings: list[NormalizedFinding] = []
        errors: list[str] = []
        for go_mod_file in go_mod_files:
            try:
                findings.extend(self._parse_go_mod(target_path=target_path, go_mod_file=go_mod_file))
            except OSError as exc:
                errors.append(f"{go_mod_file.name}: go.mod could not be read ({exc}).")

        status = "completed" if findings or not errors else "failed"
        return ToolExecutionResult(
            tool_name=self.tool_name,
            status=status,
            command="manifest-review:go.mod",
            findings=findings,
            partial=bool(errors),
            error_message="\n".join(errors) if errors else None,
        )

    def _parse_go_mod(self, *, target_path: Path, go_mod_file: Path) -> list[NormalizedFinding]:
        content = go_mod_file.read_text(encoding="utf-8")
        lines = content.splitlines()
        findings: list[NormalizedFinding] = []
        manifest_label = self._manifest_label(target_path, go_mod_file)

        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("replace "):
                findings.append(self._build_replace_finding(stripped, manifest_label, line_number))

            if stripped.startswith("toolchain "):
                toolchain_value = stripped.partition("toolchain ")[2].strip()
                if toolchain_value == "default":
                    findings.append(
                        NormalizedFinding(
                            title="Go toolchain is not pinned",
                            description=(
                                "go.mod uses `toolchain default`, which leaves the effective toolchain choice "
                                "to the environment and can reduce build reproducibility."
                            ),
                            severity="low",
                            category="module_configuration",
                            tool_name=self.tool_name,
                            file_path=manifest_label,
                            line_number=line_number,
                            remediation="Pin an explicit reviewed Go toolchain version if reproducibility matters for this project.",
                            raw_payload={
                                "ecosystem": "go",
                                "manifest": manifest_label,
                                "toolchain": toolchain_value,
                                "check": "unpinned-toolchain",
                            },
                        )
                    )

            dependency_entry = self._parse_dependency_entry(stripped)
            if dependency_entry is not None:
                dependency_name, version = dependency_entry
                if self._is_pseudo_version(version):
                    findings.append(
                        NormalizedFinding(
                            title=f"{dependency_name} uses a Go pseudo-version",
                            description=(
                                f"The module {dependency_name} is pinned to {version}, which is a pseudo-version "
                                "and may indicate an untagged upstream commit."
                            ),
                            severity="low",
                            category="dependency_risk",
                            tool_name=self.tool_name,
                            file_path=manifest_label,
                            line_number=line_number,
                            remediation=f"Prefer a reviewed tagged release for {dependency_name} where one is available.",
                            raw_payload={
                                "ecosystem": "go",
                                "manifest": manifest_label,
                                "dependency": {
                                    "name": dependency_name,
                                    "version": version,
                                },
                                "check": "pseudo-version",
                            },
                        )
                    )

        return findings

    def _build_replace_finding(self, stripped_line: str, manifest_label: str, line_number: int) -> NormalizedFinding:
        replacement_target = stripped_line.partition("=>")[2].strip()
        local_replace = replacement_target.startswith(".") or replacement_target.startswith("/") or replacement_target.startswith("..")
        severity = "medium" if local_replace else "low"
        title = "Go module uses a local replace directive" if local_replace else "Go module uses a replace directive"
        description = (
            "go.mod uses a replace directive that points to a local filesystem path, which can bypass normal module provenance."
            if local_replace
            else "go.mod uses a replace directive, which overrides the default module source and should be reviewed for provenance."
        )
        remediation = (
            "Remove the local replace directive before production release or document the trusted internal source."
            if local_replace
            else "Review whether the replace directive is still necessary and document the trusted replacement source."
        )
        return NormalizedFinding(
            title=title,
            description=description,
            severity=severity,
            category="module_configuration",
            tool_name=self.tool_name,
            file_path=manifest_label,
            line_number=line_number,
            remediation=remediation,
            raw_payload={
                "ecosystem": "go",
                "manifest": manifest_label,
                "directive": stripped_line,
                "local_replace": local_replace,
                "check": "replace-directive",
            },
        )

    @staticmethod
    def _is_pseudo_version(version: str) -> bool:
        parts = version.split("-")
        return len(parts) >= 3 and parts[1].isdigit() and len(parts[1]) == 14

    @staticmethod
    def _parse_dependency_entry(stripped_line: str) -> tuple[str, str] | None:
        normalized = stripped_line.split("//", 1)[0].strip()
        if not normalized or normalized in {"require (", ")"}:
            return None
        if normalized.startswith("require "):
            normalized = normalized[len("require ") :].strip()
        parts = normalized.split()
        if len(parts) < 2:
            return None
        dependency_name, version = parts[0], parts[1]
        if not version.startswith("v"):
            return None
        return dependency_name, version

    @staticmethod
    def _manifest_label(target_path: Path, go_mod_file: Path) -> str:
        try:
            return str(go_mod_file.relative_to(target_path))
        except ValueError:
            return go_mod_file.name
