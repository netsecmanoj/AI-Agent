"""Derived grouping logic for repeated or similar findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(slots=True)
class GroupedFinding:
    """Deterministic grouped view over repeated findings."""

    group_key: str
    title: str
    description: str
    severity: str
    category: str
    tool_name: str
    file_path: str | None
    dependency_name: str | None
    remediation: str | None
    representative_finding_id: str | None
    member_count: int
    member_ids: list[str]
    affected_files: list[str]
    sample_members: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-safe grouped finding payload."""
        return {
            "group_key": self.group_key,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "tool_name": self.tool_name,
            "file_path": self.file_path,
            "dependency_name": self.dependency_name,
            "remediation": self.remediation,
            "representative_finding_id": self.representative_finding_id,
            "member_count": self.member_count,
            "member_ids": self.member_ids,
            "affected_files": self.affected_files,
            "sample_members": self.sample_members,
        }


class FindingGroupingService:
    """Group repeated findings without altering stored raw records."""

    def group(self, findings: Iterable[Any]) -> list[GroupedFinding]:
        """Return deterministic grouped summaries for the provided findings."""
        grouped: dict[tuple[str, ...], list[Any]] = {}
        for finding in findings:
            grouped.setdefault(self._build_key_tuple(finding), []).append(finding)

        grouped_findings: list[GroupedFinding] = []
        for key, members in grouped.items():
            representative = self._pick_representative(members)
            grouped_findings.append(
                GroupedFinding(
                    group_key="|".join(key),
                    title=representative.title,
                    description=getattr(representative, "description", ""),
                    severity=representative.severity,
                    category=representative.category,
                    tool_name=representative.tool_name,
                    file_path=representative.file_path,
                    dependency_name=self._dependency_name(representative),
                    remediation=getattr(representative, "remediation", None),
                    representative_finding_id=getattr(representative, "id", None),
                    member_count=len(members),
                    member_ids=[getattr(member, "id", "") for member in members if getattr(member, "id", "")],
                    affected_files=self._affected_files(members),
                    sample_members=[
                        {
                            "id": getattr(member, "id", None),
                            "file_path": getattr(member, "file_path", None),
                            "line_number": getattr(member, "line_number", None),
                            "tool_name": getattr(member, "tool_name", None),
                        }
                        for member in members[:5]
                    ],
                )
            )

        return sorted(
            grouped_findings,
            key=lambda item: (
                self._severity_rank(item.severity),
                -item.member_count,
                item.title.lower(),
                item.tool_name.lower(),
                item.file_path or "",
            ),
        )

    def _build_key_tuple(self, finding: Any) -> tuple[str, ...]:
        dependency_name = self._dependency_name(finding)
        return (
            self._normalize(getattr(finding, "title", "")),
            self._normalize(getattr(finding, "severity", "")),
            self._normalize(getattr(finding, "category", "")),
            self._normalize(getattr(finding, "tool_name", "")),
            self._normalize(getattr(finding, "file_path", "")),
            self._normalize(dependency_name or ""),
        )

    @staticmethod
    def _pick_representative(members: list[Any]) -> Any:
        return sorted(
            members,
            key=lambda member: (
                getattr(member, "line_number", 0) or 0,
                getattr(member, "id", "") or "",
            ),
        )[0]

    @staticmethod
    def _dependency_name(finding: Any) -> str | None:
        raw_payload = getattr(finding, "raw_payload", {}) or {}
        dependency = raw_payload.get("dependency") or {}
        name = dependency.get("name")
        if name:
            return str(name)
        return None

    @staticmethod
    def _affected_files(members: list[Any]) -> list[str]:
        affected_files = set()
        for member in members:
            file_path = getattr(member, "file_path", None)
            if not file_path:
                continue
            normalized = str(file_path).strip()
            if normalized:
                affected_files.add(normalized)
        return sorted(affected_files)

    @staticmethod
    def _normalize(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _severity_rank(severity: str) -> int:
        order = ["critical", "high", "medium", "low", "info", "unknown"]
        return order.index(severity) if severity in order else len(order)
