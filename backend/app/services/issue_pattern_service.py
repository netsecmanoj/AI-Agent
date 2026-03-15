"""Higher-level deterministic clustering for large finding sets."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import PurePosixPath
import re
from typing import Any

from backend.app.services.finding_intelligence_service import FindingIntelligenceService
from backend.app.services.grouping_service import FindingGroupingService

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}


class IssuePatternService:
    """Build remediation-oriented summaries above strict grouped findings."""

    def __init__(self) -> None:
        self.finding_intelligence_service = FindingIntelligenceService()
        self.grouping_service = FindingGroupingService()

    def build_summary(
        self,
        findings: list[Any],
        *,
        grouped_findings: list[dict[str, Any]] | None = None,
        max_patterns: int = 10,
        max_rare_findings: int = 10,
        max_hotspots: int = 5,
    ) -> dict[str, Any]:
        """Return common patterns, rare important findings, and hotspots."""
        serialized_findings = [self._serialize_finding(finding) for finding in findings]
        grouped_payloads = grouped_findings or [
            self.finding_intelligence_service.enrich_group(group.as_dict())
            for group in self.grouping_service.group(findings)
        ]
        member_group_map = self._build_member_group_map(grouped_payloads)
        common_patterns = self._build_common_patterns(
            serialized_findings,
            grouped_payloads,
            member_group_map,
            max_patterns=max_patterns,
        )
        rare_but_important = self._build_rare_but_important(grouped_payloads, limit=max_rare_findings)
        hotspots = self._build_hotspots(serialized_findings, limit=max_hotspots)
        return {
            "common_patterns": common_patterns,
            "rare_but_important": rare_but_important,
            "hotspots": hotspots,
        }

    def pattern_signature(self, finding: Any) -> tuple[str, str]:
        """Return the broader deterministic pattern signature for one finding."""
        serialized = self._serialize_finding(finding)
        return self._pattern_signature(serialized)

    def matches_pattern(self, finding: Any, pattern_key: str) -> bool:
        """Return whether a finding belongs to the requested pattern cluster."""
        serialized = self._serialize_finding(finding)
        finding_pattern_key, _ = self._pattern_signature(serialized)
        return finding_pattern_key == pattern_key

    def matches_hotspot_file(self, finding: Any, file_path: str) -> bool:
        """Return whether a finding belongs to the requested file hotspot."""
        serialized = self._serialize_finding(finding)
        return str(serialized.get("file_path") or "") == file_path

    def matches_hotspot_module(self, finding: Any, module_path: str) -> bool:
        """Return whether a finding belongs to the requested module hotspot."""
        serialized = self._serialize_finding(finding)
        file_path = serialized.get("file_path")
        if not file_path:
            return False
        return self._module_path(file_path) == module_path

    def _serialize_finding(self, finding: Any) -> dict[str, Any]:
        if isinstance(finding, dict):
            return dict(finding)
        return self.finding_intelligence_service.enrich_finding(finding)

    def _build_member_group_map(self, grouped_findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        member_group_map: dict[str, dict[str, Any]] = {}
        for group in grouped_findings:
            for member_id in group.get("member_ids", []):
                if member_id:
                    member_group_map[member_id] = group
        return member_group_map

    def _build_common_patterns(
        self,
        serialized_findings: list[dict[str, Any]],
        grouped_findings: list[dict[str, Any]],
        member_group_map: dict[str, dict[str, Any]],
        *,
        max_patterns: int,
    ) -> list[dict[str, Any]]:
        pattern_clusters: dict[str, dict[str, Any]] = {}
        for finding in serialized_findings:
            pattern_key, pattern_name = self._pattern_signature(finding)
            cluster = pattern_clusters.setdefault(
                pattern_key,
                {
                    "pattern_key": pattern_key,
                    "pattern_name": pattern_name,
                    "occurrence_count": 0,
                    "group_keys": set(),
                    "files": set(),
                    "file_counts": Counter(),
                    "group_titles": {},
                    "representative": finding,
                    "representative_rank": self._representative_rank(finding),
                },
            )
            cluster["occurrence_count"] += 1
            file_path = finding.get("file_path")
            if file_path:
                cluster["files"].add(file_path)
                cluster["file_counts"][file_path] += 1
            member_id = finding.get("id")
            group = member_group_map.get(member_id)
            if group is not None:
                cluster["group_keys"].add(group["group_key"])
                cluster["group_titles"][group["group_key"]] = {
                    "group_key": group["group_key"],
                    "title": group["title"],
                    "member_count": group["member_count"],
                    "anchor_id": group.get("anchor_id"),
                }
            candidate_rank = self._representative_rank(finding)
            if candidate_rank < cluster["representative_rank"]:
                cluster["representative"] = finding
                cluster["representative_rank"] = candidate_rank

        patterns: list[dict[str, Any]] = []
        for cluster in pattern_clusters.values():
            representative = cluster["representative"]
            occurrence_count = cluster["occurrence_count"]
            grouped_count = len(cluster["group_keys"])
            top_files = [
                {"file_path": file_path, "count": count}
                for file_path, count in cluster["file_counts"].most_common(5)
            ]
            patterns.append(
                {
                    "pattern_key": cluster["pattern_key"],
                    "anchor_id": f"pattern-{self._slugify(cluster['pattern_key'])}",
                    "pattern_name": cluster["pattern_name"],
                    "total_occurrence_count": occurrence_count,
                    "grouped_finding_count": grouped_count,
                    "files_affected_count": len(cluster["files"]),
                    "top_affected_files": top_files,
                    "representative_explanation": representative.get("plain_explanation"),
                    "likely_impact_type": representative.get("impact_summary"),
                    "representative_recommendation": representative.get("recommended_action"),
                    "finding_type": representative.get("finding_type"),
                    "security_relevance": representative.get("security_relevance"),
                    "highest_severity": representative.get("severity"),
                    "fix_one_remove_many_hint": self._fix_one_remove_many_hint(
                        representative,
                        occurrence_count=occurrence_count,
                        grouped_count=grouped_count,
                        files_count=len(cluster["files"]),
                    ),
                    "underlying_groups": sorted(
                        cluster["group_titles"].values(),
                        key=lambda group: (-group["member_count"], group["title"].lower()),
                    )[:5],
                }
            )

        return sorted(
            patterns,
            key=lambda pattern: (
                -pattern["total_occurrence_count"],
                -pattern["grouped_finding_count"],
                SEVERITY_RANK.get(pattern["highest_severity"], len(SEVERITY_ORDER)),
                pattern["pattern_name"].lower(),
            ),
        )[:max_patterns]

    def _build_rare_but_important(
        self,
        grouped_findings: list[dict[str, Any]],
        *,
        limit: int,
    ) -> list[dict[str, Any]]:
        rare_candidates = [
            group
            for group in grouped_findings
            if group.get("security_relevance") == "direct" and group.get("member_count", 0) <= 3
        ]
        return sorted(
            rare_candidates,
            key=lambda group: (
                self.finding_intelligence_service.sort_key(group),
                group.get("member_count", 0),
                group.get("title", "").lower(),
            ),
        )[:limit]

    def _build_hotspots(self, serialized_findings: list[dict[str, Any]], *, limit: int) -> dict[str, list[dict[str, Any]]]:
        file_counts: Counter[str] = Counter()
        module_counts: Counter[str] = Counter()
        file_security: defaultdict[str, int] = defaultdict(int)
        module_security: defaultdict[str, int] = defaultdict(int)

        for finding in serialized_findings:
            file_path = finding.get("file_path")
            if not file_path:
                continue
            module_path = self._module_path(file_path)
            file_counts[file_path] += 1
            module_counts[module_path] += 1
            if finding.get("security_relevance") == "direct":
                file_security[file_path] += 1
                module_security[module_path] += 1

        return {
            "files": [
                {
                    "path": path,
                    "anchor_id": f"hotspot-file-{self._slugify(path)}",
                    "count": count,
                    "direct_security_count": file_security[path],
                }
                for path, count in file_counts.most_common(limit)
            ],
            "modules": [
                {
                    "path": path,
                    "anchor_id": f"hotspot-module-{self._slugify(path)}",
                    "count": count,
                    "direct_security_count": module_security[path],
                }
                for path, count in module_counts.most_common(limit)
            ],
        }

    def _pattern_signature(self, finding: dict[str, Any]) -> tuple[str, str]:
        tool_name = str(finding.get("tool_name", "")).lower()
        category = str(finding.get("category", "")).lower()
        title = str(finding.get("title", "")).strip()
        raw_payload = finding.get("raw_payload") or {}
        rule_code = str(raw_payload.get("rule_code") or "").strip().lower()
        check = str(raw_payload.get("check") or "").strip().lower()
        check_id = str(raw_payload.get("check_id") or "").strip().lower()

        if tool_name == "dart-flutter-analyze" and rule_code:
            return (
                f"dart_diagnostic:{rule_code}",
                f"Dart analyzer: {rule_code.replace('_', ' ')}",
            )
        if check:
            return (
                f"{tool_name}:{check}",
                self._humanize_identifier(check),
            )
        if check_id:
            return (
                f"{tool_name}:{check_id}",
                self._humanize_identifier(check_id),
            )
        if tool_name.startswith("framework") and title:
            return (
                f"{tool_name}:{self._normalize_title(title)}",
                title,
            )
        if category.startswith("dependency"):
            dependency_name = str((raw_payload.get("dependency") or {}).get("name") or "").strip().lower()
            if dependency_name:
                return (
                    f"{tool_name}:dependency:{dependency_name}",
                    f"{self._humanize_identifier(tool_name)}: {dependency_name}",
                )
        normalized_title = self._normalize_title(title)
        return (
            f"{tool_name}:{category}:{normalized_title}",
            title or self._humanize_identifier(category or tool_name or "issue_pattern"),
        )

    def _fix_one_remove_many_hint(
        self,
        representative: dict[str, Any],
        *,
        occurrence_count: int,
        grouped_count: int,
        files_count: int,
    ) -> str | None:
        if representative.get("finding_type") != "code_correctness":
            return None
        if occurrence_count < 8 and files_count < 3:
            return None

        raw_payload = representative.get("raw_payload") or {}
        rule_code = str(raw_payload.get("rule_code") or "").lower()
        if rule_code.startswith("undefined_"):
            return (
                f"This pattern appears {occurrence_count} times across {files_count} files and {grouped_count} grouped findings. "
                "Fixing a shared import, model, or API mismatch may remove many downstream analyzer errors."
            )
        if rule_code == "argument_type_not_assignable":
            return (
                f"This pattern appears {occurrence_count} times across {files_count} files. "
                "Fixing the underlying type mismatch in a shared model or function signature may clear many follow-on issues."
            )
        return (
            f"This pattern appears {occurrence_count} times across {files_count} files. "
            "A shared code or build root cause is likely; fixing the first representative case may remove many related findings."
        )

    def _representative_rank(self, finding: dict[str, Any]) -> tuple[int, int, str]:
        severity = str(finding.get("severity", "unknown")).lower()
        return (
            SEVERITY_RANK.get(severity, len(SEVERITY_ORDER)),
            0 if finding.get("security_relevance") == "direct" else 1,
            str(finding.get("title", "")).lower(),
        )

    @staticmethod
    def _module_path(file_path: str) -> str:
        path = PurePosixPath(file_path)
        if str(path.parent) == ".":
            return "(repo root)"
        return str(path.parent)

    @staticmethod
    def _normalize_title(title: str) -> str:
        normalized = re.sub(r"\s+", " ", title.strip().lower())
        normalized = re.sub(r"[^a-z0-9:_./ -]+", "", normalized)
        return normalized

    @staticmethod
    def _humanize_identifier(value: str) -> str:
        text = value.replace(":", " ").replace("-", " ").replace("_", " ").strip()
        text = re.sub(r"\s+", " ", text)
        return text[:1].upper() + text[1:] if text else value

    @staticmethod
    def _slugify(value: str) -> str:
        slug = "".join(char if char.isalnum() else "-" for char in value.lower())
        slug = "-".join(part for part in slug.split("-") if part)
        return slug or "item"
