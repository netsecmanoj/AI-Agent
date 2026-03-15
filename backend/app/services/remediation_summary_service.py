"""Compact remediation-oriented summary helpers for scan review exports."""

from __future__ import annotations

from typing import Any

from backend.app.services.finding_intelligence_service import FindingIntelligenceService


class RemediationSummaryService:
    """Build a compact review artifact from existing triage and grouped summaries."""

    def __init__(self) -> None:
        self.finding_intelligence_service = FindingIntelligenceService()

    def build_summary(
        self,
        *,
        triage_summary: dict[str, Any],
        grouped_findings: list[dict[str, Any]],
        comparison: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Return a compact action-oriented remediation summary."""
        common_patterns = [self._compact_pattern(pattern) for pattern in triage_summary.get("common_patterns", [])[:10]]
        hotspot_files = [self._compact_hotspot(hotspot, kind="file") for hotspot in triage_summary.get("hotspots", {}).get("files", [])[:10]]
        hotspot_modules = [self._compact_hotspot(hotspot, kind="module") for hotspot in triage_summary.get("hotspots", {}).get("modules", [])[:10]]
        direct_security_findings = [
            self._compact_group(group)
            for group in grouped_findings
            if group.get("security_relevance") == "direct"
        ]
        fix_one_remove_many = [
            self._compact_pattern(pattern)
            for pattern in triage_summary.get("common_patterns", [])
            if pattern.get("fix_one_remove_many_hint")
        ][:10]
        return {
            "common_issue_patterns": common_patterns,
            "hotspot_files": hotspot_files,
            "hotspot_modules": hotspot_modules,
            "direct_security_findings": direct_security_findings,
            "fix_one_remove_many": fix_one_remove_many,
            "comparison_summary": self._compact_comparison(comparison),
        }

    def _compact_pattern(self, pattern: dict[str, Any]) -> dict[str, Any]:
        return {
            "label": pattern.get("pattern_name"),
            "type": pattern.get("finding_type"),
            "security_relevance": pattern.get("security_relevance"),
            "count": pattern.get("total_occurrence_count"),
            "affected_scope_count": pattern.get("files_affected_count"),
            "affected_items": [item["file_path"] for item in pattern.get("top_affected_files", [])],
            "recommendation": pattern.get("representative_recommendation"),
            "likely_impact": pattern.get("likely_impact_type"),
            "anchor_id": pattern.get("anchor_id"),
            "pattern_key": pattern.get("pattern_key"),
            "fix_one_remove_many_hint": pattern.get("fix_one_remove_many_hint"),
        }

    def _compact_hotspot(self, hotspot: dict[str, Any], *, kind: str) -> dict[str, Any]:
        return {
            "label": hotspot.get("path"),
            "type": f"{kind}_hotspot",
            "security_relevance": "direct" if hotspot.get("direct_security_count", 0) else "none",
            "count": hotspot.get("count"),
            "affected_items": [hotspot.get("path")],
            "recommendation": "Review grouped findings in this hotspot first and clear repeated root causes before expanding scope.",
            "anchor_id": hotspot.get("anchor_id"),
            "hotspot_file": hotspot.get("path") if kind == "file" else None,
            "hotspot_module": hotspot.get("path") if kind == "module" else None,
        }

    def _compact_group(self, group: dict[str, Any]) -> dict[str, Any]:
        return {
            "label": group.get("title"),
            "type": group.get("finding_type"),
            "security_relevance": group.get("security_relevance"),
            "count": group.get("member_count"),
            "affected_scope_count": len(group.get("affected_files", [])),
            "affected_items": group.get("affected_files", [])[:5],
            "recommendation": group.get("recommended_action"),
            "likely_impact": group.get("impact_summary"),
            "anchor_id": group.get("anchor_id"),
            "group_key": group.get("group_key"),
        }

    @staticmethod
    def _compact_comparison(comparison: dict[str, Any] | None) -> dict[str, Any] | None:
        if not comparison or not comparison.get("comparison_available"):
            return None
        summary = comparison.get("summary", {})
        grouped_delta = comparison.get("grouped_delta", {})
        return {
            "trend": comparison.get("trend"),
            "previous_scan_id": comparison.get("previous_scan_id"),
            "new_group_count": summary.get("new_group_count", 0),
            "resolved_group_count": summary.get("resolved_group_count", 0),
            "unchanged_group_count": summary.get("unchanged_group_count", 0),
            "risk_delta": grouped_delta.get("delta_risk_score"),
        }
