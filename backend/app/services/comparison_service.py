"""Deterministic scan-to-scan comparison helpers."""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.models.scan import ScanJob
from backend.app.schemas.scan import (
    GroupedComparisonRead,
    ProjectSummaryRead,
    ScanComparisonRead,
    SeverityDeltaRead,
)
from backend.app.services.grouping_service import FindingGroupingService, GroupedFinding


class ScanComparisonService:
    """Compare grouped findings between two scans of the same project."""

    _severity_weights = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "unknown": 1,
    }

    def __init__(self, db: Session) -> None:
        self.db = db
        self.grouping_service = FindingGroupingService()

    def build_for_scan(self, scan_job: ScanJob, compare_to_scan_id: str | None = None) -> ScanComparisonRead:
        """Build a comparison summary for a scan and an older scan from the same project."""
        previous_scan = self.resolve_previous_scan(scan_job, compare_to_scan_id=compare_to_scan_id)
        if previous_scan is None:
            return ScanComparisonRead(
                comparison_available=False,
                message="No previous scan is available for comparison.",
                project=ProjectSummaryRead(id=scan_job.project.id, name=scan_job.project.name),
                current_scan_id=scan_job.id,
            )
        return self.compare_scans(scan_job, previous_scan)

    def resolve_previous_scan(self, scan_job: ScanJob, compare_to_scan_id: str | None = None) -> ScanJob | None:
        """Resolve a valid older scan from the same project."""
        if compare_to_scan_id:
            previous_scan = self.load_scan_job(compare_to_scan_id)
            if previous_scan is None:
                raise ValueError("Comparison target scan was not found.")
            self._validate_pair(scan_job, previous_scan)
            return previous_scan

        return (
            self.db.execute(
                select(ScanJob)
                .where(
                    ScanJob.project_id == scan_job.project_id,
                    ScanJob.id != scan_job.id,
                    ScanJob.created_at < scan_job.created_at,
                    ScanJob.status.in_(["completed", "partial", "failed"]),
                )
                .options(
                    selectinload(ScanJob.project),
                    selectinload(ScanJob.findings),
                    selectinload(ScanJob.tool_executions),
                    selectinload(ScanJob.reports),
                )
                .order_by(ScanJob.created_at.desc())
            )
            .scalars()
            .first()
        )

    def list_previous_scan_options(self, scan_job: ScanJob) -> list[dict[str, Any]]:
        """List older scans that can be selected as comparison targets."""
        scans = (
            self.db.execute(
                select(ScanJob)
                .where(
                    ScanJob.project_id == scan_job.project_id,
                    ScanJob.id != scan_job.id,
                    ScanJob.created_at < scan_job.created_at,
                    ScanJob.status.in_(["completed", "partial", "failed"]),
                )
                .order_by(ScanJob.created_at.desc())
            )
            .scalars()
            .all()
        )
        return [
            {
                "id": previous_scan.id,
                "status": previous_scan.status,
                "created_at": previous_scan.created_at,
                "source_label": previous_scan.source_label,
                "total_findings": previous_scan.total_findings,
            }
            for previous_scan in scans
        ]

    def compare_scans(self, current_scan: ScanJob, previous_scan: ScanJob) -> ScanComparisonRead:
        """Compare two same-project scans using deterministic grouped finding keys."""
        self._validate_pair(current_scan, previous_scan)

        previous_groups = self._group_by_key(previous_scan)
        current_groups = self._group_by_key(current_scan)
        previous_keys = set(previous_groups)
        current_keys = set(current_groups)

        new_groups = [
            self._build_entry("new", current_group=current_groups[key], previous_group=None)
            for key in sorted(current_keys - previous_keys)
        ]
        resolved_groups = [
            self._build_entry("resolved", current_group=None, previous_group=previous_groups[key])
            for key in sorted(previous_keys - current_keys)
        ]
        unchanged_groups = [
            self._build_entry(
                "unchanged",
                current_group=current_groups[key],
                previous_group=previous_groups[key],
            )
            for key in sorted(current_keys & previous_keys)
        ]

        previous_severity = self._severity_counts(previous_groups.values())
        current_severity = self._severity_counts(current_groups.values())
        severity_deltas = {
            severity: SeverityDeltaRead(
                previous=previous_severity.get(severity, 0),
                current=current_severity.get(severity, 0),
                delta=current_severity.get(severity, 0) - previous_severity.get(severity, 0),
            )
            for severity in sorted(set(previous_severity) | set(current_severity))
        }

        previous_risk_score = self._risk_score(previous_groups.values())
        current_risk_score = self._risk_score(current_groups.values())
        return ScanComparisonRead(
            comparison_available=True,
            project=ProjectSummaryRead(id=current_scan.project.id, name=current_scan.project.name),
            current_scan_id=current_scan.id,
            previous_scan_id=previous_scan.id,
            trend=self._trend(previous_risk_score, current_risk_score),
            summary={
                "new_group_count": len(new_groups),
                "resolved_group_count": len(resolved_groups),
                "unchanged_group_count": len(unchanged_groups),
                "new_occurrence_count": sum(item.current_member_count for item in new_groups),
                "resolved_occurrence_count": sum(item.previous_member_count for item in resolved_groups),
                "unchanged_occurrence_count": sum(item.current_member_count for item in unchanged_groups),
            },
            severity_deltas=severity_deltas,
            grouped_delta={
                "previous_group_count": len(previous_groups),
                "current_group_count": len(current_groups),
                "delta_group_count": len(current_groups) - len(previous_groups),
                "previous_occurrence_count": sum(group.member_count for group in previous_groups.values()),
                "current_occurrence_count": sum(group.member_count for group in current_groups.values()),
                "delta_occurrence_count": sum(group.member_count for group in current_groups.values())
                - sum(group.member_count for group in previous_groups.values()),
                "previous_risk_score": previous_risk_score,
                "current_risk_score": current_risk_score,
                "delta_risk_score": current_risk_score - previous_risk_score,
            },
            new_groups=new_groups,
            resolved_groups=resolved_groups,
            unchanged_groups=unchanged_groups,
        )

    def load_scan_job(self, scan_job_id: str) -> ScanJob | None:
        """Load one scan job with the relations needed for comparison."""
        return (
            self.db.execute(
                select(ScanJob)
                .where(ScanJob.id == scan_job_id)
                .options(
                    selectinload(ScanJob.project),
                    selectinload(ScanJob.findings),
                    selectinload(ScanJob.tool_executions),
                    selectinload(ScanJob.reports),
                )
            )
            .scalars()
            .first()
        )

    def _group_by_key(self, scan_job: ScanJob) -> dict[str, GroupedFinding]:
        return {group.group_key: group for group in self.grouping_service.group(scan_job.findings)}

    def _build_entry(
        self,
        status: str,
        *,
        current_group: GroupedFinding | None,
        previous_group: GroupedFinding | None,
    ) -> GroupedComparisonRead:
        group = current_group or previous_group
        if group is None:
            raise ValueError("Comparison entry requires at least one grouped finding.")
        previous_count = previous_group.member_count if previous_group else 0
        current_count = current_group.member_count if current_group else 0
        return GroupedComparisonRead(
            status=status,  # type: ignore[arg-type]
            group_key=group.group_key,
            title=group.title,
            description=group.description,
            severity=group.severity,
            category=group.category,
            tool_name=group.tool_name,
            file_path=group.file_path,
            dependency_name=group.dependency_name,
            remediation=group.remediation,
            representative_finding_id=group.representative_finding_id,
            previous_member_count=previous_count,
            current_member_count=current_count,
            delta_member_count=current_count - previous_count,
            affected_files=group.affected_files,
            member_ids=group.member_ids,
            sample_members=group.sample_members,
        )

    def _validate_pair(self, current_scan: ScanJob, previous_scan: ScanJob) -> None:
        if current_scan.project_id != previous_scan.project_id:
            raise ValueError("Scan comparisons are only supported within the same project.")
        if current_scan.id == previous_scan.id:
            raise ValueError("A scan cannot be compared against itself.")
        if previous_scan.created_at >= current_scan.created_at:
            raise ValueError("Comparison target must be older than the current scan.")

    def _severity_counts(self, groups: list[GroupedFinding] | Any) -> Counter:
        counter: Counter = Counter()
        for group in groups:
            counter[group.severity] += group.member_count
        return counter

    def _risk_score(self, groups: list[GroupedFinding] | Any) -> int:
        total = 0
        for group in groups:
            total += self._severity_weights.get(group.severity, 1) * group.member_count
        return total

    @staticmethod
    def _trend(previous_risk_score: int, current_risk_score: int) -> str:
        if current_risk_score > previous_risk_score:
            return "worsened"
        if current_risk_score < previous_risk_score:
            return "improved"
        return "unchanged"
