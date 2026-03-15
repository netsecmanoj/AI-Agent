"""Project-level trend aggregation derived from stored scan history."""

from __future__ import annotations

from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.models.project import Project
from backend.app.models.scan import ScanJob
from backend.app.schemas.scan import ProjectSummaryRead, ProjectTrendPointRead, ProjectTrendSummaryRead
from backend.app.services.comparison_service import ScanComparisonService
from backend.app.services.grouping_service import FindingGroupingService
from backend.app.services.policy_service import PolicyEvaluationService


class ProjectTrendService:
    """Build deterministic project-level trend summaries from stored scans."""

    terminal_statuses = {"completed", "partial", "failed"}
    severity_weights = {
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
        self.comparison_service = ScanComparisonService(db)
        self.policy_service = PolicyEvaluationService()

    def build_project_trend(self, project_id: str, *, limit: int | None = None) -> ProjectTrendSummaryRead | None:
        """Return a project-level trend summary ordered by scan creation time."""
        project = self.db.get(Project, project_id)
        if project is None:
            return None

        all_scans = self._load_project_scans(project_id)
        scans = all_scans[-limit:] if limit is not None else all_scans

        points: list[ProjectTrendPointRead] = []
        previous_comparable_scan = self._initial_previous_scan(all_scans, scans)
        for scan_job in scans:
            comparison_payload = self._comparison_payload(scan_job, previous_comparable_scan)
            policy_payload = self.policy_service.evaluate_scan(
                scan_job,
                comparison=comparison_payload,
            ).model_dump(mode="json")
            point = ProjectTrendPointRead(
                scan_id=scan_job.id,
                created_at=scan_job.created_at,
                status=scan_job.status,
                source_type=scan_job.source_type,
                source_label=scan_job.source_label,
                total_findings=scan_job.total_findings or len(scan_job.findings),
                severity_counts=dict(Counter(finding.severity for finding in scan_job.findings)),
                weighted_risk_score=self._weighted_risk_score(scan_job),
                policy_status=policy_payload["status"],
                comparison_available=bool(comparison_payload.get("comparison_available")),
                comparison_trend=comparison_payload.get("trend"),
                new_group_count=comparison_payload.get("summary", {}).get("new_group_count"),
                resolved_group_count=comparison_payload.get("summary", {}).get("resolved_group_count"),
                unchanged_group_count=comparison_payload.get("summary", {}).get("unchanged_group_count"),
                weighted_risk_delta=comparison_payload.get("grouped_delta", {}).get("delta_risk_score"),
            )
            points.append(point)
            if scan_job.status in self.terminal_statuses:
                previous_comparable_scan = scan_job

        latest_point = points[-1] if points else None
        message = None
        if not points:
            message = "This project has no recorded scans yet."
        elif len(points) == 1:
            message = "Trend data is available from the first scan onward. Comparison deltas appear after a second scan."

        return ProjectTrendSummaryRead(
            project=ProjectSummaryRead(id=project.id, name=project.name),
            effective_policy=self.policy_service.resolve_project_policy(project).payload(),
            total_scans=len(points),
            comparison_points=sum(1 for point in points if point.comparison_available),
            latest_weighted_risk_score=latest_point.weighted_risk_score if latest_point else None,
            latest_policy_status=latest_point.policy_status if latest_point else None,
            latest_severity_counts=latest_point.severity_counts if latest_point else {},
            policy_counts=dict(Counter(point.policy_status for point in points)),
            message=message,
            points=points,
        )

    def _load_project_scans(self, project_id: str) -> list[ScanJob]:
        return (
            self.db.execute(
                select(ScanJob)
                .where(ScanJob.project_id == project_id)
                .options(
                    selectinload(ScanJob.project),
                    selectinload(ScanJob.findings),
                    selectinload(ScanJob.tool_executions),
                    selectinload(ScanJob.reports),
                )
                .order_by(ScanJob.created_at.asc())
            )
            .scalars()
            .all()
        )

    def _comparison_payload(self, scan_job: ScanJob, previous_scan: ScanJob | None) -> dict:
        if previous_scan is None or scan_job.status not in self.terminal_statuses:
            return {
                "comparison_available": False,
                "message": "No previous scan is available for comparison.",
            }
        return self.comparison_service.compare_scans(scan_job, previous_scan).model_dump(mode="json")

    def _initial_previous_scan(
        self,
        all_scans: list[ScanJob],
        selected_scans: list[ScanJob],
    ) -> ScanJob | None:
        if not selected_scans or len(selected_scans) == len(all_scans):
            return None
        first_selected_id = selected_scans[0].id
        previous_scan: ScanJob | None = None
        for scan_job in all_scans:
            if scan_job.id == first_selected_id:
                break
            if scan_job.status in self.terminal_statuses:
                previous_scan = scan_job
        return previous_scan

    def _weighted_risk_score(self, scan_job: ScanJob) -> int:
        total = 0
        for grouped_finding in self.grouping_service.group(scan_job.findings):
            total += self.severity_weights.get(grouped_finding.severity, 1) * grouped_finding.member_count
        return total
