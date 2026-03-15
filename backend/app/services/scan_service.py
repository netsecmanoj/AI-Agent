"""Service layer for queuing scans, executing queued jobs, and persisting results."""

from pathlib import Path
from uuid import uuid4

from sqlalchemy import delete
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.models.base import utcnow
from backend.app.models.project import Project
from backend.app.models.report import Report
from backend.app.models.scan import Finding, ScanJob, ToolExecution
from backend.app.schemas.scan import ScanCreateRequest
from backend.app.services.ai_service import AIEnrichmentService
from backend.app.services.comparison_service import ScanComparisonService
from backend.app.services.execution_service import ScanExecutionService
from backend.app.services.report_service import ReportService
from backend.app.services.workspace_service import WorkspaceService
from fastapi import UploadFile


class ScanService:
    """Coordinate scan creation and worker-side execution."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.workspace_service = WorkspaceService()
        self.execution_service = ScanExecutionService()
        self.comparison_service = ScanComparisonService(db)
        self.ai_service = AIEnrichmentService(db)
        self.report_service = ReportService()

    def enqueue_scan(self, request: ScanCreateRequest, upload: UploadFile | None = None) -> ScanJob:
        """Prepare scan input and persist a queued scan job quickly."""
        scan_id = str(uuid4())
        prepared = self.workspace_service.prepare(scan_id=scan_id, request=request, upload=upload)
        project = self._resolve_project(request, prepared.project_name, prepared.source_type, prepared.source_value)
        queued_at = utcnow()
        scan_job = ScanJob(
            id=scan_id,
            project_id=project.id,
            status="queued",
            source_type=prepared.source_type,
            source_value=prepared.source_value,
            source_filename=prepared.source_filename,
            workspace_path=str(prepared.workspace_path),
            source_label=self._build_source_label(
                prepared.source_type,
                prepared.source_value,
                prepared.source_filename,
                request.source_label,
            ),
            queued_at=queued_at,
            started_at=queued_at,
        )
        self.db.add(scan_job)
        self.db.commit()
        return self._reload_scan(scan_job.id)

    def execute_scan_job(self, scan_job_id: str) -> ScanJob:
        """Execute one queued scan job inside the worker context."""
        scan_job = self._reload_scan(scan_job_id)
        if scan_job.status not in {"queued", "running"}:
            return scan_job

        self._transition_to_running(scan_job)
        execution_summary = self.execution_service.execute(Path(scan_job.workspace_path))
        self._reset_previous_results(scan_job.id)
        for result in execution_summary.results:
            tool_execution = ToolExecution(
                scan_job_id=scan_job.id,
                tool_name=result.tool_name,
                status=result.status,
                command=result.command,
                error_message=result.error_message,
            )
            self.db.add(tool_execution)
            for finding in self.execution_service.normalize_findings(result):
                self.db.add(
                    Finding(
                        project_id=scan_job.project_id,
                        scan_job_id=scan_job.id,
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity,
                        category=finding.category,
                        tool_name=finding.tool_name,
                        file_path=finding.file_path,
                        line_number=finding.line_number,
                        remediation=finding.remediation,
                        raw_payload=finding.raw_payload,
                    )
                )
        self.db.commit()

        scan_job = self._reload_scan(scan_job.id)
        scan_job.total_findings = execution_summary.total_findings
        scan_job.partial = execution_summary.partial
        scan_job.status = execution_summary.status
        scan_job.error_message = (
            "\n".join(execution_summary.error_messages) if execution_summary.error_messages else None
        )
        scan_job.worker_error = None
        scan_job.finished_at = utcnow()
        scan_job.duration_seconds = self.calculate_duration_seconds(scan_job.started_at, scan_job.finished_at)
        scan_job.ai_status = "pending"
        scan_job.ai_summary = None
        scan_job.ai_top_risks = None
        scan_job.ai_next_steps = None
        scan_job.ai_error = None
        self.db.commit()

        scan_job = self._reload_scan(scan_job.id)
        scan_job = self.ai_service.enrich_scan(scan_job)
        comparison_summary = self.comparison_service.build_for_scan(scan_job).model_dump(mode="json")
        for report in self.report_service.generate_reports(scan_job, comparison=comparison_summary):
            self.db.add(report)
        self.db.commit()
        return self._reload_scan(scan_job.id)

    def fail_scan_job(self, scan_job_id: str, error_message: str) -> ScanJob:
        """Mark a queued or running scan as failed from worker-level errors."""
        scan_job = self._reload_scan(scan_job_id)
        scan_job.status = "failed"
        scan_job.partial = False
        scan_job.worker_error = error_message
        scan_job.error_message = error_message
        scan_job.finished_at = utcnow()
        scan_job.duration_seconds = self.calculate_duration_seconds(scan_job.started_at, scan_job.finished_at)
        scan_job.retry_count += 1
        scan_job.ai_status = "pending"
        scan_job.ai_summary = None
        scan_job.ai_top_risks = None
        scan_job.ai_next_steps = None
        scan_job.ai_error = None
        self.db.commit()
        return self._reload_scan(scan_job.id)

    def _get_or_create_project(self, name: str, source_type: str, source_value: str) -> Project:
        project = self.db.execute(select(Project).where(Project.name == name)).scalars().first()
        if project:
            project.source_type = source_type
            project.source_value = source_value
            self.db.commit()
            return project
        project = Project(name=name, source_type=source_type, source_value=source_value)
        self.db.add(project)
        self.db.commit()
        self.db.refresh(project)
        return project

    def _resolve_project(
        self,
        request: ScanCreateRequest,
        fallback_name: str,
        source_type: str,
        source_value: str,
    ) -> Project:
        if request.project_id:
            project = self.db.get(Project, request.project_id)
            if project is None:
                raise ValueError("Selected project was not found.")
            project.source_type = source_type
            project.source_value = source_value
            self.db.commit()
            self.db.refresh(project)
            return project
        return self._get_or_create_project(request.project_name or fallback_name, source_type, source_value)

    def _reload_scan(self, scan_job_id: str) -> ScanJob:
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
            .one()
        )

    def _transition_to_running(self, scan_job: ScanJob) -> None:
        scan_job.status = "running"
        scan_job.partial = False
        scan_job.error_message = None
        scan_job.worker_error = None
        scan_job.started_at = utcnow()
        scan_job.finished_at = None
        scan_job.duration_seconds = None
        scan_job.ai_status = "pending"
        scan_job.ai_summary = None
        scan_job.ai_top_risks = None
        scan_job.ai_next_steps = None
        scan_job.ai_error = None
        self.db.commit()

    def _reset_previous_results(self, scan_job_id: str) -> None:
        report_paths = [report.path for report in self.db.execute(select(Report).where(Report.scan_job_id == scan_job_id)).scalars().all()]
        for report_path in report_paths:
            Path(report_path).unlink(missing_ok=True)
        self.db.execute(delete(Finding).where(Finding.scan_job_id == scan_job_id))
        self.db.execute(delete(ToolExecution).where(ToolExecution.scan_job_id == scan_job_id))
        self.db.execute(delete(Report).where(Report.scan_job_id == scan_job_id))
        self.db.commit()

    def _build_source_label(
        self,
        source_type: str,
        source_value: str,
        source_filename: str | None,
        requested_source_label: str | None = None,
    ) -> str:
        if requested_source_label:
            return requested_source_label.strip()
        if source_type == "uploaded_archive" and source_filename:
            return source_filename
        return Path(source_value).name

    @staticmethod
    def calculate_duration_seconds(started_at, finished_at) -> int | None:
        if not started_at or not finished_at:
            return None
        if started_at.tzinfo is None and finished_at.tzinfo is not None:
            started_at = started_at.replace(tzinfo=finished_at.tzinfo)
        if finished_at.tzinfo is None and started_at.tzinfo is not None:
            finished_at = finished_at.replace(tzinfo=started_at.tzinfo)
        return max(int((finished_at - started_at).total_seconds()), 0)
