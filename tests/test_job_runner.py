"""Tests for queued scan execution and worker lifecycle transitions."""

from pathlib import Path

from backend.app.models.report import Report
from backend.app.models.scan import Finding, ScanJob
from backend.app.scanners.base import NormalizedFinding, ToolExecutionResult
from backend.app.schemas.scan import ScanCreateRequest
from backend.app.services.execution_service import ScanExecutionSummary
from backend.app.services.job_runner import InProcessJobRunner
from backend.app.services.scan_service import ScanService


def test_worker_processes_queued_scan_to_completed_and_generates_reports(
    isolated_app,
    monkeypatch,
    tmp_path,
) -> None:
    _, session_factory, runner = isolated_app
    target_path = tmp_path / "repo"
    target_path.mkdir()
    (target_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")

    class DummyExecutionService:
        def execute(self, workspace_path: Path) -> ScanExecutionSummary:
            assert workspace_path == target_path
            result = ToolExecutionResult(
                tool_name="dummy-scanner",
                status="completed",
                command="dummy scan",
                findings=[
                    NormalizedFinding(
                        title="Dummy finding",
                        description="Detected by dummy scanner.",
                        severity="low",
                        category="code",
                        tool_name="dummy-scanner",
                        file_path="requirements.txt",
                        raw_payload={"ok": True},
                    )
                ],
            )
            return ScanExecutionSummary(
                status="completed",
                partial=False,
                total_findings=1,
                error_messages=[],
                results=[result],
            )

        @staticmethod
        def normalize_findings(result: ToolExecutionResult):
            return result.findings

    class DummyAIService:
        def __init__(self, db) -> None:
            self.db = db

        def enrich_scan(self, scan_job: ScanJob) -> ScanJob:
            scan_job.ai_status = "completed"
            scan_job.ai_summary = "Management summary generated."
            scan_job.ai_top_risks = "One low-severity issue."
            scan_job.ai_next_steps = "Review and fix the finding."
            for finding in scan_job.findings:
                finding.ai_status = "completed"
                finding.ai_explanation = "Plain language explanation."
                finding.ai_remediation = "Plain language remediation."
            self.db.commit()
            self.db.refresh(scan_job)
            return scan_job

    monkeypatch.setattr("backend.app.services.scan_service.ScanExecutionService", DummyExecutionService)
    monkeypatch.setattr("backend.app.services.scan_service.AIEnrichmentService", DummyAIService)

    session = session_factory()
    try:
        scan_service = ScanService(session)
        queued_scan = scan_service.enqueue_scan(
            ScanCreateRequest(
                source_type="local_path",
                source_value=str(target_path),
                project_name="queued-demo",
            )
        )
        assert queued_scan.status == "queued"

        runner._process(queued_scan.id)
    finally:
        session.close()

    verify_session = session_factory()
    try:
        persisted_scan = verify_session.get(ScanJob, queued_scan.id)
        assert persisted_scan is not None
        assert persisted_scan.status == "completed"
        assert persisted_scan.duration_seconds is not None
        assert persisted_scan.ai_status == "completed"
        assert persisted_scan.ai_summary == "Management summary generated."
        reports = verify_session.query(Report).filter(Report.scan_job_id == queued_scan.id).all()
        findings = verify_session.query(Finding).filter(Finding.scan_job_id == queued_scan.id).all()
        assert len(reports) == 3
        assert {report.report_format for report in reports} == {"json", "html", "summary"}
        assert len(findings) == 1
        assert findings[0].ai_status == "completed"
        assert findings[0].ai_explanation == "Plain language explanation."
    finally:
        verify_session.close()


def test_worker_processes_partial_scan_status(isolated_app, monkeypatch, tmp_path) -> None:
    _, session_factory, runner = isolated_app
    target_path = tmp_path / "repo"
    target_path.mkdir()
    (target_path / "package.json").write_text('{"name":"demo"}', encoding="utf-8")

    class DummyExecutionService:
        def execute(self, workspace_path: Path) -> ScanExecutionSummary:
            result = ToolExecutionResult(
                tool_name="dummy-scanner",
                status="completed",
                command="dummy scan",
                findings=[],
            )
            return ScanExecutionSummary(
                status="partial",
                partial=True,
                total_findings=0,
                error_messages=["dummy-scanner: partial warning"],
                results=[result],
            )

        @staticmethod
        def normalize_findings(result: ToolExecutionResult):
            return result.findings

    monkeypatch.setattr("backend.app.services.scan_service.ScanExecutionService", DummyExecutionService)

    session = session_factory()
    try:
        queued_scan = ScanService(session).enqueue_scan(
            ScanCreateRequest(source_type="local_path", source_value=str(target_path))
        )
        runner._process(queued_scan.id)
    finally:
        session.close()

    verify_session = session_factory()
    try:
        persisted_scan = verify_session.get(ScanJob, queued_scan.id)
        assert persisted_scan is not None
        assert persisted_scan.status == "partial"
        assert persisted_scan.error_message == "dummy-scanner: partial warning"
    finally:
        verify_session.close()


def test_worker_marks_failed_when_execution_raises(isolated_app, monkeypatch, tmp_path) -> None:
    _, session_factory, runner = isolated_app
    target_path = tmp_path / "repo"
    target_path.mkdir()
    (target_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")

    class FailingExecutionService:
        def execute(self, workspace_path: Path) -> ScanExecutionSummary:
            raise RuntimeError("simulated worker failure")

    monkeypatch.setattr("backend.app.services.scan_service.ScanExecutionService", FailingExecutionService)

    session = session_factory()
    try:
        queued_scan = ScanService(session).enqueue_scan(
            ScanCreateRequest(source_type="local_path", source_value=str(target_path))
        )
        runner._process(queued_scan.id)
    finally:
        session.close()

    verify_session = session_factory()
    try:
        persisted_scan = verify_session.get(ScanJob, queued_scan.id)
        assert persisted_scan is not None
        assert persisted_scan.status == "failed"
        assert persisted_scan.worker_error is not None
        assert persisted_scan.retry_count == 1
    finally:
        verify_session.close()


def test_worker_status_snapshot_exposes_queue_and_cleanup_visibility(isolated_app, monkeypatch) -> None:
    _, _, runner = isolated_app
    monkeypatch.setattr("backend.app.services.job_runner.settings.cleanup_interval_seconds", 123)
    monkeypatch.setattr("backend.app.services.job_runner.settings.cleanup_on_startup", True)
    runner.enqueue("scan-123")
    snapshot = runner.status_snapshot()

    assert snapshot["queue_depth"] >= 1
    assert snapshot["cleanup_interval_seconds"] == 123
    assert snapshot["cleanup_on_startup"] is True
    assert "storage_counts" in snapshot
