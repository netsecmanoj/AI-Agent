"""Tests for retention cleanup behavior and safety rules."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from backend.app.core.config import get_settings
from backend.app.models.base import utcnow
from backend.app.models.project import Project
from backend.app.models.report import Report
from backend.app.models.scan import ScanJob
from backend.app.services.cleanup_service import CleanupService


def test_cleanup_deletes_only_inactive_managed_artifacts(isolated_app, monkeypatch) -> None:
    _, session_factory, runner = isolated_app
    runner.stop()

    now = utcnow()
    settings = get_settings()
    monkeypatch.setattr("backend.app.services.cleanup_service.settings.upload_retention_days", 1)
    monkeypatch.setattr("backend.app.services.cleanup_service.settings.workspace_retention_days", 1)
    monkeypatch.setattr("backend.app.services.cleanup_service.settings.report_retention_days", 1)

    old_finished_at = now - timedelta(days=10)

    session = session_factory()
    try:
        project = Project(name="cleanup-demo", source_type="manual", source_value="")
        session.add(project)
        session.commit()
        session.refresh(project)

        old_scan = ScanJob(
            id="old-scan",
            project_id=project.id,
            project=project,
            status="completed",
            source_type="uploaded_archive",
            source_value=str((settings.scan_upload_dir / "old-scan" / "archive.zip").resolve()),
            source_filename="repo.zip",
            workspace_path=str((settings.scan_workspace_dir / "old-scan" / "source").resolve()),
            finished_at=old_finished_at,
        )
        session.add(old_scan)

        active_scan = ScanJob(
            id="active-scan",
            project_id=project.id,
            project=project,
            status="queued",
            source_type="uploaded_archive",
            source_value=str((settings.scan_upload_dir / "active-scan" / "archive.zip").resolve()),
            source_filename="repo.zip",
            workspace_path=str((settings.scan_workspace_dir / "active-scan" / "source").resolve()),
        )
        session.add(active_scan)
        session.commit()

        old_report_dir = settings.report_output_dir / old_scan.id
        old_report_dir.mkdir(parents=True, exist_ok=True)
        old_report_path = old_report_dir / "report.json"
        old_report_path.write_text("{}", encoding="utf-8")
        session.add(Report(scan_job_id=old_scan.id, report_format="json", path=str(old_report_path.resolve())))

        active_report_dir = settings.report_output_dir / active_scan.id
        active_report_dir.mkdir(parents=True, exist_ok=True)
        active_report_path = active_report_dir / "report.json"
        active_report_path.write_text("{}", encoding="utf-8")
        session.add(Report(scan_job_id=active_scan.id, report_format="json", path=str(active_report_path.resolve())))

        upload_old = settings.scan_upload_dir / old_scan.id
        upload_old.mkdir(parents=True, exist_ok=True)
        (upload_old / "repo.zip").write_text("archive", encoding="utf-8")
        upload_active = settings.scan_upload_dir / active_scan.id
        upload_active.mkdir(parents=True, exist_ok=True)
        (upload_active / "repo.zip").write_text("archive", encoding="utf-8")

        workspace_old = settings.scan_workspace_dir / old_scan.id
        workspace_old.mkdir(parents=True, exist_ok=True)
        (workspace_old / "source").mkdir(parents=True, exist_ok=True)
        workspace_active = settings.scan_workspace_dir / active_scan.id
        workspace_active.mkdir(parents=True, exist_ok=True)
        (workspace_active / "source").mkdir(parents=True, exist_ok=True)
        session.commit()

        summary = CleanupService(session).run_cleanup()

        assert summary.uploads_deleted == 1
        assert summary.workspaces_deleted == 1
        assert summary.reports_deleted == 1
        assert not upload_old.exists()
        assert not workspace_old.exists()
        assert not old_report_path.exists()
        assert upload_active.exists()
        assert workspace_active.exists()
        assert active_report_path.exists()
    finally:
        session.close()


def test_cleanup_handles_missing_paths_gracefully(isolated_app, monkeypatch) -> None:
    _, session_factory, runner = isolated_app
    runner.stop()

    settings = get_settings()
    monkeypatch.setattr("backend.app.services.cleanup_service.settings.upload_retention_days", 1)
    monkeypatch.setattr("backend.app.services.cleanup_service.settings.workspace_retention_days", 1)
    monkeypatch.setattr("backend.app.services.cleanup_service.settings.report_retention_days", 1)

    session = session_factory()
    try:
        project = Project(name="missing-demo", source_type="manual", source_value="")
        session.add(project)
        session.commit()
        session.refresh(project)

        old_scan = ScanJob(
            id="missing-scan",
            project_id=project.id,
            project=project,
            status="completed",
            source_type="uploaded_archive",
            source_value=str((settings.scan_upload_dir / "missing-scan" / "repo.zip").resolve()),
            workspace_path=str((settings.scan_workspace_dir / "missing-scan" / "source").resolve()),
            finished_at=utcnow() - timedelta(days=5),
        )
        session.add(old_scan)
        session.add(
            Report(
                scan_job_id=old_scan.id,
                report_format="json",
                path=str((settings.report_output_dir / "missing-scan" / "report.json").resolve()),
            )
        )
        session.commit()

        summary = CleanupService(session).run_cleanup()

        assert summary.total_deleted == 0
        assert summary.errors == []
    finally:
        session.close()
