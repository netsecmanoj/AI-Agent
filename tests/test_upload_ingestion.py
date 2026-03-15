"""Tests for safe archive extraction and upload-based scan submission."""

from io import BytesIO
from pathlib import Path
import zipfile

from fastapi.testclient import TestClient

from backend.app.models.scan import Finding, ScanJob
from backend.app.scanners.base import NormalizedFinding, ToolExecutionResult
from backend.app.services.execution_service import ScanExecutionSummary
from backend.app.services.workspace_service import WorkspaceService


def test_safe_extract_zip_rejects_traversal_entry(tmp_path) -> None:
    service = WorkspaceService()
    archive_path = tmp_path / "unsafe.zip"
    destination = tmp_path / "out"
    destination.mkdir()

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../../evil.txt", "owned")

    try:
        service.safe_extract_zip(archive_path, destination)
    except ValueError as exc:
        assert "Unsafe archive entry" in str(exc)
    else:
        raise AssertionError("Expected unsafe archive extraction to fail.")

    assert not (tmp_path / "evil.txt").exists()


def test_upload_scan_submission_extracts_archive_and_persists_scan(
    isolated_app,
    create_admin_user,
    extract_csrf_token,
    monkeypatch,
) -> None:
    app, session_factory, runner = isolated_app
    create_admin_user()

    class DummyExecutionService:
        def execute(self, workspace_path: Path) -> ScanExecutionSummary:
            extracted_file = workspace_path / "src" / "app.py"
            assert extracted_file.exists()
            result = ToolExecutionResult(
                tool_name="dummy-scanner",
                status="completed",
                command="dummy scan",
                findings=[
                    NormalizedFinding(
                        title="Dummy finding",
                        description="Archive content reached the scanner boundary.",
                        severity="low",
                        category="test",
                        tool_name="dummy-scanner",
                        file_path=str(extracted_file.relative_to(workspace_path)),
                        remediation="No action required.",
                        raw_payload={"test": True},
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

    monkeypatch.setattr("backend.app.services.scan_service.ScanExecutionService", DummyExecutionService)
    monkeypatch.setattr(runner, "start", lambda: None)
    monkeypatch.setattr(runner, "recover_jobs", lambda: [])

    archive_buffer = BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("src/app.py", "print('hello')")
    archive_buffer.seek(0)

    with TestClient(app) as client:
        login_page = client.get("/login")
        login_csrf = extract_csrf_token(login_page.text)
        client.post(
            "/login",
            data={
                "username": "admin",
                "password": "Password123!",
                "csrf_token": login_csrf,
                "next": "/",
            },
            follow_redirects=False,
        )
        dashboard = client.get("/")
        scan_csrf = extract_csrf_token(dashboard.text)
        response = client.post(
            "/scans",
            data={"project_name": "uploaded-demo", "source_path": "", "csrf_token": scan_csrf},
            files={"archive_file": ("demo.zip", archive_buffer.getvalue(), "application/zip")},
            follow_redirects=False,
        )

    assert response.status_code == 303
    location = response.headers["location"]
    scan_id = location.rsplit("/", maxsplit=1)[-1]

    session = session_factory()
    try:
        scan_job = session.get(ScanJob, scan_id)
        assert scan_job is not None
        assert scan_job.source_type == "uploaded_archive"
        assert scan_job.source_filename == "demo.zip"
        assert scan_job.status == "queued"
        assert scan_job.workspace_path is not None
        assert Path(scan_job.workspace_path).joinpath("src", "app.py").exists()
    finally:
        session.close()

    runner._process(scan_id)

    session = session_factory()
    try:
        scan_job = session.get(ScanJob, scan_id)
        assert scan_job is not None
        assert scan_job.status == "completed"
        findings = session.query(Finding).filter(Finding.scan_job_id == scan_id).all()
        assert len(findings) == 1
        assert findings[0].tool_name == "dummy-scanner"
    finally:
        session.close()
