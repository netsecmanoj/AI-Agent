"""Tests for token-authenticated API routes and webhook intake."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
from datetime import datetime, timezone
import zipfile

from fastapi.testclient import TestClient

from backend.app.core.config import get_settings
from backend.app.models.project import Project
from backend.app.models.scan import Finding
from backend.app.models.scan import ScanJob
from backend.app.scanners.base import NormalizedFinding, ToolExecutionResult
from backend.app.services.execution_service import ScanExecutionSummary


def test_api_requires_token_auth(isolated_app, monkeypatch) -> None:
    app, _, runner = isolated_app
    runner.stop()
    monkeypatch.setattr(get_settings(), "api_tokens_raw", "service-token")

    with TestClient(app) as client:
        response = client.get("/api/v1/scans/missing/status")

    assert response.status_code == 401
    assert response.json()["detail"] == "API token required."


def test_api_can_upload_archive_enqueue_and_poll_scan(
    isolated_app,
    monkeypatch,
) -> None:
    app, session_factory, runner = isolated_app
    settings = get_settings()
    monkeypatch.setattr(settings, "api_tokens_raw", "service-token")
    monkeypatch.setattr(runner, "start", lambda: None)
    monkeypatch.setattr(runner, "recover_jobs", lambda: [])

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
                        description="Detected in uploaded archive.",
                        severity="medium",
                        category="code",
                        tool_name="dummy-scanner",
                        file_path="src/app.py",
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

    monkeypatch.setattr("backend.app.services.scan_service.ScanExecutionService", DummyExecutionService)

    archive_buffer = BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("src/app.py", "print('hello')\n")
    archive_buffer.seek(0)

    headers = {"Authorization": "Bearer service-token"}
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            headers=headers,
            data={
                "project_name": "gitlab-demo",
                "source_label": "feature/test-branch",
            },
            files={"archive_file": ("repo.zip", archive_buffer.getvalue(), "application/zip")},
        )

        assert response.status_code == 202
        payload = response.json()["scan"]
        scan_id = payload["scan_id"]
        assert payload["status"] == "queued"
        assert payload["source_label"] == "feature/test-branch"

        queued = client.get(f"/api/v1/scans/{scan_id}/status", headers=headers)
        assert queued.status_code == 200
        assert queued.json()["scan"]["status"] == "queued"

        runner._process(scan_id)

        detail = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert detail.status_code == 200
        detail_payload = detail.json()["scan"]
        assert detail_payload["status"] == "completed"
        assert detail_payload["severity_counts"]["medium"] == 1
        assert detail_payload["tool_summary"]["statuses"]["dummy-scanner"] == "completed"
        assert detail_payload["policy"]["status"] == "pass"
        assert detail_payload["policy"]["should_fail_ci"] is False
        assert detail_payload["grouped_finding_count"] == 1
        assert detail_payload["grouped_findings"][0]["title"] == "Dummy finding"
        assert detail_payload["grouped_findings"][0]["affected_files"] == ["src/app.py"]

        policy = client.get(f"/api/v1/scans/{scan_id}/policy", headers=headers)
        assert policy.status_code == 200
        assert policy.json()["policy"]["status"] == "pass"

        report = client.get(f"/api/v1/scans/{scan_id}/reports/json", headers=headers)
        assert report.status_code == 200
        assert report.headers["content-type"].startswith("application/json")

        summary_report = client.get(f"/api/v1/scans/{scan_id}/reports/summary", headers=headers)
        assert summary_report.status_code == 200
        assert summary_report.headers["content-type"].startswith("application/json")
        assert summary_report.json()["common_issue_patterns"]
        assert "direct_security_findings" in summary_report.json()

    session = session_factory()
    try:
        persisted_scan = session.get(ScanJob, scan_id)
        assert persisted_scan is not None
        assert persisted_scan.status == "completed"
    finally:
        session.close()


def test_gitlab_webhook_validates_secret_and_can_queue_local_path_scan(
    isolated_app,
    monkeypatch,
    tmp_path,
) -> None:
    app, session_factory, runner = isolated_app
    settings = get_settings()
    monkeypatch.setattr(settings, "webhook_shared_secret", "gitlab-secret")
    monkeypatch.setattr(settings, "allow_api_local_path_scans", True)
    runner.stop()

    target_path = tmp_path / "repo"
    target_path.mkdir()

    with TestClient(app) as client:
        unauthorized = client.post(
            "/api/v1/webhooks/gitlab",
            json={"project_name": "hook-demo", "source_path": str(target_path)},
        )
        assert unauthorized.status_code == 401

        accepted = client.post(
            "/api/v1/webhooks/gitlab",
            headers={"X-Gitlab-Token": "gitlab-secret"},
            json={
                "project_name": "hook-demo",
                "source_path": str(target_path),
                "ref": "main",
            },
        )

    assert accepted.status_code == 202
    payload = accepted.json()
    assert payload["accepted"] is True
    assert payload["queued"] is True
    assert payload["scan"]["status"] == "queued"

    session = session_factory()
    try:
        persisted_scan = session.get(ScanJob, payload["scan"]["scan_id"])
        assert persisted_scan is not None
        assert persisted_scan.source_label == "main"
    finally:
        session.close()


def test_worker_status_api_returns_worker_snapshot(isolated_app, monkeypatch) -> None:
    app, _, runner = isolated_app
    settings = get_settings()
    monkeypatch.setattr(settings, "api_tokens_raw", "service-token")
    runner.stop()

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/worker/status",
            headers={"Authorization": "Bearer service-token"},
        )

    assert response.status_code == 200
    payload = response.json()["worker"]
    assert "running" in payload
    assert "queue_depth" in payload
    assert "storage_counts" in payload


def test_requirements_status_api_returns_tool_summary(isolated_app, monkeypatch) -> None:
    app, _, runner = isolated_app
    settings = get_settings()
    monkeypatch.setattr(settings, "api_tokens_raw", "service-token")
    monkeypatch.setattr(settings, "npm_command", "missing-npm")
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "ai_provider", "openai")
    monkeypatch.setattr(settings, "ai_model", "")
    monkeypatch.setattr(settings, "ai_base_url", "")
    monkeypatch.setattr(settings, "ai_api_key", "")
    runner.stop()
    monkeypatch.setattr(
        "backend.app.services.preflight_service.shutil.which",
        lambda command: f"/resolved/{command}" if command in {settings.semgrep_command, settings.trivy_command} else None,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/requirements/status",
            headers={"Authorization": "Bearer service-token"},
        )

    assert response.status_code == 200
    payload = response.json()["requirements"]
    assert "counts" in payload
    assert "tools" in payload
    assert "ai" in payload
    assert any(item["label"] == "Semgrep" and item["status"] == "available" for item in payload["tools"])
    assert any(item["label"] == "npm" and item["status"] == "missing" for item in payload["tools"])
    assert payload["ai"]["status"] == "missing_required_config"


def test_api_can_return_scan_comparison_summary(isolated_app, monkeypatch) -> None:
    app, session_factory, runner = isolated_app
    settings = get_settings()
    monkeypatch.setattr(settings, "api_tokens_raw", "service-token")
    runner.stop()

    session = session_factory()
    try:
        project = Project(name="compare-demo", source_type="manual", source_value="")
        session.add(project)
        session.commit()
        session.refresh(project)

        previous_scan = ScanJob(
            id="scan-prev",
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
            created_at=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        )
        current_scan = ScanJob(
            id="scan-current",
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
            created_at=datetime(2026, 3, 15, 11, 0, 0, tzinfo=timezone.utc),
        )
        session.add_all([previous_scan, current_scan])
        session.commit()

        session.add_all(
            [
                Finding(
                    project_id=project.id,
                    scan_job_id=previous_scan.id,
                    title="Old issue",
                    description="Old issue",
                    severity="medium",
                    category="code",
                    tool_name="semgrep",
                    file_path="src/app.py",
                    raw_payload={},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=current_scan.id,
                    title="Old issue",
                    description="Old issue",
                    severity="medium",
                    category="code",
                    tool_name="semgrep",
                    file_path="src/app.py",
                    raw_payload={},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=current_scan.id,
                    title="New issue",
                    description="New issue",
                    severity="high",
                    category="code",
                    tool_name="semgrep",
                    file_path="src/new.py",
                    raw_payload={},
                ),
            ]
        )
        session.commit()
    finally:
        session.close()

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/scans/scan-current/comparison?compare_to=scan-prev",
            headers={"Authorization": "Bearer service-token"},
        )

    assert response.status_code == 200
    comparison = response.json()["comparison"]
    assert comparison["comparison_available"] is True
    assert comparison["summary"]["new_group_count"] == 1
    assert comparison["summary"]["resolved_group_count"] == 0
    assert comparison["summary"]["unchanged_group_count"] == 1
    assert comparison["new_groups"][0]["title"] == "New issue"


def test_api_scan_detail_includes_framework_inventory(isolated_app, monkeypatch, tmp_path) -> None:
    app, session_factory, runner = isolated_app
    settings = get_settings()
    monkeypatch.setattr(settings, "api_tokens_raw", "service-token")
    runner.stop()

    workspace = tmp_path / "express-service"
    workspace.mkdir()
    (workspace / "package.json").write_text(
        '{"dependencies":{"express":"^4.19.0"}}',
        encoding="utf-8",
    )
    (workspace / "app.js").write_text("const express = require('express');\n", encoding="utf-8")

    session = session_factory()
    try:
        project = Project(name="express-service", source_type="local_path", source_value=str(workspace))
        session.add(project)
        session.commit()
        session.refresh(project)

        scan = ScanJob(
            id="scan-framework",
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value=str(workspace),
            workspace_path=str(workspace),
            total_findings=0,
        )
        session.add(scan)
        session.commit()
    finally:
        session.close()

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/scans/scan-framework",
            headers={"Authorization": "Bearer service-token"},
        )

    assert response.status_code == 200
    payload = response.json()["scan"]
    assert payload["frameworks"] == ["express"]
    assert payload["framework_summary"][0]["name"] == "express"


def test_api_can_return_policy_summary(isolated_app, monkeypatch) -> None:
    app, session_factory, runner = isolated_app
    settings = get_settings()
    monkeypatch.setattr(settings, "api_tokens_raw", "service-token")
    runner.stop()

    session = session_factory()
    try:
        project = Project(name="policy-demo", source_type="manual", source_value="")
        project.policy_preset = "strict"
        project.policy_warn_on_any_high_findings = False
        session.add(project)
        session.commit()
        session.refresh(project)

        previous_scan = ScanJob(
            id="scan-policy-prev",
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
            created_at=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        )
        current_scan = ScanJob(
            id="scan-policy-current",
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
            created_at=datetime(2026, 3, 15, 11, 0, 0, tzinfo=timezone.utc),
        )
        session.add_all([previous_scan, current_scan])
        session.commit()

        session.add_all(
            [
                Finding(
                    project_id=project.id,
                    scan_job_id=previous_scan.id,
                    title="Old issue",
                    description="Old issue",
                    severity="medium",
                    category="code",
                    tool_name="semgrep",
                    file_path="src/app.py",
                    raw_payload={},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=current_scan.id,
                    title="Old issue",
                    description="Old issue",
                    severity="medium",
                    category="code",
                    tool_name="semgrep",
                    file_path="src/app.py",
                    raw_payload={},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=current_scan.id,
                    title="Critical issue",
                    description="Critical issue",
                    severity="critical",
                    category="code",
                    tool_name="semgrep",
                    file_path="src/critical.py",
                    raw_payload={},
                ),
            ]
        )
        session.commit()
    finally:
        session.close()

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/scans/scan-policy-current/policy?compare_to=scan-policy-prev",
            headers={"Authorization": "Bearer service-token"},
        )

    assert response.status_code == 200
    policy = response.json()["policy"]
    assert policy["status"] == "fail"
    assert policy["should_fail_ci"] is True
    assert policy["config"]["preset"] == "strict"
    assert policy["config"]["warn_on_any_high_findings"] is False
    assert any(rule["rule_id"] == "current_severity_threshold" and rule["triggered"] for rule in policy["rules"])


def test_api_can_return_project_trend_summary(isolated_app, monkeypatch) -> None:
    app, session_factory, runner = isolated_app
    settings = get_settings()
    monkeypatch.setattr(settings, "api_tokens_raw", "service-token")
    runner.stop()

    session = session_factory()
    try:
        project = Project(name="trend-demo", source_type="manual", source_value="")
        session.add(project)
        session.commit()
        session.refresh(project)
        project_id = project.id

        first_scan = ScanJob(
            id="scan-trend-1",
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
            source_label="baseline",
            created_at=datetime(2026, 3, 15, 9, 0, 0, tzinfo=timezone.utc),
        )
        second_scan = ScanJob(
            id="scan-trend-2",
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
            source_label="candidate",
            created_at=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        )
        session.add_all([first_scan, second_scan])
        session.commit()

        session.add_all(
            [
                Finding(
                    project_id=project.id,
                    scan_job_id=first_scan.id,
                    title="Existing issue",
                    description="Existing issue",
                    severity="medium",
                    category="code",
                    tool_name="semgrep",
                    file_path="src/app.py",
                    raw_payload={},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=second_scan.id,
                    title="Existing issue",
                    description="Existing issue",
                    severity="medium",
                    category="code",
                    tool_name="semgrep",
                    file_path="src/app.py",
                    raw_payload={},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=second_scan.id,
                    title="New high issue",
                    description="New high issue",
                    severity="high",
                    category="code",
                    tool_name="semgrep",
                    file_path="src/new.py",
                    raw_payload={},
                ),
            ]
        )
        session.commit()
    finally:
        session.close()

    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/projects/{project_id}/trends",
            headers={"Authorization": "Bearer service-token"},
        )

    assert response.status_code == 200
    trend = response.json()["trend"]
    assert trend["project"]["id"] == project_id
    assert trend["effective_policy"]["source"] == "global_default"
    assert trend["total_scans"] == 2
    assert trend["comparison_points"] == 1
    assert trend["latest_policy_status"] == "fail"
    assert trend["points"][0]["comparison_available"] is False
    assert trend["points"][1]["comparison_available"] is True
    assert trend["points"][1]["new_group_count"] == 1
    assert trend["points"][1]["weighted_risk_score"] == 7
