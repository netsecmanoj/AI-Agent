"""Tests for deterministic project-level trend aggregation."""

from __future__ import annotations

from datetime import datetime, timezone

from backend.app.models.project import Project
from backend.app.models.scan import Finding, ScanJob
from backend.app.services.trend_service import ProjectTrendService


def test_project_trend_aggregates_risk_policy_and_comparison_counts(isolated_app) -> None:
    _, session_factory, runner = isolated_app
    runner.stop()

    session = session_factory()
    try:
        project = Project(id="project-trend", name="trend-demo", source_type="manual", source_value="")
        session.add(project)
        session.commit()
        session.refresh(project)

        scan_one = _build_scan(project, "scan-1", datetime(2026, 3, 15, 9, 0, 0, tzinfo=timezone.utc))
        scan_two = _build_scan(project, "scan-2", datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc))
        scan_three = _build_scan(project, "scan-3", datetime(2026, 3, 15, 11, 0, 0, tzinfo=timezone.utc))
        session.add_all([scan_one, scan_two, scan_three])
        session.commit()

        session.add_all(
            [
                _finding(project.id, scan_one.id, "Existing issue", "medium", "src/app.py"),
                _finding(project.id, scan_two.id, "Existing issue", "medium", "src/app.py"),
                _finding(project.id, scan_two.id, "New high issue", "high", "src/new.py"),
                _finding(project.id, scan_three.id, "Existing issue", "medium", "src/app.py"),
            ]
        )
        session.commit()

        trend = ProjectTrendService(session).build_project_trend(project.id)
    finally:
        session.close()

    assert trend is not None
    assert trend.total_scans == 3
    assert trend.comparison_points == 2
    assert trend.latest_weighted_risk_score == 3
    assert trend.latest_policy_status == "pass"
    assert trend.policy_counts["pass"] == 2
    assert trend.policy_counts["fail"] == 1
    assert trend.points[0].comparison_available is False
    assert trend.points[1].weighted_risk_score == 7
    assert trend.points[1].policy_status == "fail"
    assert trend.points[1].new_group_count == 1
    assert trend.points[1].unchanged_group_count == 1
    assert trend.points[1].weighted_risk_delta == 4
    assert trend.points[2].resolved_group_count == 1
    assert trend.points[2].unchanged_group_count == 1
    assert trend.points[2].weighted_risk_delta == -4


def test_project_trend_handles_zero_and_single_scan_gracefully(isolated_app) -> None:
    _, session_factory, runner = isolated_app
    runner.stop()

    session = session_factory()
    try:
        empty_project = Project(id="project-empty", name="empty-demo", source_type="manual", source_value="")
        single_project = Project(id="project-single", name="single-demo", source_type="manual", source_value="")
        session.add_all([empty_project, single_project])
        session.commit()

        single_scan = _build_scan(single_project, "scan-single", datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc))
        session.add(single_scan)
        session.commit()
        session.add(_finding(single_project.id, single_scan.id, "Solo issue", "low", "README.md"))
        session.commit()

        service = ProjectTrendService(session)
        empty_trend = service.build_project_trend(empty_project.id)
        single_trend = service.build_project_trend(single_project.id)
    finally:
        session.close()

    assert empty_trend is not None
    assert empty_trend.total_scans == 0
    assert empty_trend.points == []
    assert "no recorded scans" in (empty_trend.message or "").lower()

    assert single_trend is not None
    assert single_trend.total_scans == 1
    assert single_trend.comparison_points == 0
    assert single_trend.points[0].comparison_available is False
    assert "after a second scan" in (single_trend.message or "").lower()


def _build_scan(project: Project, scan_id: str, created_at: datetime) -> ScanJob:
    return ScanJob(
        id=scan_id,
        project_id=project.id,
        project=project,
        status="completed",
        source_type="local_path",
        source_value="/tmp/demo",
        source_label=scan_id,
        created_at=created_at,
        total_findings=0,
        partial=False,
    )


def _finding(project_id: str, scan_job_id: str, title: str, severity: str, file_path: str) -> Finding:
    return Finding(
        project_id=project_id,
        scan_job_id=scan_job_id,
        title=title,
        description=title,
        severity=severity,
        category="code",
        tool_name="semgrep",
        file_path=file_path,
        raw_payload={},
    )
