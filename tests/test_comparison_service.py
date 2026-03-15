"""Tests for deterministic scan comparison behavior."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.app.models.project import Project
from backend.app.models.scan import Finding, ScanJob
from backend.app.services.comparison_service import ScanComparisonService


def test_compare_scans_returns_new_resolved_and_unchanged_groups() -> None:
    project = Project(id="project-1", name="demo", source_type="manual", source_value="")
    previous_created_at = datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
    current_created_at = previous_created_at + timedelta(hours=1)

    previous_scan = ScanJob(
        id="scan-prev",
        project_id=project.id,
        project=project,
        status="completed",
        source_type="local_path",
        source_value="/tmp/demo",
        created_at=previous_created_at,
    )
    current_scan = ScanJob(
        id="scan-current",
        project_id=project.id,
        project=project,
        status="completed",
        source_type="local_path",
        source_value="/tmp/demo",
        created_at=current_created_at,
    )

    previous_scan.findings = [
        Finding(
            id="finding-1",
            project_id=project.id,
            scan_job_id=previous_scan.id,
            title="Hardcoded secret",
            description="Secret-like literal detected.",
            severity="high",
            category="code",
            tool_name="semgrep",
            file_path="src/app.py",
            line_number=10,
            raw_payload={},
        ),
        Finding(
            id="finding-2",
            project_id=project.id,
            scan_job_id=previous_scan.id,
            title="Dependency issue",
            description="Old vulnerable dependency.",
            severity="medium",
            category="dependency:python",
            tool_name="pip-audit",
            file_path="requirements.txt",
            raw_payload={"dependency": {"name": "django", "version": "3.2.0"}},
        ),
    ]
    current_scan.findings = [
        Finding(
            id="finding-3",
            project_id=project.id,
            scan_job_id=current_scan.id,
            title="Hardcoded secret",
            description="Secret-like literal detected.",
            severity="high",
            category="code",
            tool_name="semgrep",
            file_path="src/app.py",
            line_number=10,
            raw_payload={},
        ),
        Finding(
            id="finding-4",
            project_id=project.id,
            scan_job_id=current_scan.id,
            title="Hardcoded secret",
            description="Secret-like literal detected.",
            severity="high",
            category="code",
            tool_name="semgrep",
            file_path="src/app.py",
            line_number=20,
            raw_payload={},
        ),
        Finding(
            id="finding-5",
            project_id=project.id,
            scan_job_id=current_scan.id,
            title="Critical container issue",
            description="Container package vulnerability.",
            severity="critical",
            category="dependency:node",
            tool_name="npm-audit",
            file_path="package-lock.json",
            raw_payload={"dependency": {"name": "lodash", "version": "4.17.15"}},
        ),
    ]

    comparison = ScanComparisonService(db=None).compare_scans(current_scan, previous_scan)  # type: ignore[arg-type]

    assert comparison.comparison_available is True
    assert comparison.trend == "worsened"
    assert comparison.summary["new_group_count"] == 1
    assert comparison.summary["resolved_group_count"] == 1
    assert comparison.summary["unchanged_group_count"] == 1
    assert comparison.new_groups[0].title == "Critical container issue"
    assert comparison.resolved_groups[0].title == "Dependency issue"
    assert comparison.unchanged_groups[0].title == "Hardcoded secret"
    assert comparison.unchanged_groups[0].delta_member_count == 1
    assert comparison.severity_deltas["critical"].delta == 1
    assert comparison.severity_deltas["medium"].delta == -1


def test_compare_scans_rejects_cross_project_pairs() -> None:
    previous_scan = ScanJob(
        id="scan-prev",
        project_id="project-1",
        project=Project(id="project-1", name="one", source_type="manual", source_value=""),
        status="completed",
        source_type="local_path",
        source_value="/tmp/one",
        created_at=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
    )
    current_scan = ScanJob(
        id="scan-current",
        project_id="project-2",
        project=Project(id="project-2", name="two", source_type="manual", source_value=""),
        status="completed",
        source_type="local_path",
        source_value="/tmp/two",
        created_at=datetime(2026, 3, 15, 11, 0, 0, tzinfo=timezone.utc),
    )

    with pytest.raises(ValueError, match="same project"):
        ScanComparisonService(db=None).compare_scans(current_scan, previous_scan)  # type: ignore[arg-type]
