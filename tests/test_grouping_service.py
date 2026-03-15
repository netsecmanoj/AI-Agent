"""Tests for deterministic finding grouping."""

from __future__ import annotations

from datetime import datetime, timezone

from backend.app.models.scan import Finding
from backend.app.services.grouping_service import FindingGroupingService


def test_grouping_service_collapses_repeated_code_findings() -> None:
    created_at = datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
    findings = [
        Finding(
            id="finding-1",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Hardcoded secret",
            description="Secret-like literal detected.",
            severity="high",
            category="code",
            tool_name="semgrep",
            file_path="src/app.py",
            line_number=12,
            remediation="Move the secret into a secret manager.",
            raw_payload={},
            created_at=created_at,
        ),
        Finding(
            id="finding-2",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Hardcoded secret",
            description="Secret-like literal detected.",
            severity="high",
            category="code",
            tool_name="semgrep",
            file_path="src/app.py",
            line_number=30,
            remediation="Move the secret into a secret manager.",
            raw_payload={},
            created_at=created_at,
        ),
        Finding(
            id="finding-3",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Outdated lodash advisory",
            description="Dependency vulnerability detected in lodash.",
            severity="medium",
            category="dependency:node",
            tool_name="npm-audit",
            file_path="package-lock.json",
            remediation="Upgrade lodash to 4.17.21",
            raw_payload={"dependency": {"name": "lodash", "version": "4.17.15"}},
            created_at=created_at,
        ),
    ]

    groups = FindingGroupingService().group(findings)

    assert len(groups) == 2
    repeated_group = groups[0]
    assert repeated_group.title == "Hardcoded secret"
    assert repeated_group.member_count == 2
    assert repeated_group.affected_files == ["src/app.py"]
    assert repeated_group.remediation == "Move the secret into a secret manager."
    assert repeated_group.sample_members[0]["line_number"] == 12


def test_grouping_service_uses_dependency_name_in_group_key() -> None:
    created_at = datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
    findings = [
        Finding(
            id="finding-1",
            project_id="project-1",
            scan_job_id="scan-1",
            title="GHSA-advisory",
            description="Dependency vulnerability detected.",
            severity="high",
            category="dependency:node",
            tool_name="npm-audit",
            file_path="package-lock.json",
            raw_payload={"dependency": {"name": "lodash", "version": "4.17.15"}},
            created_at=created_at,
        ),
        Finding(
            id="finding-2",
            project_id="project-1",
            scan_job_id="scan-1",
            title="GHSA-advisory",
            description="Dependency vulnerability detected.",
            severity="high",
            category="dependency:node",
            tool_name="npm-audit",
            file_path="package-lock.json",
            raw_payload={"dependency": {"name": "minimist", "version": "0.0.8"}},
            created_at=created_at,
        ),
    ]

    groups = FindingGroupingService().group(findings)

    assert len(groups) == 2
    assert {group.dependency_name for group in groups} == {"lodash", "minimist"}
