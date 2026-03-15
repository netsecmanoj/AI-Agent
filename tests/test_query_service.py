"""Unit tests for scan and finding browsing helpers."""

from datetime import datetime, timedelta, timezone

from backend.app.models.project import Project
from backend.app.models.scan import Finding, ScanJob, ToolExecution
from backend.app.services.query_service import (
    ScanQueryService,
    build_progress_message,
    build_tool_coverage_summary,
    build_ai_status_summary,
    display_scan_result,
    summarize_ai_error,
)


def test_filter_findings_applies_severity_tool_and_category_filters() -> None:
    service = ScanQueryService(db=None)  # type: ignore[arg-type]
    findings = [
        Finding(
            title="A",
            description="A",
            severity="high",
            category="dependency:python",
            tool_name="pip-audit",
            raw_payload={},
            project_id="project-1",
            scan_job_id="scan-1",
        ),
        Finding(
            title="B",
            description="B",
            severity="medium",
            category="code",
            tool_name="semgrep",
            raw_payload={},
            project_id="project-1",
            scan_job_id="scan-1",
        ),
    ]

    filtered = service.filter_findings(
        findings,
        severity="high",
        tool="pip-audit",
        category="dependency:python",
    )

    assert len(filtered) == 1
    assert filtered[0].title == "A"


def test_filter_findings_supports_human_finding_type_filter() -> None:
    service = ScanQueryService(db=None)  # type: ignore[arg-type]
    findings = [
        Finding(
            title="Undefined identifier",
            description="Undefined identifier 'ThemeConfig'.",
            severity="high",
            category="static_analysis",
            tool_name="dart-flutter-analyze",
            raw_payload={"rule_code": "undefined_identifier"},
            project_id="project-1",
            scan_job_id="scan-1",
        ),
        Finding(
            title="Android cleartext traffic is enabled",
            description="The application manifest explicitly allows cleartext network traffic.",
            severity="high",
            category="mobile_network_security",
            tool_name="flutter-mobile-config",
            raw_payload={"check": "usesCleartextTraffic"},
            project_id="project-1",
            scan_job_id="scan-1",
        ),
    ]

    filtered = service.filter_findings(findings, finding_type="security_risk")

    assert len(filtered) == 1
    assert filtered[0].title == "Android cleartext traffic is enabled"


def test_filter_findings_supports_review_mode_and_ai_filters() -> None:
    service = ScanQueryService(db=None)  # type: ignore[arg-type]
    findings = [
        Finding(
            title="Undefined identifier",
            description="Undefined identifier 'ThemeConfig'.",
            severity="high",
            category="static_analysis",
            tool_name="dart-flutter-analyze",
            raw_payload={"rule_code": "undefined_identifier"},
            ai_explanation="This usually means a missing import or stale symbol rename.",
            project_id="project-1",
            scan_job_id="scan-1",
        ),
        Finding(
            title="Android cleartext traffic is enabled",
            description="The application manifest explicitly allows cleartext network traffic.",
            severity="high",
            category="mobile_network_security",
            tool_name="flutter-mobile-config",
            raw_payload={"check": "usesCleartextTraffic"},
            project_id="project-1",
            scan_job_id="scan-1",
        ),
        Finding(
            title="pip-audit unavailable",
            description="pip-audit was skipped because it is not installed.",
            severity="medium",
            category="tooling_coverage",
            tool_name="coverage",
            raw_payload={"check": "tool-missing"},
            project_id="project-1",
            scan_job_id="scan-1",
        ),
    ]

    correctness_with_ai = service.filter_findings(findings, review_mode="correctness", ai_filter="with_ai")
    security_only = service.filter_findings(findings, review_mode="security")

    assert [finding.title for finding in correctness_with_ai] == ["Undefined identifier"]
    assert [finding.title for finding in security_only] == ["Android cleartext traffic is enabled"]


def test_build_ai_status_summary_covers_disabled_and_completed_states() -> None:
    disabled_scan = ScanJob(
        project_id="project-1",
        status="completed",
        source_type="local_path",
        source_value="/tmp/demo",
        ai_status="disabled",
    )
    disabled_summary = build_ai_status_summary(
        disabled_scan,
        {
            "status": "disabled_intentionally",
            "status_label": "Disabled",
            "provider": "disabled",
            "model": "llama3.1:8b",
            "base_url": "http://127.0.0.1:11434/v1",
            "api_key_configured": False,
            "summary_text": "AI explanations are intentionally disabled. Core scanning still works.",
            "warnings": [],
        },
    )
    assert disabled_summary["status"] == "disabled"
    assert disabled_summary["status_label"] == "Disabled"
    assert disabled_summary["active_for_scan"] is False
    assert disabled_summary["show_setup_hint"] is True
    assert "AI_ENABLED=true" in disabled_summary["setup_examples"]["ollama"]["snippet"]

    completed_scan = ScanJob(
        project_id="project-1",
        status="completed",
        source_type="local_path",
        source_value="/tmp/demo",
        ai_status="completed",
    )
    completed_summary = build_ai_status_summary(
        completed_scan,
        {
            "status": "ready",
            "status_label": "Ready",
            "provider": "ollama",
            "model": "llama3.1:8b",
            "base_url": "http://127.0.0.1:11434/v1",
            "api_key_configured": False,
            "summary_text": "AI appears configured.",
            "warnings": [],
        },
    )
    assert completed_summary["status"] == "completed"
    assert completed_summary["status_label"] == "Completed"
    assert completed_summary["active_for_scan"] is True


def test_summarize_ai_error_connection_refused_is_human_readable() -> None:
    message = summarize_ai_error("[Errno 61] Connection refused while calling http://127.0.0.1:11434/v1/chat/completions")

    assert message == (
        "AI enrichment failed because the configured AI endpoint was unreachable. "
        "Check AI_ENABLED / AI_BASE_URL / provider availability."
    )


def test_calculate_duration_seconds_uses_timestamps_when_present() -> None:
    service = ScanQueryService(db=None)  # type: ignore[arg-type]
    started_at = datetime(2026, 3, 14, 10, 0, 0, tzinfo=timezone.utc)
    finished_at = started_at + timedelta(seconds=17)
    scan_job = ScanJob(
        project_id="project-1",
        status="completed",
        source_type="local_path",
        source_value="/tmp/demo",
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=None,
    )

    assert service.calculate_duration_seconds(scan_job) == 17


def test_scan_result_language_and_tool_coverage_are_human_friendly() -> None:
    started_at = datetime(2026, 3, 14, 10, 0, 0, tzinfo=timezone.utc)
    finished_at = started_at + timedelta(seconds=17)
    scan_job = ScanJob(
        project_id="project-1",
        status="partial",
        partial=True,
        source_type="local_path",
        source_value="/tmp/demo",
        started_at=started_at,
        finished_at=finished_at,
    )
    executions = [
        ToolExecution(tool_name="semgrep", status="completed"),
        ToolExecution(tool_name="pip-audit", status="skipped", error_message="pip-audit is not installed"),
        ToolExecution(tool_name="npm-audit", status="failed", error_message="npm exited with status 1"),
    ]

    coverage = build_tool_coverage_summary(executions)

    assert display_scan_result(scan_job) == "Completed with tool issues"
    assert build_progress_message(scan_job, 17) == "Completed with tool issues in 17s."
    assert coverage["completed_count"] == 1
    assert coverage["issue_count"] == 2
    assert coverage["issues"][0]["reason"] == "pip-audit is not installed"


def test_build_scan_api_summary_includes_flutter_ecosystem_details(tmp_path) -> None:
    workspace = tmp_path / "mobile"
    workspace.mkdir()
    (workspace / "pubspec.yaml").write_text(
        "name: mobile_app\ndependencies:\n  flutter:\n    sdk: flutter\n",
        encoding="utf-8",
    )
    (workspace / "pubspec.lock").write_text("packages:\n  flutter:\n", encoding="utf-8")
    (workspace / "analysis_options.yaml").write_text("include: package:flutter_lints/flutter.yaml\n", encoding="utf-8")
    (workspace / "lib").mkdir()
    (workspace / "android").mkdir()
    (workspace / "ios").mkdir()

    project = Project(id="project-1", name="mobile", source_type="local_path", source_value="/tmp/mobile")
    scan_job = ScanJob(
        id="scan-1",
        project_id=project.id,
        project=project,
        status="completed",
        source_type="local_path",
        source_value="/tmp/mobile",
        workspace_path=str(workspace),
        total_findings=0,
        partial=False,
        ai_status="disabled",
    )

    summary = ScanQueryService(db=None).build_scan_api_summary(scan_job)  # type: ignore[arg-type]

    assert summary.ecosystems == ["dart", "flutter"]
    assert any(item["name"] == "flutter" and item["project_kind"] == "flutter_application" for item in summary.ecosystem_summary)


def test_build_scan_api_summary_includes_maven_and_composer_details(tmp_path) -> None:
    workspace = tmp_path / "polyglot"
    workspace.mkdir()
    (workspace / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><artifactId>service</artifactId></project>",
        encoding="utf-8",
    )
    (workspace / ".mvn").mkdir()
    (workspace / "composer.json").write_text('{"name":"demo/app"}', encoding="utf-8")
    (workspace / "composer.lock").write_text('{"packages":[]}', encoding="utf-8")

    project = Project(id="project-1", name="polyglot", source_type="local_path", source_value="/tmp/polyglot")
    scan_job = ScanJob(
        id="scan-2",
        project_id=project.id,
        project=project,
        status="completed",
        source_type="local_path",
        source_value="/tmp/polyglot",
        workspace_path=str(workspace),
        total_findings=0,
        partial=False,
        ai_status="disabled",
    )

    summary = ScanQueryService(db=None).build_scan_api_summary(scan_job)  # type: ignore[arg-type]

    assert summary.ecosystems == ["maven", "composer"]
    assert any(item["name"] == "maven" and item["project_kind"] == "maven_project" for item in summary.ecosystem_summary)
    assert any(item["name"] == "composer" and item["audit_ready"] for item in summary.ecosystem_summary)


def test_build_scan_api_summary_includes_go_and_dotnet_details(tmp_path) -> None:
    workspace = tmp_path / "polyglot"
    workspace.mkdir()
    (workspace / "go.mod").write_text("module example.com/service\n\ngo 1.22\n", encoding="utf-8")
    (workspace / "go.sum").write_text("github.com/example/lib h1:abcdef\n", encoding="utf-8")
    (workspace / "Demo.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
        encoding="utf-8",
    )
    (workspace / "packages.lock.json").write_text('{"version":1}', encoding="utf-8")

    project = Project(id="project-2", name="polyglot", source_type="local_path", source_value="/tmp/polyglot")
    scan_job = ScanJob(
        id="scan-3",
        project_id=project.id,
        project=project,
        status="completed",
        source_type="local_path",
        source_value="/tmp/polyglot",
        workspace_path=str(workspace),
        total_findings=0,
        partial=False,
        ai_status="disabled",
    )

    summary = ScanQueryService(db=None).build_scan_api_summary(scan_job)  # type: ignore[arg-type]

    assert summary.ecosystems == ["go", "dotnet"]
    assert any(item["name"] == "go" and item["project_kind"] == "go_module_project" for item in summary.ecosystem_summary)
    assert any(item["name"] == "dotnet" and item["project_kind"] == "aspnet_project" for item in summary.ecosystem_summary)


def test_build_scan_api_summary_includes_framework_details(tmp_path) -> None:
    workspace = tmp_path / "frameworks"
    workspace.mkdir()
    (workspace / "pom.xml").write_text(
        "<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>",
        encoding="utf-8",
    )
    (workspace / "application.properties").write_text(
        "management.endpoints.web.exposure.include=*\n",
        encoding="utf-8",
    )
    (workspace / "package.json").write_text(
        '{"dependencies":{"express":"^4.19.0"}}',
        encoding="utf-8",
    )
    (workspace / "app.js").write_text("const express = require('express');\n", encoding="utf-8")

    project = Project(id="project-4", name="frameworks", source_type="local_path", source_value="/tmp/frameworks")
    scan_job = ScanJob(
        id="scan-4",
        project_id=project.id,
        project=project,
        status="completed",
        source_type="local_path",
        source_value="/tmp/frameworks",
        workspace_path=str(workspace),
        total_findings=0,
        partial=False,
        ai_status="disabled",
    )

    summary = ScanQueryService(db=None).build_scan_api_summary(scan_job)  # type: ignore[arg-type]

    assert summary.frameworks == ["spring", "express"]
    assert any(item["name"] == "spring" and item["project_kind"] == "spring_boot_application" for item in summary.framework_summary)
    assert any(item["name"] == "express" and "express" in item["markers"] for item in summary.framework_summary)


def test_grouped_findings_include_intelligence_fields(tmp_path) -> None:
    workspace = tmp_path / "mobile"
    workspace.mkdir()
    (workspace / "pubspec.yaml").write_text(
        "name: mobile_app\ndependencies:\n  flutter:\n    sdk: flutter\n",
        encoding="utf-8",
    )
    (workspace / "pubspec.lock").write_text("packages:\n  flutter:\n", encoding="utf-8")
    (workspace / "android").mkdir()
    (workspace / "ios").mkdir()

    project = Project(id="project-9", name="mobile", source_type="local_path", source_value="/tmp/mobile")
    scan_job = ScanJob(
        id="scan-9",
        project_id=project.id,
        project=project,
        status="completed",
        source_type="local_path",
        source_value="/tmp/mobile",
        workspace_path=str(workspace),
        total_findings=1,
        partial=False,
        ai_status="disabled",
    )
    scan_job.findings = [
        Finding(
            id="finding-1",
            project_id=project.id,
            scan_job_id=scan_job.id,
            title="Android cleartext traffic is enabled",
            description="The application manifest explicitly allows cleartext network traffic.",
            severity="high",
            category="mobile_network_security",
            tool_name="flutter-mobile-config",
            file_path="android/app/src/main/AndroidManifest.xml",
            raw_payload={"platform": "android", "check": "usesCleartextTraffic"},
        )
    ]

    summary = ScanQueryService(db=None).build_scan_api_summary(scan_job)  # type: ignore[arg-type]

    assert summary.grouped_findings[0].finding_type == "security_risk"
    assert summary.grouped_findings[0].security_relevance == "direct"
    assert summary.grouped_findings[0].impact_summary == "security_exposure"
    assert summary.grouped_findings[0].reference_url is not None


def test_sort_grouped_findings_prioritizes_direct_security_before_correctness_noise() -> None:
    service = ScanQueryService(db=None)  # type: ignore[arg-type]
    groups = [
        {
            "group_key": "code-1",
            "title": "Undefined identifier",
            "severity": "high",
            "finding_type": "code_correctness",
            "security_relevance": "none",
            "impact_summary": "build_failure",
            "member_count": 300,
        },
        {
            "group_key": "security-1",
            "title": "Android cleartext traffic is enabled",
            "severity": "high",
            "finding_type": "security_risk",
            "security_relevance": "direct",
            "impact_summary": "security_exposure",
            "member_count": 1,
        },
    ]

    sorted_groups = service._sort_grouped_findings(groups)

    assert sorted_groups[0]["title"] == "Android cleartext traffic is enabled"


def test_apply_triage_drilldown_supports_pattern_and_hotspot_filters() -> None:
    service = ScanQueryService(db=None)  # type: ignore[arg-type]
    findings = [
        Finding(
            title="Undefined identifier",
            description="Undefined identifier 'ThemeConfig'.",
            severity="high",
            category="static_analysis",
            tool_name="dart-flutter-analyze",
            file_path="lib/screens/home.dart",
            raw_payload={"rule_code": "undefined_identifier"},
            project_id="project-1",
            scan_job_id="scan-1",
        ),
        Finding(
            title="Undefined identifier",
            description="Undefined identifier 'ThemeConfig'.",
            severity="high",
            category="static_analysis",
            tool_name="dart-flutter-analyze",
            file_path="lib/screens/details.dart",
            raw_payload={"rule_code": "undefined_identifier"},
            project_id="project-1",
            scan_job_id="scan-1",
        ),
        Finding(
            title="Android cleartext traffic is enabled",
            description="The application manifest explicitly allows cleartext network traffic.",
            severity="high",
            category="mobile_network_security",
            tool_name="flutter-mobile-config",
            file_path="android/app/src/main/AndroidManifest.xml",
            raw_payload={"check": "usesCleartextTraffic"},
            project_id="project-1",
            scan_job_id="scan-1",
        ),
    ]

    pattern_filtered = service._apply_triage_drilldown(
        findings,
        pattern_key="dart_diagnostic:undefined_identifier",
        hotspot_file=None,
        hotspot_module=None,
    )
    hotspot_filtered = service._apply_triage_drilldown(
        findings,
        pattern_key=None,
        hotspot_file="lib/screens/home.dart",
        hotspot_module=None,
    )
    module_filtered = service._apply_triage_drilldown(
        findings,
        pattern_key=None,
        hotspot_file=None,
        hotspot_module="lib/screens",
    )

    assert len(pattern_filtered) == 2
    assert all(finding.tool_name == "dart-flutter-analyze" for finding in pattern_filtered)
    assert len(hotspot_filtered) == 1
    assert hotspot_filtered[0].file_path == "lib/screens/home.dart"
    assert len(module_filtered) == 2
