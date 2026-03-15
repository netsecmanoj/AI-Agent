"""Tests for enriched report context generation."""

from datetime import datetime, timedelta, timezone
import json

from backend.app.models.project import Project
from backend.app.models.scan import Finding, ScanJob, ToolExecution
from backend.app.services.report_service import ReportService, build_scan_context


def test_build_scan_context_includes_grouped_and_metadata_fields(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "requirements.txt").write_text("django==3.2.0\n", encoding="utf-8")
    (workspace / "package.json").write_text(
        '{"name":"frontend","dependencies":{"express":"^4.19.0"}}',
        encoding="utf-8",
    )
    (workspace / "package-lock.json").write_text('{"name":"frontend","lockfileVersion":3}', encoding="utf-8")
    (workspace / "app.js").write_text(
        "const express = require('express');\napp.set('trust proxy', true);\n",
        encoding="utf-8",
    )
    (workspace / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><artifactId>demo</artifactId><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>",
        encoding="utf-8",
    )
    (workspace / ".mvn").mkdir()
    (workspace / "application.properties").write_text(
        "management.endpoints.web.exposure.include=*\n",
        encoding="utf-8",
    )
    (workspace / "composer.json").write_text(
        '{"name":"demo/app","require":{"laravel/framework":"^11.0"}}',
        encoding="utf-8",
    )
    (workspace / "composer.lock").write_text('{"packages":[]}', encoding="utf-8")
    (workspace / "artisan").write_text("#!/usr/bin/env php\n", encoding="utf-8")
    (workspace / "bootstrap").mkdir()
    (workspace / "bootstrap" / "app.php").write_text("<?php\n", encoding="utf-8")
    (workspace / ".env.example").write_text("APP_DEBUG=true\n", encoding="utf-8")
    (workspace / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n", encoding="utf-8")
    (workspace / "go.sum").write_text("github.com/example/lib h1:abcdef\n", encoding="utf-8")
    (workspace / "Demo.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
        encoding="utf-8",
    )
    (workspace / "packages.lock.json").write_text('{"version":1}', encoding="utf-8")
    (workspace / "pubspec.yaml").write_text(
        "name: mobile_app\ndependencies:\n  flutter:\n    sdk: flutter\n",
        encoding="utf-8",
    )
    (workspace / "pubspec.lock").write_text("packages:\n  flutter:\n", encoding="utf-8")
    (workspace / "analysis_options.yaml").write_text("include: package:flutter_lints/flutter.yaml\n", encoding="utf-8")
    (workspace / "lib").mkdir()
    (workspace / "lib" / "main.dart").write_text(
        'const String apiKey = "supersecret12345";\n',
        encoding="utf-8",
    )
    (workspace / "android").mkdir()
    (workspace / "ios").mkdir()

    started_at = datetime(2026, 3, 14, 10, 0, 0, tzinfo=timezone.utc)
    finished_at = started_at + timedelta(seconds=42)
    project = Project(name="demo", source_type="local_path", source_value="/tmp/demo")
    project.policy_preset = "balanced"
    project.policy_warn_on_any_high_findings = False
    scan_job = ScanJob(
        id="scan-1",
        project_id="project-1",
        project=project,
        status="partial",
        partial=True,
        source_type="local_path",
        source_value="/tmp/demo",
        source_label="demo",
        workspace_path=str(workspace),
        total_findings=2,
        ai_status="completed",
        ai_summary="Management summary text.",
        ai_top_risks="Top risks text.",
        ai_next_steps="Next steps text.",
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=42,
    )
    scan_job.findings = [
        Finding(
            id="finding-1",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Dependency issue",
            description="Dependency issue",
            severity="high",
            category="dependency:python",
            tool_name="pip-audit",
            file_path="requirements.txt",
            ai_status="completed",
            ai_explanation="AI explains the dependency issue.",
            ai_remediation="Upgrade the dependency.",
            raw_payload={},
            created_at=started_at,
        ),
        Finding(
            id="finding-2",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Code issue",
            description="Code issue",
            severity="medium",
            category="code",
            tool_name="semgrep",
            ai_status="failed",
            ai_error="AI provider timeout.",
            raw_payload={},
            created_at=started_at,
        ),
        Finding(
            id="finding-3",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Android cleartext traffic is enabled",
            description="The application manifest explicitly allows cleartext network traffic.",
            severity="high",
            category="mobile_network_security",
            tool_name="flutter-mobile-config",
            file_path="android/app/src/main/AndroidManifest.xml",
            remediation="Disable cleartext traffic in production.",
            raw_payload={"platform": "android", "check": "usesCleartextTraffic"},
            created_at=started_at,
        ),
    ]
    scan_job.tool_executions = [
        ToolExecution(
            id="tool-1",
            scan_job_id="scan-1",
            tool_name="semgrep",
            status="completed",
            command="semgrep scan",
        ),
        ToolExecution(
            id="tool-2",
            scan_job_id="scan-1",
            tool_name="pip-audit",
            status="skipped",
            command="pip-audit -f json -r requirements.txt",
            error_message="pip-audit is not installed",
        ),
        ToolExecution(
            id="tool-3",
            scan_job_id="scan-1",
            tool_name="dart-pub-outdated",
            status="completed",
            command="flutter pub outdated --json --no-up-to-date",
        ),
        ToolExecution(
            id="tool-4",
            scan_job_id="scan-1",
            tool_name="maven-pom-review",
            status="completed",
            command="manifest-review:pom.xml",
        ),
        ToolExecution(
            id="tool-5",
            scan_job_id="scan-1",
            tool_name="composer-review",
            status="completed",
            command="manifest-review:composer.json,composer.lock",
        ),
        ToolExecution(
            id="tool-6",
            scan_job_id="scan-1",
            tool_name="go-mod-review",
            status="completed",
            command="manifest-review:go.mod",
        ),
        ToolExecution(
            id="tool-7",
            scan_job_id="scan-1",
            tool_name="dotnet-project-review",
            status="completed",
            command="manifest-review:csproj,Directory.Packages.props",
        ),
    ]

    context = build_scan_context(
        scan_job,
        comparison={
            "comparison_available": True,
            "previous_scan_id": "scan-0",
            "trend": "improved",
            "summary": {
                "new_group_count": 0,
                "resolved_group_count": 1,
                "unchanged_group_count": 1,
            },
            "severity_deltas": {
                "high": {"previous": 2, "current": 1, "delta": -1},
            },
        },
    )

    assert context["source_label"] == "demo"
    assert context["result_label"] == "Completed with tool issues"
    assert context["progress_message"] == "Completed with tool issues in 42s."
    assert context["duration_seconds"] == 42
    assert context["duration_text"] == "42s"
    assert context["tool_summary"]["count"] == 7
    assert context["tool_coverage"]["issue_count"] == 1
    assert context["finding_breakdown"]["dependency"][0]["tool_name"] == "pip-audit"
    assert {finding["tool_name"] for finding in context["finding_breakdown"]["code_and_config"]} == {
        "semgrep",
        "flutter-mobile-config",
    }
    assert context["ecosystems"] == ["python", "node", "dart", "flutter", "maven", "composer", "go", "dotnet"]
    assert context["frameworks"] == ["spring", "laravel", "express", "flutter_app"]
    assert any(item["name"] == "node" and item["audit_ready"] for item in context["ecosystem_summary"])
    assert any(item["name"] == "flutter" and item["project_kind"] == "flutter_application" for item in context["ecosystem_summary"])
    assert any(item["name"] == "maven" and item["project_kind"] == "spring_maven_project" for item in context["ecosystem_summary"])
    assert any(item["name"] == "composer" and item["audit_ready"] for item in context["ecosystem_summary"])
    assert any(item["name"] == "go" and item["project_kind"] == "go_module_project" for item in context["ecosystem_summary"])
    assert any(item["name"] == "dotnet" and item["audit_ready"] for item in context["ecosystem_summary"])
    assert any(item["name"] == "spring" and item["project_kind"] == "spring_boot_application" for item in context["framework_summary"])
    assert any(item["name"] == "laravel" and "artisan" in item["markers"] for item in context["framework_summary"])
    assert any(item["name"] == "express" and "express" in item["markers"] for item in context["framework_summary"])
    assert any(item["name"] == "flutter_app" and item["project_kind"] == "flutter_application" for item in context["framework_summary"])
    assert context["findings_overview"]["leading_tool_name"] == "pip-audit"
    assert context["top_priority_groups"][0]["severity"] == "high"
    assert context["ai_summary_block"]["status"] == "completed"
    assert context["ai_summary_block"]["management_summary"] == "Management summary text."
    assert context["ai_status_summary"]["status"] == "completed"
    assert context["ai_status_summary"]["status_label"] == "Completed"
    assert "AI_ENABLED=true" in context["ai_status_summary"]["setup_examples"]["ollama"]["snippet"]
    assert context["findings"][0]["ai_explanation"] == "AI explains the dependency issue."
    assert context["findings"][1]["ai_error"] == "AI provider timeout."
    assert context["findings"][1]["ai_error_summary"] == (
        "AI enrichment failed because the configured AI endpoint timed out. "
        "Check AI_BASE_URL / provider availability / AI_TIMEOUT_SECONDS."
    )
    assert context["grouped_finding_summary"]["group_count"] == 3
    assert context["triage_summary"]["common_patterns"]
    assert context["triage_summary"]["hotspots"]["files"]
    assert context["triage_summary"]["common_patterns"][0]["anchor_id"].startswith("pattern-")
    assert context["remediation_summary"]["common_issue_patterns"]
    assert context["remediation_summary"]["hotspot_files"]
    assert context["remediation_summary"]["direct_security_findings"]
    dependency_group = next(group for group in context["grouped_findings"] if group["title"] == "Dependency issue")
    assert dependency_group["description"] == "Dependency issue"
    assert dependency_group["affected_files"] == ["requirements.txt"]
    assert dependency_group["finding_type"] == "dependency_hygiene"
    assert dependency_group["security_relevance"] == "indirect"
    assert dependency_group["recommended_action"]
    assert context["comparison"]["trend"] == "improved"
    assert context["policy"]["status"] == "warn"
    assert context["policy"]["should_fail_ci"] is False
    assert context["policy"]["config"]["preset"] == "balanced"
    assert context["policy"]["config"]["warn_on_any_high_findings"] is False
    assert context["project"]["effective_policy"]["preset"] == "balanced"
    assert context["dependency_tool_summary"]["count"] == 6
    security_group = next(
        group for group in context["grouped_findings"] if group["title"] == "Android cleartext traffic is enabled"
    )
    assert security_group["finding_type"] == "security_risk"
    assert security_group["security_relevance"] == "direct"
    assert security_group["reference_url"] == "https://developer.android.com/privacy-and-security/risks/cleartext-communications"
    assert security_group["anchor_id"].startswith("group-")
    assert context["triage_summary"]["rare_but_important"][0]["title"] == "Android cleartext traffic is enabled"
    assert context["remediation_summary"]["comparison_summary"]["trend"] == "improved"
    assert context["remediation_summary"]["comparison_summary"]["resolved_group_count"] == 1


def test_generate_reports_avoids_dumping_raw_ai_connection_errors_in_html(tmp_path, monkeypatch) -> None:
    started_at = datetime(2026, 3, 14, 10, 0, 0, tzinfo=timezone.utc)
    project = Project(name="demo", source_type="local_path", source_value="/tmp/demo")
    raw_ai_error = "[Errno 61] Connection refused while calling http://127.0.0.1:11434/v1/chat/completions"
    scan_job = ScanJob(
        id="scan-report-ai",
        project_id="project-1",
        project=project,
        status="completed",
        source_type="local_path",
        source_value="/tmp/demo",
        total_findings=1,
        ai_status="failed",
        ai_error=raw_ai_error,
        started_at=started_at,
        finished_at=started_at + timedelta(seconds=8),
        duration_seconds=8,
    )
    scan_job.findings = [
        Finding(
            id="finding-1",
            project_id="project-1",
            scan_job_id="scan-report-ai",
            title="Code issue",
            description="Code issue",
            severity="medium",
            category="code",
            tool_name="semgrep",
            ai_status="failed",
            ai_error=raw_ai_error,
            raw_payload={},
            created_at=started_at,
        )
    ]
    scan_job.tool_executions = [
        ToolExecution(
            id="tool-1",
            scan_job_id="scan-report-ai",
            tool_name="semgrep",
            status="completed",
            command="semgrep scan",
        )
    ]

    monkeypatch.setattr("backend.app.services.report_service.settings.report_output_dir_name", str(tmp_path))
    report_service = ReportService()
    reports = report_service.generate_reports(scan_job, comparison={"comparison_available": False, "message": "No comparison."})

    html_report = next(report for report in reports if report.report_format == "html")
    json_report = next(report for report in reports if report.report_format == "json")
    html_content = (tmp_path / scan_job.id / "report.html").read_text(encoding="utf-8")
    json_payload = json.loads((tmp_path / scan_job.id / "report.json").read_text(encoding="utf-8"))

    assert html_report.path.endswith("report.html")
    assert json_report.path.endswith("report.json")
    assert "AI enrichment failed because the configured AI endpoint was unreachable." in html_content
    assert "[Errno 61] Connection refused" not in html_content
    assert json_payload["ai_error"] == raw_ai_error
