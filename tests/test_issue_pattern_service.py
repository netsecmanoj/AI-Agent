"""Tests for remediation-oriented issue pattern clustering."""

from backend.app.models.scan import Finding
from backend.app.services.finding_intelligence_service import FindingIntelligenceService
from backend.app.services.grouping_service import FindingGroupingService
from backend.app.services.issue_pattern_service import IssuePatternService


def test_clusters_repeated_dart_analyzer_findings_into_one_pattern() -> None:
    findings = [
        Finding(
            id="finding-1",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Undefined identifier",
            description="Undefined identifier 'AppTheme'.",
            severity="high",
            category="static_analysis",
            tool_name="dart-flutter-analyze",
            file_path="lib/screens/home.dart",
            raw_payload={"rule_code": "undefined_identifier"},
        ),
        Finding(
            id="finding-2",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Undefined identifier",
            description="Undefined identifier 'AppTheme'.",
            severity="high",
            category="static_analysis",
            tool_name="dart-flutter-analyze",
            file_path="lib/screens/details.dart",
            raw_payload={"rule_code": "undefined_identifier"},
        ),
        Finding(
            id="finding-3",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Undefined identifier",
            description="Undefined identifier 'AppTheme'.",
            severity="high",
            category="static_analysis",
            tool_name="dart-flutter-analyze",
            file_path="lib/widgets/card.dart",
            raw_payload={"rule_code": "undefined_identifier"},
        ),
    ]

    intelligence_service = FindingIntelligenceService()
    grouped_findings = [
        intelligence_service.enrich_group(group.as_dict())
        for group in FindingGroupingService().group(findings)
    ]
    summary = IssuePatternService().build_summary(findings, grouped_findings=grouped_findings)

    assert summary["common_patterns"][0]["pattern_key"] == "dart_diagnostic:undefined_identifier"
    assert summary["common_patterns"][0]["total_occurrence_count"] == 3
    assert summary["common_patterns"][0]["grouped_finding_count"] == 3
    assert summary["common_patterns"][0]["files_affected_count"] == 3
    assert "shared import" in summary["common_patterns"][0]["fix_one_remove_many_hint"]


def test_rare_but_important_separates_low_count_direct_security_findings() -> None:
    findings = [
        Finding(
            id="finding-1",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Android cleartext traffic is enabled",
            description="The application manifest explicitly allows cleartext network traffic.",
            severity="high",
            category="mobile_network_security",
            tool_name="flutter-mobile-config",
            file_path="android/app/src/main/AndroidManifest.xml",
            raw_payload={"check": "usesCleartextTraffic"},
        ),
        Finding(
            id="finding-2",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Undefined identifier",
            description="Undefined identifier 'AppTheme'.",
            severity="high",
            category="static_analysis",
            tool_name="dart-flutter-analyze",
            file_path="lib/main.dart",
            raw_payload={"rule_code": "undefined_identifier"},
        ),
    ]

    intelligence_service = FindingIntelligenceService()
    grouped_findings = [
        intelligence_service.enrich_group(group.as_dict())
        for group in FindingGroupingService().group(findings)
    ]
    summary = IssuePatternService().build_summary(findings, grouped_findings=grouped_findings)

    assert len(summary["rare_but_important"]) == 1
    assert summary["rare_but_important"][0]["title"] == "Android cleartext traffic is enabled"
    assert summary["rare_but_important"][0]["security_relevance"] == "direct"


def test_hotspots_summarize_files_and_modules() -> None:
    findings = [
        Finding(
            id="finding-1",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Undefined identifier",
            description="Undefined identifier 'AppTheme'.",
            severity="high",
            category="static_analysis",
            tool_name="dart-flutter-analyze",
            file_path="lib/screens/home.dart",
            raw_payload={"rule_code": "undefined_identifier"},
        ),
        Finding(
            id="finding-2",
            project_id="project-1",
            scan_job_id="scan-1",
            title="Undefined getter",
            description="Undefined getter 'colors'.",
            severity="high",
            category="static_analysis",
            tool_name="dart-flutter-analyze",
            file_path="lib/screens/home.dart",
            raw_payload={"rule_code": "undefined_getter"},
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
            raw_payload={"check": "usesCleartextTraffic"},
        ),
    ]

    summary = IssuePatternService().build_summary(findings)

    assert summary["hotspots"]["files"][0]["path"] == "lib/screens/home.dart"
    assert summary["hotspots"]["files"][0]["count"] == 2
    assert summary["hotspots"]["modules"][0]["path"] == "lib/screens"
    assert summary["hotspots"]["modules"][0]["count"] == 2


def test_pattern_and_hotspot_matching_helpers_are_deterministic() -> None:
    finding = Finding(
        id="finding-1",
        project_id="project-1",
        scan_job_id="scan-1",
        title="Undefined identifier",
        description="Undefined identifier 'ThemeConfig'.",
        severity="high",
        category="static_analysis",
        tool_name="dart-flutter-analyze",
        file_path="lib/screens/home.dart",
        raw_payload={"rule_code": "undefined_identifier"},
    )

    service = IssuePatternService()
    pattern_key, _ = service.pattern_signature(finding)

    assert service.matches_pattern(finding, pattern_key) is True
    assert service.matches_hotspot_file(finding, "lib/screens/home.dart") is True
    assert service.matches_hotspot_module(finding, "lib/screens") is True
