"""Tests for derived finding classification and explanation helpers."""

from backend.app.models.scan import Finding
from backend.app.services.finding_intelligence_service import FindingIntelligenceService


def test_flutter_analyzer_issue_is_classified_as_correctness_not_direct_security() -> None:
    finding = Finding(
        title="undefined_identifier in lib/main.dart",
        description="Undefined name 'foo'",
        severity="high",
        category="static_analysis",
        tool_name="dart-flutter-analyze",
        file_path="lib/main.dart",
        raw_payload={"rule_code": "undefined_identifier"},
        project_id="project-1",
        scan_job_id="scan-1",
    )

    enriched = FindingIntelligenceService().enrich_finding(finding)

    assert enriched["finding_type"] == "code_correctness"
    assert enriched["security_relevance"] == "none"
    assert enriched["impact_summary"] == "build_failure"
    assert "does not exist" in enriched["plain_explanation"]
    assert enriched["reference_url"] == "https://dart.dev/tools/diagnostics/undefined_identifier"


def test_cleartext_mobile_issue_is_classified_as_direct_security_risk() -> None:
    finding = Finding(
        title="Android cleartext traffic is enabled",
        description="The application manifest explicitly allows cleartext network traffic.",
        severity="high",
        category="mobile_network_security",
        tool_name="flutter-mobile-config",
        file_path="android/app/src/main/AndroidManifest.xml",
        raw_payload={"platform": "android", "check": "usesCleartextTraffic"},
        project_id="project-1",
        scan_job_id="scan-1",
    )

    enriched = FindingIntelligenceService().enrich_finding(finding)

    assert enriched["finding_type"] == "security_risk"
    assert enriched["security_relevance"] == "direct"
    assert enriched["impact_summary"] == "security_exposure"
    assert "network traffic" in enriched["plain_explanation"]
    assert "unencrypted" in enriched["why_flagged"].lower()
    assert enriched["reference_type"] == "platform_docs"


def test_dependency_hygiene_finding_gets_public_reference_when_available() -> None:
    finding = Finding(
        title="http is behind the latest available release",
        description="http is currently at 0.13.0; latest available is 1.2.0.",
        severity="low",
        category="dependency_outdated",
        tool_name="dart-pub-outdated",
        file_path="pubspec.lock",
        raw_payload={"dependency": {"name": "http", "version": "0.13.0"}},
        project_id="project-1",
        scan_job_id="scan-1",
    )

    enriched = FindingIntelligenceService().enrich_finding(finding)

    assert enriched["finding_type"] == "dependency_hygiene"
    assert enriched["security_relevance"] == "indirect"
    assert enriched["reference_url"] == "https://dart.dev/tools/pub/cmd/pub-outdated"
