"""Tests for optional AI enrichment behavior."""

from __future__ import annotations

from backend.app.models.project import Project
from backend.app.models.scan import Finding, ScanJob
from backend.app.services.ai_service import (
    AIEnrichmentService,
    DisabledAIProvider,
    FindingAIResult,
    OpenAICompatibleAIProvider,
    ScanAIResult,
)


def test_disabled_ai_provider_marks_scan_and_findings_disabled(isolated_app) -> None:
    _, session_factory, runner = isolated_app
    runner.stop()

    session = session_factory()
    try:
        project = Project(name="demo", source_type="manual", source_value="")
        session.add(project)
        session.commit()
        session.refresh(project)

        scan_job = ScanJob(
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
            source_label="demo",
            total_findings=1,
        )
        session.add(scan_job)
        session.commit()
        session.refresh(scan_job)

        finding = Finding(
            project_id=project.id,
            scan_job_id=scan_job.id,
            title="Potential secret",
            description="Possible credential exposure.",
            severity="high",
            category="code",
            tool_name="semgrep",
            raw_payload={},
        )
        session.add(finding)
        session.commit()
        session.refresh(scan_job)

        enriched = AIEnrichmentService(session, provider=DisabledAIProvider()).enrich_scan(scan_job)

        assert enriched.ai_status == "disabled"
        assert enriched.findings[0].ai_status == "disabled"
        assert enriched.findings[0].ai_explanation is None
    finally:
        session.close()


def test_openai_compatible_provider_parses_success_payload() -> None:
    class DummyResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"explanation":"The tool flagged an unsafe pattern.",'
                                '"remediation":"Replace the unsafe pattern."}'
                            )
                        }
                    }
                ]
            }

    class DummyClient:
        def post(self, url: str, headers: dict, json: dict) -> DummyResponse:  # noqa: A002
            assert url.endswith("/chat/completions")
            assert json["model"] == "demo-model"
            return DummyResponse()

    provider = OpenAICompatibleAIProvider(
        base_url="http://localhost:11434/v1",
        model="demo-model",
        timeout_seconds=5,
        client=DummyClient(),
    )

    result = provider.generate_finding_guidance(
        {
            "title": "Unsafe subprocess",
            "severity": "high",
            "tool_name": "semgrep",
        }
    )

    assert result.explanation == "The tool flagged an unsafe pattern."
    assert result.remediation == "Replace the unsafe pattern."


def test_ai_enrichment_gracefully_handles_provider_failure(isolated_app) -> None:
    _, session_factory, runner = isolated_app
    runner.stop()

    class FailingProvider:
        provider_name = "failing"

        def generate_finding_guidance(self, finding_context: dict) -> FindingAIResult:
            raise RuntimeError("provider unavailable")

        def generate_scan_summary(self, scan_context: dict) -> ScanAIResult:
            raise RuntimeError("provider unavailable")

    session = session_factory()
    try:
        project = Project(name="demo", source_type="manual", source_value="")
        session.add(project)
        session.commit()
        session.refresh(project)

        scan_job = ScanJob(
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
            source_label="demo",
            total_findings=1,
        )
        session.add(scan_job)
        session.commit()
        session.refresh(scan_job)

        finding = Finding(
            project_id=project.id,
            scan_job_id=scan_job.id,
            title="Potential secret",
            description="Possible credential exposure.",
            severity="high",
            category="code",
            tool_name="semgrep",
            raw_payload={},
        )
        session.add(finding)
        session.commit()
        session.refresh(scan_job)

        enriched = AIEnrichmentService(session, provider=FailingProvider()).enrich_scan(scan_job)

        assert enriched.ai_status == "failed"
        assert "provider unavailable" in (enriched.ai_error or "")
        assert enriched.findings[0].ai_status == "failed"
    finally:
        session.close()


def test_ai_scan_context_uses_grouped_finding_summary(isolated_app) -> None:
    _, session_factory, runner = isolated_app
    runner.stop()

    class CapturingProvider:
        provider_name = "capturing"

        def __init__(self) -> None:
            self.scan_context: dict | None = None

        def generate_finding_guidance(self, finding_context: dict) -> FindingAIResult:
            return FindingAIResult(
                explanation=f"Explain {finding_context['title']}",
                remediation="Apply the documented remediation.",
            )

        def generate_scan_summary(self, scan_context: dict) -> ScanAIResult:
            self.scan_context = scan_context
            return ScanAIResult(
                management_summary="Grouped summary ready.",
                top_risks="Repeated high severity issues need attention.",
                next_steps="Prioritize the repeated group first.",
            )

    provider = CapturingProvider()
    session = session_factory()
    try:
        project = Project(name="demo", source_type="manual", source_value="")
        session.add(project)
        session.commit()
        session.refresh(project)

        previous_scan = ScanJob(
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
        )
        session.add(previous_scan)
        session.commit()
        session.refresh(previous_scan)

        session.add(
            Finding(
                project_id=project.id,
                scan_job_id=previous_scan.id,
                title="Potential secret",
                description="Possible credential exposure.",
                severity="high",
                category="code",
                tool_name="semgrep",
                file_path="src/app.py",
                line_number=4,
                remediation="Move the secret into a secret manager.",
                raw_payload={},
            )
        )
        session.commit()

        scan_job = ScanJob(
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
            source_label="demo",
            total_findings=2,
        )
        session.add(scan_job)
        session.commit()
        session.refresh(scan_job)

        session.add_all(
            [
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Potential secret",
                    description="Possible credential exposure.",
                    severity="high",
                    category="code",
                    tool_name="semgrep",
                    file_path="src/app.py",
                    line_number=4,
                    remediation="Move the secret into a secret manager.",
                    raw_payload={},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Potential secret",
                    description="Possible credential exposure.",
                    severity="high",
                    category="code",
                    tool_name="semgrep",
                    file_path="src/app.py",
                    line_number=12,
                    remediation="Move the secret into a secret manager.",
                    raw_payload={},
                ),
            ]
        )
        session.commit()
        session.refresh(scan_job)

        enriched = AIEnrichmentService(session, provider=provider).enrich_scan(scan_job)

        assert enriched.ai_status == "completed"
        assert provider.scan_context is not None
        assert provider.scan_context["group_count"] == 1
        assert provider.scan_context["repeated_group_count"] == 1
        assert provider.scan_context["grouped_findings"][0]["member_count"] == 2
        assert provider.scan_context["grouped_findings"][0]["affected_files"] == ["src/app.py"]
        assert provider.scan_context["comparison_summary"] is not None
    finally:
        session.close()
