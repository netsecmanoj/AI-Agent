"""Optional AI enrichment services for findings and scan summaries."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Protocol

import httpx
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.models.scan import Finding, ScanJob
from backend.app.services.comparison_service import ScanComparisonService
from backend.app.services.grouping_service import FindingGroupingService

settings = get_settings()


@dataclass(slots=True)
class FindingAIResult:
    """AI-generated explanation and remediation for one finding."""

    explanation: str
    remediation: str


@dataclass(slots=True)
class ScanAIResult:
    """AI-generated management summary for one scan."""

    management_summary: str
    top_risks: str
    next_steps: str


class AIProvider(Protocol):
    """Protocol for pluggable AI providers."""

    provider_name: str

    def generate_finding_guidance(self, finding_context: dict[str, Any]) -> FindingAIResult:
        """Generate an explanation and remediation for one finding."""

    def generate_scan_summary(self, scan_context: dict[str, Any]) -> ScanAIResult:
        """Generate a management summary for one scan."""


class DisabledAIProvider:
    """Explicit no-op provider used when AI is turned off."""

    provider_name = "disabled"

    def generate_finding_guidance(self, finding_context: dict[str, Any]) -> FindingAIResult:
        raise RuntimeError("AI provider is disabled")

    def generate_scan_summary(self, scan_context: dict[str, Any]) -> ScanAIResult:
        raise RuntimeError("AI provider is disabled")


class OpenAICompatibleAIProvider:
    """Provider for OpenAI-compatible chat completion APIs, including local endpoints."""

    provider_name = "openai_compatible"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        timeout_seconds: int,
        api_key: str = "",
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=timeout_seconds)

    def generate_finding_guidance(self, finding_context: dict[str, Any]) -> FindingAIResult:
        """Generate AI guidance for one finding."""
        schema_hint = {
            "explanation": "string",
            "remediation": "string",
        }
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a security engineering assistant. "
                    "Return concise JSON only. Avoid markdown. "
                    "Do not include secrets or raw code."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Explain this security finding for a developer and propose a remediation. "
                    f"Return JSON with keys {list(schema_hint.keys())}. "
                    f"Finding context: {json.dumps(finding_context, ensure_ascii=True)}"
                ),
            },
        ]
        payload = self._chat_json(messages)
        return FindingAIResult(
            explanation=str(payload.get("explanation", "")).strip(),
            remediation=str(payload.get("remediation", "")).strip(),
        )

    def generate_scan_summary(self, scan_context: dict[str, Any]) -> ScanAIResult:
        """Generate a management-facing summary for one scan."""
        schema_hint = {
            "management_summary": "string",
            "top_risks": "string",
            "next_steps": "string",
        }
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a security program assistant. "
                    "Return concise JSON only. Avoid markdown and speculation. "
                    "Use grouped findings to avoid repetitive summaries. "
                    "Focus on the highest-severity repeated risks, affected areas, practical next steps, "
                    "and any meaningful regression or improvement if comparison data is present."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Summarize this scan for engineering management. "
                    f"Return JSON with keys {list(schema_hint.keys())}. "
                    f"Scan context: {json.dumps(scan_context, ensure_ascii=True)}"
                ),
            },
        ]
        payload = self._chat_json(messages)
        return ScanAIResult(
            management_summary=str(payload.get("management_summary", "")).strip(),
            top_risks=str(payload.get("top_risks", "")).strip(),
            next_steps=str(payload.get("next_steps", "")).strip(),
        )

    def _chat_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        response_payload = self._post_chat_completion(messages)
        try:
            content = response_payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("AI provider returned an unexpected response structure.") from exc
        if isinstance(content, list):
            content = "".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
        if not isinstance(content, str) or not content.strip():
            raise ValueError("AI provider returned empty content.")
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError("AI provider returned invalid JSON content.") from exc

    def _post_chat_completion(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        response = self.client.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json={
                "model": self.model,
                "messages": messages,
                "temperature": 0,
            },
        )
        response.raise_for_status()
        return response.json()


def build_ai_provider() -> AIProvider:
    """Create the configured AI provider."""
    if not settings.ai_enabled or settings.ai_provider.lower() == "disabled":
        return DisabledAIProvider()
    if settings.ai_provider.lower() in {"openai", "openai_compatible", "ollama"}:
        return OpenAICompatibleAIProvider(
            base_url=settings.ai_base_url,
            model=settings.ai_model,
            api_key=settings.ai_api_key,
            timeout_seconds=settings.ai_timeout_seconds,
        )
    raise ValueError(f"Unsupported AI provider: {settings.ai_provider}")


class AIEnrichmentService:
    """Attach optional AI explanations and management summaries after scanning."""

    def __init__(self, db: Session, provider: AIProvider | None = None) -> None:
        self.db = db
        self.grouping_service = FindingGroupingService()
        self.comparison_service = ScanComparisonService(db)
        self.provider_error: str | None = None
        if provider is not None:
            self.provider = provider
            return
        try:
            self.provider = build_ai_provider()
        except Exception as exc:  # noqa: BLE001
            self.provider = DisabledAIProvider()
            self.provider_error = self._safe_error_message(exc)

    def enrich_scan(self, scan_job: ScanJob) -> ScanJob:
        """Enrich findings and the scan summary without affecting scanner status."""
        if isinstance(self.provider, DisabledAIProvider):
            scan_job.ai_status = "disabled"
            scan_job.ai_summary = None
            scan_job.ai_top_risks = None
            scan_job.ai_next_steps = None
            scan_job.ai_error = self.provider_error
            for finding in scan_job.findings:
                finding.ai_status = "disabled"
                finding.ai_explanation = None
                finding.ai_remediation = None
                finding.ai_error = self.provider_error
            self.db.commit()
            self.db.refresh(scan_job)
            return scan_job

        finding_successes = 0
        finding_failures: list[str] = []
        for finding in scan_job.findings:
            try:
                result = self.provider.generate_finding_guidance(self._build_finding_context(finding))
                finding.ai_explanation = result.explanation
                finding.ai_remediation = result.remediation
                finding.ai_status = "completed"
                finding.ai_error = None
                finding_successes += 1
            except Exception as exc:  # noqa: BLE001
                finding.ai_status = "failed"
                finding.ai_explanation = None
                finding.ai_remediation = None
                finding.ai_error = self._safe_error_message(exc)
                finding_failures.append(f"{finding.id}: {finding.ai_error}")

        scan_summary_success = False
        scan_summary_failure: str | None = None
        try:
            summary = self.provider.generate_scan_summary(self._build_scan_context(scan_job))
            scan_job.ai_summary = summary.management_summary
            scan_job.ai_top_risks = summary.top_risks
            scan_job.ai_next_steps = summary.next_steps
            scan_summary_success = True
        except Exception as exc:  # noqa: BLE001
            scan_job.ai_summary = None
            scan_job.ai_top_risks = None
            scan_job.ai_next_steps = None
            scan_summary_failure = self._safe_error_message(exc)

        total_units = len(scan_job.findings) + 1
        success_count = finding_successes + (1 if scan_summary_success else 0)
        failure_messages = [*finding_failures]
        if scan_summary_failure:
            failure_messages.append(f"scan_summary: {scan_summary_failure}")

        if success_count == 0:
            scan_job.ai_status = "failed"
        elif success_count == total_units:
            scan_job.ai_status = "completed"
        else:
            scan_job.ai_status = "partial"
        scan_job.ai_error = "\n".join(failure_messages) if failure_messages else None
        self.db.commit()
        self.db.refresh(scan_job)
        return scan_job

    @staticmethod
    def _build_finding_context(finding: Finding) -> dict[str, Any]:
        dependency = (finding.raw_payload or {}).get("dependency") or {}
        return {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "category": finding.category,
            "tool_name": finding.tool_name,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "dependency_name": dependency.get("name"),
            "dependency_version": dependency.get("version"),
            "existing_remediation": finding.remediation,
        }

    def _build_scan_context(self, scan_job: ScanJob) -> dict[str, Any]:
        severity_counts: dict[str, int] = {}
        for finding in scan_job.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        grouped_findings = [
            {
                "title": group.title,
                "description": group.description,
                "severity": group.severity,
                "category": group.category,
                "tool_name": group.tool_name,
                "file_path": group.file_path,
                "dependency_name": group.dependency_name,
                "remediation": group.remediation,
                "member_count": group.member_count,
                "affected_files": group.affected_files[:5],
            }
            for group in self.grouping_service.group(scan_job.findings)[:10]
        ]
        return {
            "scan_id": scan_job.id,
            "project_name": scan_job.project.name if scan_job.project else None,
            "status": scan_job.status,
            "source_type": scan_job.source_type,
            "source_label": scan_job.source_label,
            "total_findings": scan_job.total_findings,
            "group_count": len(grouped_findings),
            "repeated_group_count": sum(1 for group in grouped_findings if group["member_count"] > 1),
            "severity_counts": severity_counts,
            "tool_names": [execution.tool_name for execution in scan_job.tool_executions],
            "grouped_findings": grouped_findings,
            "comparison_summary": self._build_comparison_context(scan_job),
        }

    @staticmethod
    def _safe_error_message(exc: Exception) -> str:
        return str(exc).strip()[:240] or exc.__class__.__name__

    def _build_comparison_context(self, scan_job: ScanJob) -> dict[str, Any] | None:
        comparison = self.comparison_service.build_for_scan(scan_job)
        if not comparison.comparison_available:
            return None
        return {
            "previous_scan_id": comparison.previous_scan_id,
            "trend": comparison.trend,
            "summary": comparison.summary,
            "grouped_delta": comparison.grouped_delta,
            "severity_deltas": {
                severity: value.model_dump(mode="json")
                for severity, value in comparison.severity_deltas.items()
            },
        }
