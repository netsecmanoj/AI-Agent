"""Report generation helpers for JSON and HTML outputs."""

from collections import Counter
from pathlib import Path
from typing import Any
import json

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.app.core.config import get_settings
from backend.app.models.report import Report
from backend.app.models.scan import ScanJob
from backend.app.services.ecosystem_service import EcosystemDetectionService
from backend.app.services.finding_intelligence_service import FindingIntelligenceService
from backend.app.services.grouping_service import FindingGroupingService
from backend.app.services.issue_pattern_service import IssuePatternService
from backend.app.services.policy_service import PolicyEvaluationService
from backend.app.services.preflight_service import RequirementsPreflightService
from backend.app.services.query_service import (
    build_ai_status_summary,
    build_findings_overview,
    build_progress_message,
    build_tool_coverage_summary,
    display_scan_result,
    display_scan_result_tone,
    format_duration,
    summarize_ai_error,
)
from backend.app.services.remediation_summary_service import RemediationSummaryService

settings = get_settings()
ecosystem_service = EcosystemDetectionService()
grouping_service = FindingGroupingService()
finding_intelligence_service = FindingIntelligenceService()
issue_pattern_service = IssuePatternService()
policy_service = PolicyEvaluationService()
remediation_summary_service = RemediationSummaryService()
requirements_preflight_service = RequirementsPreflightService()
DEPENDENCY_TOOL_NAMES = {
    "pip-audit",
    "npm-audit",
    "dart-pub-outdated",
    "maven-pom-review",
    "composer-review",
    "go-mod-review",
    "dotnet-project-review",
}


def _is_dependency_category(category: str) -> bool:
    return category.startswith("dependency")


def _group_findings(findings_payload: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for finding in findings_payload:
        grouped.setdefault(finding["tool_name"], []).append(finding)
    return grouped


def _serialize_detection_summary(workspace_path: Path, details: dict[str, Any]) -> list[dict[str, Any]]:
    """Serialize ecosystem or framework detection details for report payloads."""
    return [
        {
            "name": name,
            "manifests": [
                str(path.relative_to(workspace_path)) if path.is_relative_to(workspace_path) else path.name
                for path in detail.manifests
            ],
            "audit_files": [
                str(path.relative_to(workspace_path)) if path.is_relative_to(workspace_path) else path.name
                for path in detail.audit_files
            ],
            "audit_ready": detail.audit_ready,
            "project_kind": detail.project_kind,
            "markers": detail.markers,
        }
        for name, detail in details.items()
    ]


def build_scan_context(scan_job: ScanJob, comparison: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a serializable report context from a scan job."""
    findings_payload = [
        {
            **finding_intelligence_service.enrich_finding(finding),
            "ai_error_summary": summarize_ai_error(
                getattr(finding, "ai_error", None),
                disabled=getattr(finding, "ai_status", None) == "disabled",
            ),
        }
        for finding in scan_job.findings
    ]
    grouped_findings = _group_findings(findings_payload)
    grouped_finding_summary = [
        _with_group_anchor(finding_intelligence_service.enrich_group(group.as_dict()))
        for group in grouping_service.group(scan_job.findings)
    ]
    grouped_finding_summary = sorted(
        grouped_finding_summary,
        key=lambda group: (
            finding_intelligence_service.sort_key(group),
            -group.get("member_count", 0),
        ),
    )
    dependency_findings = [finding for finding in findings_payload if _is_dependency_category(finding["category"])]
    non_dependency_findings = [finding for finding in findings_payload if not _is_dependency_category(finding["category"])]
    triage_summary = issue_pattern_service.build_summary(
        findings_payload,
        grouped_findings=grouped_finding_summary,
        max_patterns=10,
        max_hotspots=10,
    )
    ecosystems: list[str] = []
    ecosystem_summary: list[dict[str, Any]] = []
    frameworks: list[str] = []
    framework_summary: list[dict[str, Any]] = []
    if scan_job.workspace_path:
        workspace_path = Path(scan_job.workspace_path)
        if workspace_path.exists():
            inventory = ecosystem_service.detect(workspace_path)
            ecosystems = inventory.ecosystems
            ecosystem_summary = _serialize_detection_summary(workspace_path, inventory.details)
            frameworks = inventory.frameworks
            framework_summary = _serialize_detection_summary(workspace_path, inventory.framework_details)
    duration_seconds = _calculate_duration_seconds(scan_job)
    policy_summary = policy_service.evaluate_scan(scan_job, comparison=comparison).model_dump(mode="json")
    tool_coverage = build_tool_coverage_summary(scan_job.tool_executions)
    findings_overview = build_findings_overview(scan_job.findings)
    ai_readiness = requirements_preflight_service.build_summary()["ai"]
    ai_status = build_ai_status_summary(scan_job, ai_readiness)
    remediation_summary = remediation_summary_service.build_summary(
        triage_summary=triage_summary,
        grouped_findings=grouped_finding_summary,
        comparison=comparison,
    )
    return {
        "scan_id": scan_job.id,
        "project": {
            "id": scan_job.project.id,
            "name": scan_job.project.name,
            "source_type": scan_job.project.source_type,
            "source_value": scan_job.project.source_value,
            "effective_policy": policy_service.resolve_project_policy(scan_job.project).payload(),
        },
        "status": scan_job.status,
        "partial": scan_job.partial,
        "source_type": scan_job.source_type,
        "source_value": scan_job.source_value,
        "source_filename": scan_job.source_filename,
        "source_label": scan_job.source_label,
        "workspace_path": scan_job.workspace_path,
        "total_findings": scan_job.total_findings,
        "created_at": scan_job.created_at.isoformat() if scan_job.created_at else None,
        "queued_at": scan_job.queued_at.isoformat() if scan_job.queued_at else None,
        "started_at": scan_job.started_at.isoformat() if scan_job.started_at else None,
        "finished_at": scan_job.finished_at.isoformat() if scan_job.finished_at else None,
        "duration_seconds": duration_seconds,
        "duration_text": format_duration(duration_seconds),
        "result_label": display_scan_result(scan_job),
        "result_tone": display_scan_result_tone(scan_job),
        "progress_message": build_progress_message(scan_job, duration_seconds),
        "ecosystems": ecosystems,
        "ecosystem_summary": ecosystem_summary,
        "frameworks": frameworks,
        "framework_summary": framework_summary,
        "stack_summary": _build_stack_summary(ecosystems, frameworks),
        "worker_error": scan_job.worker_error,
        "retry_count": scan_job.retry_count,
        "ai_status": scan_job.ai_status,
        "ai_summary": scan_job.ai_summary,
        "ai_top_risks": scan_job.ai_top_risks,
        "ai_next_steps": scan_job.ai_next_steps,
        "ai_error": scan_job.ai_error,
        "ai_error_summary": summarize_ai_error(scan_job.ai_error, disabled=(scan_job.ai_status or "").lower() == "disabled"),
        "severity_counts": dict(Counter(finding.severity for finding in scan_job.findings)),
        "tool_executions": [
            {
                "id": execution.id,
                "tool_name": execution.tool_name,
                "status": execution.status,
                "command": execution.command,
                "error_message": execution.error_message,
                "is_dependency_tool": execution.tool_name in DEPENDENCY_TOOL_NAMES,
            }
            for execution in scan_job.tool_executions
        ],
        "tool_summary": {
            "count": len(scan_job.tool_executions),
            "names": [execution.tool_name for execution in scan_job.tool_executions],
        },
        "tool_coverage": tool_coverage,
        "findings_overview": findings_overview,
        "ai_status_summary": ai_status,
        "ai_readiness": ai_readiness,
        "dependency_tool_summary": {
            "count": len(
                [execution for execution in scan_job.tool_executions if execution.tool_name in DEPENDENCY_TOOL_NAMES]
            ),
            "executions": [
                {
                    "tool_name": execution.tool_name,
                    "status": execution.status,
                    "error_message": execution.error_message,
                }
                for execution in scan_job.tool_executions
                if execution.tool_name in DEPENDENCY_TOOL_NAMES
            ],
        },
        "ai_summary_block": {
            "status": scan_job.ai_status,
            "management_summary": scan_job.ai_summary,
            "top_risks": scan_job.ai_top_risks,
            "next_steps": scan_job.ai_next_steps,
            "error": scan_job.ai_error,
            "error_summary": summarize_ai_error(
                scan_job.ai_error,
                disabled=(scan_job.ai_status or "").lower() == "disabled",
            ),
        },
        "finding_groups": grouped_findings,
        "grouped_findings": grouped_finding_summary,
        "top_priority_groups": grouped_finding_summary[:10],
        "triage_summary": triage_summary,
        "remediation_summary": remediation_summary,
        "grouped_finding_summary": {
            "group_count": len(grouped_finding_summary),
            "repeated_group_count": sum(1 for group in grouped_finding_summary if group["member_count"] > 1),
            "consolidated_occurrences": sum(group["member_count"] for group in grouped_finding_summary),
        },
        "comparison": comparison,
        "policy": policy_summary,
        "finding_breakdown": {
            "dependency": dependency_findings,
            "code_and_config": non_dependency_findings,
        },
        "findings": findings_payload,
}


def _with_group_anchor(group: dict[str, Any]) -> dict[str, Any]:
    return {
        **group,
        "anchor_id": f"group-{_slugify(group['group_key'])}",
    }


def _slugify(value: str) -> str:
    slug = "".join(char if char.isalnum() else "-" for char in value.lower())
    slug = "-".join(part for part in slug.split("-") if part)
    return slug or "group"


def _build_stack_summary(ecosystems: list[str], frameworks: list[str]) -> str:
    parts: list[str] = []
    if ecosystems:
        parts.append(", ".join(ecosystems))
    if frameworks:
        parts.append(f"frameworks: {', '.join(frameworks)}")
    return " · ".join(parts) if parts else "No ecosystem markers detected"


def _calculate_duration_seconds(scan_job: ScanJob) -> int | None:
    if scan_job.duration_seconds is not None:
        return scan_job.duration_seconds
    if not scan_job.started_at or not scan_job.finished_at:
        return None
    started_at = scan_job.started_at
    finished_at = scan_job.finished_at
    if started_at.tzinfo is None and finished_at.tzinfo is not None:
        started_at = started_at.replace(tzinfo=finished_at.tzinfo)
    if finished_at.tzinfo is None and started_at.tzinfo is not None:
        finished_at = finished_at.replace(tzinfo=started_at.tzinfo)
    return max(int((finished_at - started_at).total_seconds()), 0)


class ReportService:
    """Generate persisted report files for a completed scan."""

    def __init__(self) -> None:
        self.environment = Environment(
            loader=FileSystemLoader(settings.templates_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def generate_reports(self, scan_job: ScanJob, comparison: dict[str, Any] | None = None) -> list[Report]:
        """Generate JSON and HTML reports for a scan job."""
        output_dir = settings.report_output_dir / scan_job.id
        output_dir.mkdir(parents=True, exist_ok=True)
        context = build_scan_context(scan_job, comparison=comparison)
        json_path = output_dir / "report.json"
        html_path = output_dir / "report.html"
        summary_path = output_dir / "summary.json"
        json_path.write_text(json.dumps(context, indent=2), encoding="utf-8")
        summary_path.write_text(json.dumps(context["remediation_summary"], indent=2), encoding="utf-8")
        html_template = self.environment.get_template("report.html")
        html_path.write_text(html_template.render(scan=context), encoding="utf-8")
        return [
            Report(scan_job_id=scan_job.id, report_format="json", path=str(json_path)),
            Report(scan_job_id=scan_job.id, report_format="html", path=str(html_path)),
            Report(scan_job_id=scan_job.id, report_format="summary", path=str(summary_path)),
        ]
