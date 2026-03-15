"""Query and filtering helpers for scan history and finding browsing."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, selectinload

from backend.app.models.project import Project
from backend.app.models.scan import Finding, ScanJob
from backend.app.schemas.scan import (
    AISummaryRead,
    GroupedFindingRead,
    ProjectSummaryRead,
    ProjectTrendSummaryRead,
    ScanApiSummaryRead,
)
from backend.app.services.comparison_service import ScanComparisonService
from backend.app.services.ecosystem_service import EcosystemDetectionService
from backend.app.services.finding_intelligence_service import FindingIntelligenceService
from backend.app.services.grouping_service import FindingGroupingService
from backend.app.services.issue_pattern_service import IssuePatternService
from backend.app.services.policy_service import PolicyEvaluationService
from backend.app.services.preflight_service import RequirementsPreflightService
from backend.app.services.remediation_summary_service import RemediationSummaryService
from backend.app.services.trend_service import ProjectTrendService

DEPENDENCY_TOOL_NAMES = {
    "pip-audit",
    "npm-audit",
    "dart-pub-outdated",
    "maven-pom-review",
    "composer-review",
    "go-mod-review",
    "dotnet-project-review",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_RANK = {severity: len(SEVERITY_ORDER) - index for index, severity in enumerate(SEVERITY_ORDER)}
TOOL_DISPLAY_NAMES = {
    "semgrep": "Semgrep code review",
    "trivy": "Trivy filesystem review",
    "pip-audit": "Python dependency audit",
    "npm-audit": "Node dependency audit",
    "dart-analyze": "Flutter/Dart static analysis",
    "dart-pub-outdated": "Dart/Flutter dependency freshness",
    "flutter-mobile-config": "Flutter mobile config review",
    "maven-pom-review": "Maven manifest review",
    "composer-review": "Composer manifest review",
    "go-mod-review": "Go module review",
    "dotnet-project-review": ".NET / NuGet review",
    "framework-review": "Framework-specific review",
}
REVIEW_MODE_LABELS = {
    "all": "All findings",
    "security": "Security risks",
    "correctness": "Code correctness",
    "dependency_config": "Dependency/config issues",
    "tooling": "Tooling/coverage issues",
}


def _is_dependency_category(category: str) -> bool:
    return category.startswith("dependency")


def human_tool_name(tool_name: str) -> str:
    """Return a readable tool label for UI summaries."""
    return TOOL_DISPLAY_NAMES.get(tool_name, tool_name)


def format_duration(seconds: int | None) -> str:
    """Return a compact human-readable duration string."""
    if seconds is None:
        return "n/a"
    minutes, remainder = divmod(max(seconds, 0), 60)
    if minutes == 0:
        return f"{remainder}s"
    if remainder == 0:
        return f"{minutes}m"
    return f"{minutes}m {remainder}s"


def highest_severity(findings: list[Finding]) -> str | None:
    """Return the highest severity present in a finding set."""
    if not findings:
        return None
    return max(
        (finding.severity for finding in findings),
        key=lambda severity: SEVERITY_RANK.get(severity, 0),
    )


def display_scan_result(scan_job: ScanJob) -> str:
    """Return a user-facing scan result label."""
    if scan_job.status == "queued":
        return "Queued"
    if scan_job.status == "running":
        return "Running"
    if scan_job.status == "failed":
        return "Failed"
    if scan_job.status == "partial" or scan_job.partial:
        return "Completed with tool issues"
    return "Completed"


def display_scan_result_tone(scan_job: ScanJob) -> str:
    """Return a badge tone for the user-facing result label."""
    if scan_job.status in {"queued", "running", "failed"}:
        return scan_job.status
    if scan_job.status == "partial" or scan_job.partial:
        return "partial"
    return "completed"


def build_progress_message(scan_job: ScanJob, duration_seconds: int | None) -> str:
    """Return concise progress wording that avoids implying live updates after completion."""
    result_label = display_scan_result(scan_job)
    if scan_job.status == "queued":
        return "Queued. Waiting for a worker to start."
    if scan_job.status == "running":
        return "Running now. Refresh this page to see updated results."
    if scan_job.status == "failed":
        if duration_seconds is not None:
            return f"Failed after {format_duration(duration_seconds)}."
        return "Failed before the scan completed."
    if duration_seconds is not None:
        return f"{result_label} in {format_duration(duration_seconds)}."
    return f"{result_label}."


def build_tool_coverage_summary(tool_executions: list[Any]) -> dict[str, Any]:
    """Return tool execution counts and issue summaries separate from findings."""
    counts = Counter(execution.status for execution in tool_executions)
    issues: list[dict[str, str]] = []
    for execution in tool_executions:
        if execution.status not in {"skipped", "failed"}:
            continue
        default_reason = (
            "The tool was unavailable or not applicable for this scan."
            if execution.status == "skipped"
            else "The tool failed before it could return usable results."
        )
        issues.append(
            {
                "tool_name": execution.tool_name,
                "tool_label": human_tool_name(execution.tool_name),
                "status": execution.status,
                "status_label": "Skipped" if execution.status == "skipped" else "Failed",
                "reason": execution.error_message or default_reason,
            }
        )
    return {
        "completed_count": counts.get("completed", 0),
        "skipped_count": counts.get("skipped", 0),
        "failed_count": counts.get("failed", 0),
        "issue_count": len(issues),
        "issues": issues,
    }


def build_findings_overview(findings: list[Finding]) -> dict[str, Any]:
    """Return concise human-readable findings summary details."""
    total_findings = len(findings)
    highest = highest_severity(findings)
    if total_findings == 0:
        return {
            "total_findings": 0,
            "highest_severity": None,
            "leading_tool_name": None,
            "leading_tool_label": None,
            "leading_tool_count": 0,
            "summary_text": "No findings were recorded.",
        }
    tool_counts = Counter(finding.tool_name for finding in findings)
    leading_tool_name, leading_tool_count = tool_counts.most_common(1)[0]
    return {
        "total_findings": total_findings,
        "highest_severity": highest,
        "leading_tool_name": leading_tool_name,
        "leading_tool_label": human_tool_name(leading_tool_name),
        "leading_tool_count": leading_tool_count,
        "summary_text": (
            f"Most findings come from {human_tool_name(leading_tool_name)} "
            f"({leading_tool_count} of {total_findings})."
        ),
    }


def build_ai_status_summary(scan_job: ScanJob, ai_readiness: dict[str, Any]) -> dict[str, Any]:
    """Return user-facing AI advisory status for one scan."""
    readiness_status = ai_readiness.get("status")
    raw_status = (scan_job.ai_status or "").lower()
    if raw_status in {"completed", "partial", "failed", "disabled"}:
        status = raw_status
    elif readiness_status == "ready":
        status = "enabled"
    else:
        status = "disabled"

    labels = {
        "disabled": "Disabled",
        "enabled": "Enabled",
        "completed": "Completed",
        "partial": "Partial",
        "failed": "Failed",
    }
    tones = {
        "disabled": "info",
        "enabled": "medium",
        "completed": "completed",
        "partial": "partial",
        "failed": "failed",
    }
    active_for_scan = status in {"enabled", "completed", "partial", "failed"}
    if status == "disabled":
        summary_text = ai_readiness.get(
            "summary_text",
            "AI explanations are optional and not required for core scanning.",
        )
    elif status == "enabled":
        summary_text = (
            "AI enrichment is enabled for this scan and runs after deterministic scanners complete. "
            "AI output is advisory only."
        )
    elif status == "completed":
        summary_text = (
            "AI explanations and summaries are available for this scan. "
            "Use them for interpretation, but rely on raw findings and policy for authoritative decisions."
        )
    elif status == "partial":
        summary_text = (
            "Some AI explanations were generated, but others were unavailable. "
            "Deterministic scanner output and policy remain authoritative."
        )
    else:
        summary_text = (
            "AI enrichment failed for this scan. Core scanning results remain available and authoritative."
        )
    return {
        "status": status,
        "status_label": labels[status],
        "status_tone": tones[status],
        "active_for_scan": active_for_scan,
        "show_setup_hint": status == "disabled",
        "error_message": summarize_ai_error(scan_job.ai_error, disabled=status == "disabled"),
        "summary_text": summary_text,
        "provider": ai_readiness.get("provider", "disabled"),
        "model": ai_readiness.get("model"),
        "base_url": ai_readiness.get("base_url"),
        "readiness_status": readiness_status,
        "readiness_status_label": ai_readiness.get("status_label", "Unknown"),
        "readiness_warnings": ai_readiness.get("warnings", []),
        "api_key_configured": ai_readiness.get("api_key_configured", False),
    }


def summarize_ai_error(error: str | None, *, disabled: bool = False) -> str | None:
    """Return a short operator-facing AI failure message for UI/report views."""
    if disabled or not error:
        return None
    normalized = str(error).strip().lower()
    if not normalized:
        return None
    if any(token in normalized for token in ("connection refused", "errno 61", "errno 111", "connecterror")):
        return (
            "AI enrichment failed because the configured AI endpoint was unreachable. "
            "Check AI_ENABLED / AI_BASE_URL / provider availability."
        )
    if any(token in normalized for token in ("timed out", "timeout")):
        return (
            "AI enrichment failed because the configured AI endpoint timed out. "
            "Check AI_BASE_URL / provider availability / AI_TIMEOUT_SECONDS."
        )
    if any(token in normalized for token in ("401", "403", "unauthorized", "forbidden", "authentication")):
        return (
            "AI enrichment failed because the configured AI provider rejected the request. "
            "Check AI_API_KEY / provider configuration."
        )
    return "AI enrichment failed. Check AI_ENABLED / AI_BASE_URL / provider availability."


class ScanQueryService:
    """Provide dashboard and scan-detail query/filter behavior."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.ecosystem_service = EcosystemDetectionService()
        self.finding_intelligence_service = FindingIntelligenceService()
        self.grouping_service = FindingGroupingService()
        self.issue_pattern_service = IssuePatternService()
        self.comparison_service = ScanComparisonService(db)
        self.policy_service = PolicyEvaluationService()
        self.remediation_summary_service = RemediationSummaryService()
        self.requirements_preflight_service = RequirementsPreflightService()
        self.trend_service = ProjectTrendService(db) if db is not None else None

    def build_dashboard_context(
        self,
        *,
        request: Any,
        error: str | None = None,
        project: str | None = None,
        status: str | None = None,
        source_type: str | None = None,
        severity: str | None = None,
    ) -> dict[str, Any]:
        """Return dashboard context with scan history filters applied."""
        scans_query = (
            select(ScanJob)
            .join(Project)
            .options(
                selectinload(ScanJob.project),
                selectinload(ScanJob.tool_executions),
                selectinload(ScanJob.findings),
            )
            .order_by(ScanJob.created_at.desc())
        )
        scans_query = self._apply_scan_filters(
            scans_query,
            project=project,
            status=status,
            source_type=source_type,
            severity=severity,
        )
        latest_scans = self.db.execute(scans_query.limit(25)).scalars().all()

        severity_counts = dict(
            self.db.execute(select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)).all()
        )
        recent_projects = (
            self.db.execute(select(Project).order_by(Project.created_at.desc()).limit(25)).scalars().all()
        )
        all_projects = self.db.execute(select(Project).order_by(Project.name.asc())).scalars().all()
        scan_rows = [self._build_dashboard_scan_row(scan) for scan in latest_scans]
        return {
            "request": request,
            "latest_scans": latest_scans,
            "scan_rows": scan_rows,
            "severity_counts": severity_counts,
            "recent_projects": recent_projects,
            "all_projects": all_projects,
            "error": error,
            "status_counts": dict(Counter(scan.status for scan in latest_scans)),
            "result_counts": dict(Counter(row["result_label"] for row in scan_rows)),
            "project_options": [project_item.name for project_item in recent_projects],
            "filter_options": {
                "status": ["completed", "partial", "failed", "running", "queued"],
                "source_type": ["local_path", "uploaded_archive"],
                "severity": ["critical", "high", "medium", "low", "info", "unknown"],
            },
            "active_filters": {
                "project": project or "",
                "status": status or "",
                "source_type": source_type or "",
                "severity": severity or "",
            },
        }

    def load_scan_detail(
        self,
        scan_job_id: str,
        *,
        severity: str | None = None,
        tool: str | None = None,
        category: str | None = None,
        finding_type: str | None = None,
        review_mode: str | None = None,
        ai_filter: str | None = None,
        pattern_key: str | None = None,
        hotspot_file: str | None = None,
        hotspot_module: str | None = None,
        compare_to_scan_id: str | None = None,
        raw_page: int = 1,
        raw_limit: int = 100,
    ) -> dict[str, Any] | None:
        """Load one scan and return filterable detail context."""
        scan_job = (
            self.db.execute(
                select(ScanJob)
                .where(ScanJob.id == scan_job_id)
                .options(
                    selectinload(ScanJob.project),
                    selectinload(ScanJob.findings),
                    selectinload(ScanJob.tool_executions),
                    selectinload(ScanJob.reports),
                )
            )
            .scalars()
            .first()
        )
        if scan_job is None:
            return None
        comparison_summary = self.comparison_service.build_for_scan(
            scan_job,
            compare_to_scan_id=compare_to_scan_id,
        ).model_dump(mode="json")
        policy_summary = self.policy_service.evaluate_scan(
            scan_job,
            comparison=comparison_summary,
        ).model_dump(mode="json")

        base_filtered_findings = self.filter_findings(
            scan_job.findings,
            severity=severity,
            tool=tool,
            category=category,
            finding_type=finding_type,
            review_mode=review_mode,
            ai_filter=ai_filter,
        )
        base_grouped_findings = [
            self._with_group_anchor(self.finding_intelligence_service.enrich_group(group.as_dict()))
            for group in self.grouping_service.group(base_filtered_findings)
        ]
        triage_summary = self.issue_pattern_service.build_summary(
            base_filtered_findings,
            grouped_findings=base_grouped_findings,
            max_patterns=10,
            max_hotspots=10,
        )
        filtered_findings = self._apply_triage_drilldown(
            base_filtered_findings,
            pattern_key=pattern_key,
            hotspot_file=hotspot_file,
            hotspot_module=hotspot_module,
        )
        grouped_filtered_findings = [
            self._with_group_anchor(self.finding_intelligence_service.enrich_group(group.as_dict()))
            for group in self.grouping_service.group(filtered_findings)
        ]
        grouped_filtered_findings = self._sort_grouped_findings(grouped_filtered_findings)
        top_priority_groups = grouped_filtered_findings[:10]
        raw_limit = min(max(raw_limit, 25), 250)
        total_filtered_findings = len(filtered_findings)
        total_pages = max((total_filtered_findings + raw_limit - 1) // raw_limit, 1)
        raw_page = min(max(raw_page, 1), total_pages)
        raw_start = (raw_page - 1) * raw_limit
        raw_end = raw_start + raw_limit
        raw_findings_page = filtered_findings[raw_start:raw_end]
        serialized_raw_findings = [self._serialize_finding_with_intelligence(finding) for finding in raw_findings_page]
        dependency_findings = [finding for finding in serialized_raw_findings if _is_dependency_category(finding["category"])]
        general_findings = [finding for finding in serialized_raw_findings if not _is_dependency_category(finding["category"])]
        workspace_path = Path(scan_job.workspace_path) if scan_job.workspace_path else None
        ecosystems = []
        ecosystem_summary: list[dict[str, Any]] = []
        frameworks: list[str] = []
        framework_summary: list[dict[str, Any]] = []
        if workspace_path and workspace_path.exists():
            inventory = self.ecosystem_service.detect(workspace_path)
            ecosystems = inventory.ecosystems
            ecosystem_summary = self._serialize_detection_summary(
                workspace_path,
                inventory.details,
            )
            frameworks = inventory.frameworks
            framework_summary = self._serialize_detection_summary(
                workspace_path,
                inventory.framework_details,
            )
        tool_coverage = build_tool_coverage_summary(scan_job.tool_executions)
        findings_overview = build_findings_overview(scan_job.findings)
        duration_seconds = self.calculate_duration_seconds(scan_job)
        ai_readiness = self.requirements_preflight_service.build_summary()["ai"]
        ai_status = build_ai_status_summary(scan_job, ai_readiness)
        remediation_summary = self.remediation_summary_service.build_summary(
            triage_summary=triage_summary,
            grouped_findings=base_grouped_findings,
            comparison=comparison_summary,
        )

        return {
            "scan": scan_job,
            "severity_counts": dict(Counter(finding.severity for finding in scan_job.findings)),
            "filtered_findings": raw_findings_page,
            "total_filtered_findings": total_filtered_findings,
            "grouped_filtered_findings": grouped_filtered_findings,
            "top_priority_groups": top_priority_groups,
            "triage_summary": triage_summary,
            "remediation_summary": remediation_summary,
            "grouped_finding_summary": {
                "group_count": len(grouped_filtered_findings),
                "repeated_group_count": sum(1 for group in grouped_filtered_findings if group["member_count"] > 1),
                "consolidated_occurrences": sum(group["member_count"] for group in grouped_filtered_findings),
            },
            "comparison": comparison_summary,
            "policy": policy_summary,
            "comparison_options": self.comparison_service.list_previous_scan_options(scan_job),
            "findings_by_tool": self.group_findings_by_tool(serialized_raw_findings),
            "dependency_findings_by_tool": self.group_findings_by_tool(dependency_findings),
            "general_findings_by_tool": self.group_findings_by_tool(general_findings),
            "finding_filter_options": {
                "severity": sorted({finding.severity for finding in scan_job.findings}),
                "tool": sorted({finding.tool_name for finding in scan_job.findings}),
                "category": sorted({finding.category for finding in scan_job.findings}),
                "finding_type": sorted(
                    {
                        self.finding_intelligence_service.enrich_finding(finding)["finding_type"]
                        for finding in scan_job.findings
                    }
                ),
                "ai_filter": ["with_ai", "without_ai"],
            },
            "active_finding_filters": {
                "severity": severity or "",
                "tool": tool or "",
                "category": category or "",
                "finding_type": finding_type or "",
                "review_mode": review_mode or "all",
                "ai_filter": ai_filter or "",
            },
            "active_triage_filters": {
                "pattern_key": pattern_key or "",
                "hotspot_file": hotspot_file or "",
                "hotspot_module": hotspot_module or "",
            },
            "active_compare_to": compare_to_scan_id or "",
            "scan_summary": {
                "result_label": display_scan_result(scan_job),
                "result_tone": display_scan_result_tone(scan_job),
                "progress_message": build_progress_message(scan_job, duration_seconds),
                "tools_run": len(scan_job.tool_executions),
                "source_type": scan_job.source_type,
                "queued_at": scan_job.queued_at,
                "started_at": scan_job.started_at,
                "finished_at": scan_job.finished_at,
                "duration_seconds": duration_seconds,
                "duration_text": format_duration(duration_seconds),
                "ecosystems": ecosystems,
                "ecosystem_summary": ecosystem_summary,
                "frameworks": frameworks,
                "framework_summary": framework_summary,
                "stack_summary": self._build_stack_summary(ecosystems, frameworks),
                "worker_error": scan_job.worker_error,
                "retry_count": scan_job.retry_count,
                "ai_status": scan_job.ai_status,
                "ai_error": scan_job.ai_error,
                "ai_summary": scan_job.ai_summary,
                "ai_top_risks": scan_job.ai_top_risks,
                "ai_next_steps": scan_job.ai_next_steps,
                "policy_status": policy_summary["status"],
                "tool_coverage": tool_coverage,
                "findings_overview": findings_overview,
                "ai_status": ai_status,
                "ai_readiness": ai_readiness,
            },
            "review_tabs": self._build_review_tabs(
                scan_job.findings,
                active_review_mode=review_mode or "all",
            ),
            "raw_finding_pagination": {
                "page": raw_page,
                "limit": raw_limit,
                "total_items": total_filtered_findings,
                "total_pages": total_pages,
                "start_index": raw_start + 1 if total_filtered_findings else 0,
                "end_index": min(raw_end, total_filtered_findings),
                "has_previous": raw_page > 1,
                "has_next": raw_page < total_pages,
                "previous_page": raw_page - 1,
                "next_page": raw_page + 1,
            },
            "dependency_tool_executions": [
                execution for execution in scan_job.tool_executions if execution.tool_name in DEPENDENCY_TOOL_NAMES
            ],
            "is_active": scan_job.status in {"queued", "running"},
        }

    def load_scan_job(self, scan_job_id: str) -> ScanJob | None:
        """Load a scan with related entities for API serialization."""
        return (
            self.db.execute(
                select(ScanJob)
                .where(ScanJob.id == scan_job_id)
                .options(
                    selectinload(ScanJob.project),
                    selectinload(ScanJob.findings),
                    selectinload(ScanJob.tool_executions),
                    selectinload(ScanJob.reports),
                )
            )
            .scalars()
            .first()
        )

    def build_scan_api_summary(self, scan_job: ScanJob) -> ScanApiSummaryRead:
        """Serialize a stable summary payload for external API clients."""
        ecosystems: list[str] = []
        ecosystem_summary: list[dict[str, Any]] = []
        frameworks: list[str] = []
        framework_summary: list[dict[str, Any]] = []
        grouped_findings = [
            GroupedFindingRead(**self.finding_intelligence_service.enrich_group(group.as_dict()))
            for group in self.grouping_service.group(scan_job.findings)
        ]
        grouped_findings = sorted(grouped_findings, key=lambda group: self.finding_intelligence_service.sort_key(group.model_dump(mode="json")))
        comparison_summary = self._safe_comparison_summary(scan_job)
        policy_summary = self.policy_service.evaluate_scan(
            scan_job,
            comparison=comparison_summary,
        )
        if scan_job.workspace_path:
            workspace_path = Path(scan_job.workspace_path)
            if workspace_path.exists():
                inventory = self.ecosystem_service.detect(workspace_path)
                ecosystems = inventory.ecosystems
                ecosystem_summary = self._serialize_detection_summary(
                    workspace_path,
                    inventory.details,
                )
                frameworks = inventory.frameworks
                framework_summary = self._serialize_detection_summary(
                    workspace_path,
                    inventory.framework_details,
                )
        return ScanApiSummaryRead(
            scan_id=scan_job.id,
            status=scan_job.status,
            partial=scan_job.partial,
            project=ProjectSummaryRead(id=scan_job.project.id, name=scan_job.project.name),
            source_type=scan_job.source_type,
            source_label=scan_job.source_label,
            total_findings=scan_job.total_findings,
            ecosystems=ecosystems,
            ecosystem_summary=ecosystem_summary,
            frameworks=frameworks,
            framework_summary=framework_summary,
            severity_counts=dict(Counter(finding.severity for finding in scan_job.findings)),
            tool_summary={
                "count": len(scan_job.tool_executions),
                "names": [execution.tool_name for execution in scan_job.tool_executions],
                "statuses": {execution.tool_name: execution.status for execution in scan_job.tool_executions},
            },
            grouped_finding_count=len(grouped_findings),
            repeated_group_count=sum(1 for group in grouped_findings if group.member_count > 1),
            grouped_findings=grouped_findings,
            ai_summary=AISummaryRead(
                status=scan_job.ai_status,
                summary_available=bool(scan_job.ai_summary),
                management_summary=scan_job.ai_summary,
                error=scan_job.ai_error,
            ),
            policy=policy_summary,
            report_urls={
                report.report_format: f"/api/v1/scans/{scan_job.id}/reports/{report.report_format}"
                for report in scan_job.reports
            },
            created_at=scan_job.created_at,
            queued_at=scan_job.queued_at,
            started_at=scan_job.started_at,
            finished_at=scan_job.finished_at,
            duration_seconds=scan_job.duration_seconds,
        )

    def list_recent_scans_for_project_api(self, project_id: str, limit: int = 10) -> list[ScanApiSummaryRead]:
        """Return recent scans for one project as stable API payloads."""
        scans = (
            self.db.execute(
                select(ScanJob)
                .where(ScanJob.project_id == project_id)
                .options(
                    selectinload(ScanJob.project),
                    selectinload(ScanJob.findings),
                    selectinload(ScanJob.tool_executions),
                    selectinload(ScanJob.reports),
                )
                .order_by(ScanJob.created_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )
        return [self.build_scan_api_summary(scan) for scan in scans]

    def build_scan_comparison_api_summary(
        self,
        scan_job_id: str,
        *,
        compare_to_scan_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Serialize a stable comparison payload for external API clients."""
        scan_job = self.load_scan_job(scan_job_id)
        if scan_job is None:
            return None
        return self.comparison_service.build_for_scan(
            scan_job,
            compare_to_scan_id=compare_to_scan_id,
        ).model_dump(mode="json")

    def build_scan_policy_api_summary(
        self,
        scan_job_id: str,
        *,
        compare_to_scan_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Serialize a stable policy payload for external API clients."""
        scan_job = self.load_scan_job(scan_job_id)
        if scan_job is None:
            return None
        comparison_summary = self.comparison_service.build_for_scan(
            scan_job,
            compare_to_scan_id=compare_to_scan_id,
        ).model_dump(mode="json")
        return self.policy_service.evaluate_scan(
            scan_job,
            comparison=comparison_summary,
        ).model_dump(mode="json")

    def build_project_trend_api_summary(
        self,
        project_id: str,
        *,
        limit: int | None = None,
    ) -> ProjectTrendSummaryRead | None:
        """Serialize a stable project trend payload for external API clients."""
        if self.trend_service is None:
            return None
        return self.trend_service.build_project_trend(project_id, limit=limit)

    def _serialize_detection_summary(
        self,
        workspace_path: Path,
        details: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Serialize ecosystem or framework detection details for UI and API payloads."""
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

    def _build_dashboard_scan_row(self, scan_job: ScanJob) -> dict[str, Any]:
        """Return a concise row model for dashboard scan history."""
        duration_seconds = self.calculate_duration_seconds(scan_job)
        findings_overview = build_findings_overview(scan_job.findings)
        tool_coverage = build_tool_coverage_summary(scan_job.tool_executions)
        ecosystems: list[str] = []
        frameworks: list[str] = []
        if scan_job.workspace_path:
            workspace_path = Path(scan_job.workspace_path)
            if workspace_path.exists():
                inventory = self.ecosystem_service.detect(workspace_path)
                ecosystems = inventory.ecosystems
                frameworks = inventory.frameworks
        return {
            "scan": scan_job,
            "result_label": display_scan_result(scan_job),
            "result_tone": display_scan_result_tone(scan_job),
            "progress_message": build_progress_message(scan_job, duration_seconds),
            "duration_text": format_duration(duration_seconds) if duration_seconds is not None else "n/a",
            "highest_severity": findings_overview["highest_severity"],
            "findings_summary": findings_overview["summary_text"],
            "tool_coverage": tool_coverage,
            "stack_summary": self._build_stack_summary(ecosystems, frameworks),
        }

    def _build_stack_summary(self, ecosystems: list[str], frameworks: list[str]) -> str:
        """Return a compact combined ecosystem/framework summary string."""
        parts: list[str] = []
        if ecosystems:
            parts.append(", ".join(ecosystems))
        if frameworks:
            parts.append(f"frameworks: {', '.join(frameworks)}")
        return " · ".join(parts) if parts else "No ecosystem markers detected"

    def _sort_grouped_findings(self, grouped_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sort grouped findings for triage-first presentation."""
        return sorted(
            grouped_findings,
            key=lambda group: (
                self.finding_intelligence_service.sort_key(group),
                -group.get("member_count", 0),
            ),
        )

    def _safe_comparison_summary(self, scan_job: ScanJob) -> dict[str, Any]:
        """Return a comparison summary when a DB-backed comparison is available."""
        if self.db is None:
            return {"comparison_available": False, "message": "No previous scan is available for comparison."}
        return self.comparison_service.build_for_scan(scan_job).model_dump(mode="json")

    def filter_findings(
        self,
        findings: list[Finding],
        *,
        severity: str | None = None,
        tool: str | None = None,
        category: str | None = None,
        finding_type: str | None = None,
        review_mode: str | None = None,
        ai_filter: str | None = None,
    ) -> list[Finding]:
        """Apply in-memory filters to a scan's findings."""
        filtered = findings
        if severity:
            filtered = [finding for finding in filtered if finding.severity == severity]
        if tool:
            filtered = [finding for finding in filtered if finding.tool_name == tool]
        if category:
            filtered = [finding for finding in filtered if finding.category == category]
        if finding_type:
            filtered = [
                finding
                for finding in filtered
                if self.finding_intelligence_service.enrich_finding(finding)["finding_type"] == finding_type
            ]
        if review_mode and review_mode != "all":
            filtered = [
                finding
                for finding in filtered
                if self._matches_review_mode(self.finding_intelligence_service.enrich_finding(finding), review_mode)
            ]
        if ai_filter == "with_ai":
            filtered = [finding for finding in filtered if bool(finding.ai_explanation)]
        elif ai_filter == "without_ai":
            filtered = [finding for finding in filtered if not bool(finding.ai_explanation)]
        return filtered

    def _apply_triage_drilldown(
        self,
        findings: list[Finding],
        *,
        pattern_key: str | None,
        hotspot_file: str | None,
        hotspot_module: str | None,
    ) -> list[Finding]:
        filtered = findings
        if pattern_key:
            filtered = [
                finding
                for finding in filtered
                if self.issue_pattern_service.matches_pattern(finding, pattern_key)
            ]
        if hotspot_file:
            filtered = [
                finding
                for finding in filtered
                if self.issue_pattern_service.matches_hotspot_file(finding, hotspot_file)
            ]
        if hotspot_module:
            filtered = [
                finding
                for finding in filtered
                if self.issue_pattern_service.matches_hotspot_module(finding, hotspot_module)
            ]
        return filtered

    def group_findings_by_tool(self, findings: list[Any]) -> dict[str, list[Any]]:
        """Group findings by tool name while preserving input order."""
        grouped: dict[str, list[Finding]] = {}
        for finding in findings:
            tool_name = finding["tool_name"] if isinstance(finding, dict) else finding.tool_name
            grouped.setdefault(tool_name, []).append(finding)
        return grouped

    def _serialize_finding_with_intelligence(self, finding: Finding) -> dict[str, Any]:
        payload = self.finding_intelligence_service.enrich_finding(finding)
        payload["ai_error_summary"] = summarize_ai_error(
            payload.get("ai_error"),
            disabled=payload.get("ai_status") == "disabled",
        )
        return payload

    def _with_group_anchor(self, group: dict[str, Any]) -> dict[str, Any]:
        return {
            **group,
            "anchor_id": f"group-{self._slugify(group['group_key'])}",
        }

    @staticmethod
    def _slugify(value: str) -> str:
        slug = "".join(char if char.isalnum() else "-" for char in value.lower())
        slug = "-".join(part for part in slug.split("-") if part)
        return slug or "group"

    def _build_review_tabs(self, findings: list[Finding], *, active_review_mode: str) -> list[dict[str, Any]]:
        tabs: list[dict[str, Any]] = []
        for mode, label in REVIEW_MODE_LABELS.items():
            if mode == "all":
                count = len(findings)
            else:
                count = sum(
                    1
                    for finding in findings
                    if self._matches_review_mode(self.finding_intelligence_service.enrich_finding(finding), mode)
                )
            tabs.append(
                {
                    "mode": mode,
                    "label": label,
                    "count": count,
                    "active": active_review_mode == mode,
                }
            )
        return tabs

    @staticmethod
    def _matches_review_mode(finding: dict[str, Any], review_mode: str) -> bool:
        finding_type = finding.get("finding_type")
        security_relevance = finding.get("security_relevance")
        if review_mode == "security":
            return security_relevance in {"direct", "indirect"} and finding_type != "tooling_or_coverage"
        if review_mode == "correctness":
            return finding_type == "code_correctness"
        if review_mode == "dependency_config":
            return finding_type in {"dependency_hygiene", "configuration_risk"}
        if review_mode == "tooling":
            return finding_type == "tooling_or_coverage"
        return True

    def calculate_duration_seconds(self, scan_job: ScanJob) -> int | None:
        """Compute scan duration from timestamps if available."""
        if not scan_job.started_at or not scan_job.finished_at:
            return scan_job.duration_seconds
        started_at = scan_job.started_at
        finished_at = scan_job.finished_at
        if started_at.tzinfo is None and finished_at.tzinfo is not None:
            started_at = started_at.replace(tzinfo=finished_at.tzinfo)
        if finished_at.tzinfo is None and started_at.tzinfo is not None:
            finished_at = finished_at.replace(tzinfo=started_at.tzinfo)
        return max(int((finished_at - started_at).total_seconds()), 0)

    def _apply_scan_filters(
        self,
        query: Select,
        *,
        project: str | None,
        status: str | None,
        source_type: str | None,
        severity: str | None,
    ) -> Select:
        if project:
            query = query.where(Project.name == project)
        if status:
            query = query.where(ScanJob.status == status)
        if source_type:
            query = query.where(ScanJob.source_type == source_type)
        if severity:
            query = query.join(Finding).where(Finding.severity == severity).distinct()
        return query
