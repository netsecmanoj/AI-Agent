"""Schemas for scan creation and serialized findings."""

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class ScanCreateRequest(BaseModel):
    """Request payload for creating a scan job."""

    source_type: Literal["local_path", "uploaded_archive"] = "local_path"
    source_value: str = Field(default="", min_length=0)
    project_id: str | None = None
    project_name: str | None = None
    source_label: str | None = None


class PreparedScanRequest(BaseModel):
    """Prepared scan metadata after source ingestion and workspace setup."""

    source_type: Literal["local_path", "uploaded_archive"]
    project_name: str
    source_value: str
    source_filename: str | None = None
    workspace_path: Path


class FindingRead(BaseModel):
    """Serialized finding payload."""

    id: str
    title: str
    description: str
    severity: str
    category: str
    tool_name: str
    file_path: str | None = None
    line_number: int | None = None
    remediation: str | None = None
    raw_payload: dict
    created_at: datetime


class ToolExecutionRead(BaseModel):
    """Serialized tool execution payload."""

    id: str
    tool_name: str
    status: str
    command: str | None = None
    error_message: str | None = None


class ProjectSummaryRead(BaseModel):
    """Compact project payload for API responses."""

    id: str
    name: str


class AISummaryRead(BaseModel):
    """Compact AI summary payload for scan APIs."""

    status: str
    summary_available: bool
    management_summary: str | None = None
    error: str | None = None


class PolicyRuleRead(BaseModel):
    """Stable policy rule evaluation entry for CI and reports."""

    rule_id: str
    outcome: Literal["passed", "failed", "warned", "skipped"]
    triggered: bool
    reason: str


class PolicyEvaluationRead(BaseModel):
    """Stable scan policy evaluation payload."""

    status: Literal["pass", "fail", "warn", "pending"]
    decision_ready: bool
    should_fail_ci: bool
    comparison_available: bool = False
    reasons: list[str] = Field(default_factory=list)
    rules: list[PolicyRuleRead] = Field(default_factory=list)
    config: dict = Field(default_factory=dict)
    metrics: dict = Field(default_factory=dict)


class GroupedFindingRead(BaseModel):
    """Stable grouped finding payload for reports and APIs."""

    group_key: str
    title: str
    description: str
    severity: str
    category: str
    tool_name: str
    file_path: str | None = None
    dependency_name: str | None = None
    remediation: str | None = None
    representative_finding_id: str | None = None
    member_count: int
    member_ids: list[str] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)
    sample_members: list[dict] = Field(default_factory=list)
    finding_type: str | None = None
    security_relevance: str | None = None
    impact_summary: str | None = None
    plain_explanation: str | None = None
    why_flagged: str | None = None
    app_impact: str | None = None
    why_severity: str | None = None
    recommended_action: str | None = None
    reference_title: str | None = None
    reference_type: str | None = None
    reference_url: str | None = None


class SeverityDeltaRead(BaseModel):
    """Stable severity delta payload for scan comparison responses."""

    previous: int = 0
    current: int = 0
    delta: int = 0


class GroupedComparisonRead(BaseModel):
    """Stable grouped comparison entry for scan regressions."""

    status: Literal["new", "resolved", "unchanged"]
    group_key: str
    title: str
    description: str
    severity: str
    category: str
    tool_name: str
    file_path: str | None = None
    dependency_name: str | None = None
    remediation: str | None = None
    representative_finding_id: str | None = None
    previous_member_count: int = 0
    current_member_count: int = 0
    delta_member_count: int = 0
    affected_files: list[str] = Field(default_factory=list)
    member_ids: list[str] = Field(default_factory=list)
    sample_members: list[dict] = Field(default_factory=list)


class ScanComparisonRead(BaseModel):
    """Stable scan-to-scan comparison payload."""

    comparison_available: bool = True
    message: str | None = None
    project: ProjectSummaryRead | None = None
    current_scan_id: str | None = None
    previous_scan_id: str | None = None
    trend: str | None = None
    summary: dict = Field(default_factory=dict)
    severity_deltas: dict[str, SeverityDeltaRead] = Field(default_factory=dict)
    grouped_delta: dict = Field(default_factory=dict)
    new_groups: list[GroupedComparisonRead] = Field(default_factory=list)
    resolved_groups: list[GroupedComparisonRead] = Field(default_factory=list)
    unchanged_groups: list[GroupedComparisonRead] = Field(default_factory=list)


class ProjectTrendPointRead(BaseModel):
    """Stable per-scan trend point for project-level history views."""

    scan_id: str
    created_at: datetime | None = None
    status: str
    source_type: str
    source_label: str | None = None
    total_findings: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    weighted_risk_score: int = 0
    policy_status: str = "pending"
    comparison_available: bool = False
    comparison_trend: str | None = None
    new_group_count: int | None = None
    resolved_group_count: int | None = None
    unchanged_group_count: int | None = None
    weighted_risk_delta: int | None = None


class ProjectTrendSummaryRead(BaseModel):
    """Stable project-level trend summary for UI and API responses."""

    project: ProjectSummaryRead
    effective_policy: dict = Field(default_factory=dict)
    total_scans: int = 0
    comparison_points: int = 0
    latest_weighted_risk_score: int | None = None
    latest_policy_status: str | None = None
    latest_severity_counts: dict[str, int] = Field(default_factory=dict)
    policy_counts: dict[str, int] = Field(default_factory=dict)
    message: str | None = None
    points: list[ProjectTrendPointRead] = Field(default_factory=list)


class ScanApiSummaryRead(BaseModel):
    """Stable JSON payload for external API clients."""

    scan_id: str
    status: str
    partial: bool
    project: ProjectSummaryRead
    source_type: str
    source_label: str | None = None
    total_findings: int
    ecosystems: list[str] = Field(default_factory=list)
    ecosystem_summary: list[dict] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    framework_summary: list[dict] = Field(default_factory=list)
    severity_counts: dict[str, int]
    tool_summary: dict
    grouped_finding_count: int = 0
    repeated_group_count: int = 0
    grouped_findings: list[GroupedFindingRead] = Field(default_factory=list)
    ai_summary: AISummaryRead
    policy: PolicyEvaluationRead
    report_urls: dict[str, str]
    created_at: datetime | None = None
    queued_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: int | None = None
