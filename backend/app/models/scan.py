"""Scan job, tool execution, and finding models."""

from datetime import datetime
from uuid import uuid4

from sqlalchemy import ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin, utcnow


class ScanJob(TimestampMixin, Base):
    """Represents one execution of the configured scanners."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    status: Mapped[str] = mapped_column(String(64), default="queued", index=True)
    source_type: Mapped[str] = mapped_column(String(64))
    source_value: Mapped[str] = mapped_column(String(2048))
    source_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    workspace_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    source_label: Mapped[str | None] = mapped_column(String(512), nullable=True)
    queued_at: Mapped[datetime | None] = mapped_column(nullable=True, default=utcnow)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    partial: Mapped[bool] = mapped_column(default=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    worker_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    ai_status: Mapped[str] = mapped_column(String(64), default="pending")
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_top_risks: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_next_steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)

    project = relationship("Project", back_populates="scan_jobs")
    findings = relationship("Finding", back_populates="scan_job", cascade="all, delete-orphan")
    tool_executions = relationship(
        "ToolExecution", back_populates="scan_job", cascade="all, delete-orphan"
    )
    reports = relationship("Report", back_populates="scan_job", cascade="all, delete-orphan")


class ToolExecution(TimestampMixin, Base):
    """Tracks each scanner tool execution inside a scan job."""

    __tablename__ = "tool_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(64), default="pending")
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_output_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan_job = relationship("ScanJob", back_populates="tool_executions")


class Finding(TimestampMixin, Base):
    """Normalized security finding emitted by any scanner."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    scan_job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(128), default="code")
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    file_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_status: Mapped[str] = mapped_column(String(64), default="pending")
    ai_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)

    scan_job = relationship("ScanJob", back_populates="findings")
