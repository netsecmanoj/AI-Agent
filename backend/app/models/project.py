"""Project model for grouping repeated scans of the same codebase."""

from uuid import uuid4

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin


class Project(TimestampMixin, Base):
    """A scanned project or repository."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_type: Mapped[str] = mapped_column(String(64))
    source_value: Mapped[str] = mapped_column(String(2048))
    policy_preset: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_fail_severity_threshold: Mapped[str | None] = mapped_column(String(32), nullable=True)
    policy_max_new_high_findings: Mapped[int | None] = mapped_column(Integer, nullable=True)
    policy_max_weighted_risk_delta: Mapped[int | None] = mapped_column(Integer, nullable=True)
    policy_warn_on_partial_scan: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    policy_warn_on_any_high_findings: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    scan_jobs = relationship("ScanJob", back_populates="project", cascade="all, delete-orphan")
