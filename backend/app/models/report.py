"""Report model for downloadable JSON and HTML outputs."""

from uuid import uuid4

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin


class Report(TimestampMixin, Base):
    """Generated scan report metadata."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    report_format: Mapped[str] = mapped_column(String(16), index=True)
    path: Mapped[str] = mapped_column(String(2048))

    scan_job = relationship("ScanJob", back_populates="reports")

