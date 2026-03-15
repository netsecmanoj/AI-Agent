"""Retention and cleanup helpers for managed scan artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
import logging
from pathlib import Path
import shutil

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.models.base import utcnow
from backend.app.models.report import Report
from backend.app.models.scan import ScanJob

settings = get_settings()
logger = logging.getLogger(__name__)
ACTIVE_SCAN_STATUSES = {"queued", "running"}


@dataclass(slots=True)
class CleanupSummary:
    """Result of one cleanup pass."""

    ran_at: str
    uploads_deleted: int = 0
    workspaces_deleted: int = 0
    reports_deleted: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total_deleted(self) -> int:
        """Return total filesystem artifact count deleted in this pass."""
        return self.uploads_deleted + self.workspaces_deleted + self.reports_deleted

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe summary payload."""
        return {
            "ran_at": self.ran_at,
            "uploads_deleted": self.uploads_deleted,
            "workspaces_deleted": self.workspaces_deleted,
            "reports_deleted": self.reports_deleted,
            "total_deleted": self.total_deleted,
            "errors": self.errors,
        }


class CleanupService:
    """Delete expired managed artifacts conservatively and predictably."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def run_cleanup(self) -> CleanupSummary:
        """Delete expired report/upload/workspace artifacts for inactive scans."""
        now = utcnow()
        summary = CleanupSummary(ran_at=now.isoformat())
        scan_jobs = self._load_inactive_scans()
        report_cutoff = now - timedelta(days=settings.report_retention_days)
        upload_cutoff = now - timedelta(days=settings.upload_retention_days)
        workspace_cutoff = now - timedelta(days=settings.workspace_retention_days)

        for scan_job in scan_jobs:
            reference_time = scan_job.finished_at or scan_job.created_at
            if reference_time is None:
                continue

            if self._is_expired(reference_time, report_cutoff):
                for report in scan_job.reports:
                    if self._delete_file_if_managed(Path(report.path), settings.report_output_dir, summary.errors):
                        summary.reports_deleted += 1

            if scan_job.source_type == "uploaded_archive" and self._is_expired(reference_time, upload_cutoff):
                upload_dir = settings.scan_upload_dir / scan_job.id
                if self._delete_directory_if_managed(upload_dir, settings.scan_upload_dir, summary.errors):
                    summary.uploads_deleted += 1

            if scan_job.source_type == "uploaded_archive" and self._is_expired(reference_time, workspace_cutoff):
                workspace_dir = settings.scan_workspace_dir / scan_job.id
                if self._delete_directory_if_managed(workspace_dir, settings.scan_workspace_dir, summary.errors):
                    summary.workspaces_deleted += 1

        logger.info(
            "Cleanup pass completed",
            extra={
                "uploads_deleted": summary.uploads_deleted,
                "workspaces_deleted": summary.workspaces_deleted,
                "reports_deleted": summary.reports_deleted,
                "errors": len(summary.errors),
            },
        )
        return summary

    def storage_counts(self) -> dict[str, int]:
        """Return conservative filesystem artifact counts for managed directories."""
        return {
            "upload_directories": self._count_direct_children(settings.scan_upload_dir),
            "workspace_directories": self._count_direct_children(settings.scan_workspace_dir),
            "report_directories": self._count_direct_children(settings.report_output_dir),
        }

    def _load_inactive_scans(self) -> list[ScanJob]:
        return (
            self.db.execute(
                select(ScanJob)
                .where(ScanJob.status.not_in(ACTIVE_SCAN_STATUSES))
            )
            .scalars()
            .all()
        )

    def _delete_directory_if_managed(
        self,
        candidate: Path,
        allowed_root: Path,
        errors: list[str],
    ) -> bool:
        if not self._is_managed_path(candidate, allowed_root):
            errors.append(f"Skipped unmanaged directory path: {candidate.name}")
            return False
        if not candidate.exists():
            return False
        try:
            shutil.rmtree(candidate)
        except FileNotFoundError:
            return False
        except OSError as exc:
            errors.append(f"Failed to delete directory {candidate.name}: {exc}")
            return False
        return True

    def _delete_file_if_managed(
        self,
        candidate: Path,
        allowed_root: Path,
        errors: list[str],
    ) -> bool:
        if not self._is_managed_path(candidate, allowed_root):
            errors.append(f"Skipped unmanaged file path: {candidate.name}")
            return False
        if not candidate.exists():
            return False
        try:
            candidate.unlink(missing_ok=True)
        except OSError as exc:
            errors.append(f"Failed to delete file {candidate.name}: {exc}")
            return False
        return True

    @staticmethod
    def _count_direct_children(root: Path) -> int:
        if not root.exists():
            return 0
        return sum(1 for path in root.iterdir())

    @staticmethod
    def _is_managed_path(candidate: Path, allowed_root: Path) -> bool:
        try:
            candidate_resolved = candidate.resolve()
            root_resolved = allowed_root.resolve()
        except FileNotFoundError:
            candidate_resolved = candidate.expanduser().resolve(strict=False)
            root_resolved = allowed_root.expanduser().resolve(strict=False)
        if candidate_resolved == root_resolved:
            return False
        return candidate_resolved.is_relative_to(root_resolved)

    @staticmethod
    def _is_expired(reference_time, cutoff_time) -> bool:
        if reference_time.tzinfo is None and cutoff_time.tzinfo is not None:
            reference_time = reference_time.replace(tzinfo=cutoff_time.tzinfo)
        if cutoff_time.tzinfo is None and reference_time.tzinfo is not None:
            cutoff_time = cutoff_time.replace(tzinfo=reference_time.tzinfo)
        return reference_time <= cutoff_time
