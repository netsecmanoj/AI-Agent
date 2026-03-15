"""In-process scan job runner with a small internal queue abstraction."""

from __future__ import annotations

import logging
from queue import Empty, Queue
from threading import Event, Lock, Thread
from typing import Callable
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.config import get_settings
from backend.app.core.database import SessionLocal
from backend.app.models.base import utcnow
from backend.app.models.scan import ScanJob
from backend.app.services.cleanup_service import CleanupService
from backend.app.services.scan_service import ScanService

settings = get_settings()
logger = logging.getLogger(__name__)


class InProcessJobRunner:
    """Run queued scan jobs on a background thread inside the app process."""

    def __init__(
        self,
        session_factory: sessionmaker = SessionLocal,
        poll_interval_seconds: int | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.poll_interval_seconds = poll_interval_seconds or settings.job_poll_interval_seconds
        self.queue: Queue[str] = Queue()
        self.stop_event = Event()
        self.thread: Thread | None = None
        self.lock = Lock()
        self.enqueued_ids: set[str] = set()
        self.last_activity_at = None
        self.last_cleanup_at = None
        self.last_cleanup_summary: dict[str, object] | None = None
        self._next_cleanup_at = None

    def start(self) -> None:
        """Start the worker thread if it is not already running."""
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        now = utcnow()
        self.last_activity_at = now
        self._next_cleanup_at = now
        self.thread = Thread(target=self._run_loop, name="scan-job-runner", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        """Stop the worker thread cleanly."""
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=max(self.poll_interval_seconds * 2, 2))
        self.thread = None

    def enqueue(self, scan_job_id: str) -> bool:
        """Queue a scan once and avoid duplicate enqueues."""
        with self.lock:
            if scan_job_id in self.enqueued_ids:
                return False
            self.enqueued_ids.add(scan_job_id)
        self.queue.put(scan_job_id)
        self.last_activity_at = utcnow()
        return True

    def recover_jobs(self) -> list[str]:
        """Mark interrupted running jobs and re-enqueue queued jobs on startup."""
        queued_ids: list[str] = []
        with self.session_factory() as db:
            running_jobs = (
                db.execute(select(ScanJob).where(ScanJob.status == "running")).scalars().all()
            )
            for scan_job in running_jobs:
                scan_job.status = "failed"
                scan_job.worker_error = "Worker interrupted during application restart."
                scan_job.error_message = "Scan execution was interrupted and needs to be retried."
                scan_job.finished_at = utcnow()
                scan_job.duration_seconds = ScanService.calculate_duration_seconds(
                    scan_job.started_at,
                    scan_job.finished_at,
                )
            queued_ids = [job.id for job in db.execute(select(ScanJob).where(ScanJob.status == "queued")).scalars().all()]
            db.commit()
        for scan_job_id in queued_ids:
            self.enqueue(scan_job_id)
        return queued_ids

    def run_cleanup_once(self) -> dict[str, object]:
        """Execute one cleanup pass and store a public summary."""
        with self.session_factory() as db:
            summary = CleanupService(db).run_cleanup()
        self.last_cleanup_at = utcnow()
        self.last_cleanup_summary = summary.as_dict()
        return self.last_cleanup_summary

    def status_snapshot(self) -> dict[str, object]:
        """Return worker and cleanup visibility for UI/API use."""
        storage_counts: dict[str, int] = {}
        with self.session_factory() as db:
            storage_counts = CleanupService(db).storage_counts()
        return {
            "running": bool(self.thread and self.thread.is_alive() and not self.stop_event.is_set()),
            "queue_depth": self.queue.qsize(),
            "last_activity_at": self.last_activity_at.isoformat() if self.last_activity_at else None,
            "last_cleanup_at": self.last_cleanup_at.isoformat() if self.last_cleanup_at else None,
            "cleanup_interval_seconds": settings.cleanup_interval_seconds,
            "cleanup_on_startup": settings.cleanup_on_startup,
            "retention_days": {
                "uploads": settings.upload_retention_days,
                "workspaces": settings.workspace_retention_days,
                "reports": settings.report_retention_days,
            },
            "storage_counts": storage_counts,
            "last_cleanup_summary": self.last_cleanup_summary,
        }

    def _run_loop(self) -> None:
        while not self.stop_event.is_set():
            self._maybe_run_cleanup()
            try:
                scan_job_id = self.queue.get(timeout=self.poll_interval_seconds)
            except Empty:
                continue

            try:
                self.last_activity_at = utcnow()
                self._process(scan_job_id)
            finally:
                with self.lock:
                    self.enqueued_ids.discard(scan_job_id)
                self.queue.task_done()
                self.last_activity_at = utcnow()

    def _process(self, scan_job_id: str) -> None:
        with self.session_factory() as db:
            scan_service = ScanService(db=db)
            try:
                scan_service.execute_scan_job(scan_job_id)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Scan job failed inside worker", extra={"scan_job_id": scan_job_id})
                scan_service.fail_scan_job(scan_job_id, f"Worker execution failed: {exc}")

    def _maybe_run_cleanup(self) -> None:
        now = utcnow()
        if self._next_cleanup_at is None:
            self._next_cleanup_at = now
        if now < self._next_cleanup_at:
            return
        self.run_cleanup_once()
        self._next_cleanup_at = now + timedelta(seconds=settings.cleanup_interval_seconds)


_job_runner: InProcessJobRunner | None = None


def get_job_runner() -> InProcessJobRunner:
    """Return the process-wide in-process job runner."""
    global _job_runner
    if _job_runner is None:
        _job_runner = InProcessJobRunner()
    return _job_runner


def reset_job_runner(factory: Callable[[], InProcessJobRunner] | None = None) -> InProcessJobRunner:
    """Reset the global runner, primarily for tests."""
    global _job_runner
    if _job_runner is not None:
        _job_runner.stop()
    _job_runner = factory() if factory else InProcessJobRunner()
    return _job_runner
