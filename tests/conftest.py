"""Shared pytest fixtures for isolated database-backed app tests."""

from collections.abc import Generator
import re

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.config import get_settings
from backend.app.core.database import get_db
from backend.app.main import app
from backend.app.models.base import Base
from backend.app.services.auth_service import AuthService
from backend.app.services.job_runner import InProcessJobRunner, reset_job_runner


@pytest.fixture()
def isolated_app(tmp_path, monkeypatch) -> Generator:
    """Provide a TestClient-ready app with isolated storage and database settings."""
    settings = get_settings()
    monkeypatch.setattr(settings, "scan_upload_dir_name", str(tmp_path / "uploads"))
    monkeypatch.setattr(settings, "scan_workspace_dir_name", str(tmp_path / "workspaces"))
    monkeypatch.setattr(settings, "report_output_dir_name", str(tmp_path / "reports" / "generated"))
    monkeypatch.setattr(settings, "allow_archive_uploads", True)
    monkeypatch.setattr(settings, "allow_local_path_scans", True)
    monkeypatch.setattr("backend.app.main.init_db", lambda: None)

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, class_=Session)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        runner = reset_job_runner(
            lambda: InProcessJobRunner(session_factory=TestingSessionLocal, poll_interval_seconds=1)
        )
        yield app, TestingSessionLocal, runner
    finally:
        reset_job_runner()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def create_user(isolated_app):
    """Create a local user in the isolated test database."""
    _, session_factory, _ = isolated_app

    def _create(
        username: str,
        password: str = "Password123!",
        *,
        role: str = "admin",
    ) -> tuple[str, str]:
        session = session_factory()
        try:
            AuthService(session).create_local_user(username, password, role=role)
        finally:
            session.close()
        return username, password

    return _create


@pytest.fixture()
def create_admin_user(isolated_app):
    """Create an admin user in the isolated test database."""
    _, session_factory, _ = isolated_app

    def _create(username: str = "admin", password: str = "Password123!") -> tuple[str, str]:
        session = session_factory()
        try:
            AuthService(session).create_admin_user(username, password)
        finally:
            session.close()
        return username, password

    return _create


@pytest.fixture()
def extract_csrf_token():
    """Extract a CSRF token from rendered HTML."""

    def _extract(html: str) -> str:
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        if not match:
            raise AssertionError("CSRF token not found in HTML")
        return match.group(1)

    return _extract
