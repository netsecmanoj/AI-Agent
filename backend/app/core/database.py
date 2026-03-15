"""Database engine and session management."""

from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.config import get_settings
from backend.app.models.base import Base

settings = get_settings()
engine = create_engine(
    settings.database_url,
    connect_args=settings.database_connect_args,
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, class_=Session)


def init_db() -> None:
    """Initialize directories and database tables."""
    settings.scan_upload_dir.mkdir(parents=True, exist_ok=True)
    settings.scan_workspace_dir.mkdir(parents=True, exist_ok=True)
    settings.report_output_dir.mkdir(parents=True, exist_ok=True)
    (settings.report_output_dir.parent).mkdir(parents=True, exist_ok=True)
    settings.static_dir.mkdir(parents=True, exist_ok=True)
    sqlite_path = settings.sqlite_database_path
    if sqlite_path is not None:
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    if sqlite_path is not None:
        _ensure_sqlite_schema()


def _ensure_sqlite_schema() -> None:
    """Apply additive SQLite schema updates needed for the evolving MVP."""
    inspector = inspect(engine)
    if "scan_jobs" not in inspector.get_table_names():
        return

    existing_columns = {column["name"] for column in inspector.get_columns("scan_jobs")}
    additive_columns = {
        "source_filename": "ALTER TABLE scan_jobs ADD COLUMN source_filename TEXT",
        "workspace_path": "ALTER TABLE scan_jobs ADD COLUMN workspace_path TEXT",
        "source_label": "ALTER TABLE scan_jobs ADD COLUMN source_label TEXT",
        "duration_seconds": "ALTER TABLE scan_jobs ADD COLUMN duration_seconds INTEGER",
        "queued_at": "ALTER TABLE scan_jobs ADD COLUMN queued_at TIMESTAMP",
        "worker_error": "ALTER TABLE scan_jobs ADD COLUMN worker_error TEXT",
        "retry_count": "ALTER TABLE scan_jobs ADD COLUMN retry_count INTEGER DEFAULT 0",
        "ai_status": "ALTER TABLE scan_jobs ADD COLUMN ai_status TEXT DEFAULT 'pending'",
        "ai_summary": "ALTER TABLE scan_jobs ADD COLUMN ai_summary TEXT",
        "ai_top_risks": "ALTER TABLE scan_jobs ADD COLUMN ai_top_risks TEXT",
        "ai_next_steps": "ALTER TABLE scan_jobs ADD COLUMN ai_next_steps TEXT",
        "ai_error": "ALTER TABLE scan_jobs ADD COLUMN ai_error TEXT",
    }
    project_columns = {
        "description": "ALTER TABLE projects ADD COLUMN description TEXT",
        "policy_preset": "ALTER TABLE projects ADD COLUMN policy_preset TEXT",
        "policy_fail_severity_threshold": "ALTER TABLE projects ADD COLUMN policy_fail_severity_threshold TEXT",
        "policy_max_new_high_findings": "ALTER TABLE projects ADD COLUMN policy_max_new_high_findings INTEGER",
        "policy_max_weighted_risk_delta": "ALTER TABLE projects ADD COLUMN policy_max_weighted_risk_delta INTEGER",
        "policy_warn_on_partial_scan": "ALTER TABLE projects ADD COLUMN policy_warn_on_partial_scan INTEGER",
        "policy_warn_on_any_high_findings": "ALTER TABLE projects ADD COLUMN policy_warn_on_any_high_findings INTEGER",
    }
    user_columns = {
        "auth_provider": "ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'local'",
        "external_subject": "ALTER TABLE users ADD COLUMN external_subject TEXT",
        "email": "ALTER TABLE users ADD COLUMN email TEXT",
        "display_name": "ALTER TABLE users ADD COLUMN display_name TEXT",
    }
    finding_columns = {
        "ai_status": "ALTER TABLE findings ADD COLUMN ai_status TEXT DEFAULT 'pending'",
        "ai_explanation": "ALTER TABLE findings ADD COLUMN ai_explanation TEXT",
        "ai_remediation": "ALTER TABLE findings ADD COLUMN ai_remediation TEXT",
        "ai_error": "ALTER TABLE findings ADD COLUMN ai_error TEXT",
    }
    with engine.begin() as connection:
        for column_name, ddl in additive_columns.items():
            if column_name not in existing_columns:
                connection.execute(text(ddl))
        if "projects" in inspector.get_table_names():
            existing_project_columns = {column["name"] for column in inspector.get_columns("projects")}
            for column_name, ddl in project_columns.items():
                if column_name not in existing_project_columns:
                    connection.execute(text(ddl))
        if "users" in inspector.get_table_names():
            existing_user_columns = {column["name"] for column in inspector.get_columns("users")}
            for column_name, ddl in user_columns.items():
                if column_name not in existing_user_columns:
                    connection.execute(text(ddl))
        if "findings" in inspector.get_table_names():
            existing_finding_columns = {column["name"] for column in inspector.get_columns("findings")}
            for column_name, ddl in finding_columns.items():
                if column_name not in existing_finding_columns:
                    connection.execute(text(ddl))


def get_db() -> Generator[Session, None, None]:
    """Yield a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
