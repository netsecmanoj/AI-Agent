"""Application configuration sourced from environment variables."""

from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    """Runtime configuration for the FastAPI application."""

    app_name: str = Field(default="Internal Security Audit Platform", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    secret_key: str = Field(default="change-this-in-production", alias="SECRET_KEY")
    session_cookie_secure: bool = Field(default=False, alias="SESSION_COOKIE_SECURE")
    session_max_age_seconds: int = Field(default=28800, alias="SESSION_MAX_AGE_SECONDS")
    oidc_enabled: bool = Field(default=False, alias="OIDC_ENABLED")
    oidc_issuer_url: str = Field(default="", alias="OIDC_ISSUER_URL")
    oidc_client_id: str = Field(default="", alias="OIDC_CLIENT_ID")
    oidc_client_secret: str = Field(default="", alias="OIDC_CLIENT_SECRET")
    oidc_scopes: str = Field(default="openid profile email", alias="OIDC_SCOPES")
    oidc_role_claim: str = Field(default="groups", alias="OIDC_ROLE_CLAIM")
    oidc_default_role: str = Field(default="viewer", alias="OIDC_DEFAULT_ROLE")
    oidc_admin_groups_raw: str = Field(default="", alias="OIDC_ADMIN_GROUPS")
    oidc_reviewer_groups_raw: str = Field(default="", alias="OIDC_REVIEWER_GROUPS")
    oidc_viewer_groups_raw: str = Field(default="", alias="OIDC_VIEWER_GROUPS")
    oidc_username_claim: str = Field(default="preferred_username", alias="OIDC_USERNAME_CLAIM")
    oidc_email_claim: str = Field(default="email", alias="OIDC_EMAIL_CLAIM")
    oidc_name_claim: str = Field(default="name", alias="OIDC_NAME_CLAIM")
    database_url: str = Field(default="sqlite:///./db/security_audit.db", alias="DATABASE_URL")
    allow_local_path_scans: bool = Field(default=True, alias="ALLOW_LOCAL_PATH_SCANS")
    allow_archive_uploads: bool = Field(default=True, alias="ALLOW_ARCHIVE_UPLOADS")
    scan_upload_dir_name: str = Field(default="uploads", alias="SCAN_UPLOAD_DIR")
    scan_workspace_dir_name: str = Field(default="workspaces", alias="SCAN_WORKSPACE_DIR")
    report_output_dir_name: str = Field(default="reports/generated", alias="REPORT_OUTPUT_DIR")
    semgrep_command: str = Field(default="semgrep", alias="SEMGREP_COMMAND")
    semgrep_config: str = Field(default="auto", alias="SEMGREP_CONFIG")
    semgrep_timeout_seconds: int = Field(default=300, alias="SEMGREP_TIMEOUT_SECONDS")
    trivy_command: str = Field(default="trivy", alias="TRIVY_COMMAND")
    trivy_timeout_seconds: int = Field(default=300, alias="TRIVY_TIMEOUT_SECONDS")
    pip_audit_command: str = Field(default="pip-audit", alias="PIP_AUDIT_COMMAND")
    pip_audit_timeout_seconds: int = Field(default=300, alias="PIP_AUDIT_TIMEOUT_SECONDS")
    npm_command: str = Field(default="npm", alias="NPM_COMMAND")
    npm_audit_timeout_seconds: int = Field(default=300, alias="NPM_AUDIT_TIMEOUT_SECONDS")
    flutter_command: str = Field(default="flutter", alias="FLUTTER_COMMAND")
    dart_command: str = Field(default="dart", alias="DART_COMMAND")
    dart_analyze_timeout_seconds: int = Field(default=300, alias="DART_ANALYZE_TIMEOUT_SECONDS")
    dart_pub_outdated_timeout_seconds: int = Field(default=300, alias="DART_PUB_OUTDATED_TIMEOUT_SECONDS")
    job_poll_interval_seconds: int = Field(default=1, alias="JOB_POLL_INTERVAL_SECONDS")
    ai_enabled: bool = Field(default=False, alias="AI_ENABLED")
    ai_provider: str = Field(default="disabled", alias="AI_PROVIDER")
    ai_model: str = Field(default="llama3.1:8b", alias="AI_MODEL")
    ai_base_url: str = Field(default="http://127.0.0.1:11434/v1", alias="AI_BASE_URL")
    ai_api_key: str = Field(default="", alias="AI_API_KEY")
    ai_timeout_seconds: int = Field(default=30, alias="AI_TIMEOUT_SECONDS")
    api_tokens_raw: str = Field(default="", alias="API_TOKENS")
    allow_api_local_path_scans: bool = Field(default=False, alias="ALLOW_API_LOCAL_PATH_SCANS")
    webhook_shared_secret: str = Field(default="", alias="WEBHOOK_SHARED_SECRET")
    ci_default_fail_severity: str = Field(default="", alias="CI_DEFAULT_FAIL_SEVERITY")
    policy_fail_on_new_critical: bool = Field(default=True, alias="POLICY_FAIL_ON_NEW_CRITICAL")
    policy_max_new_high_findings: int = Field(default=0, alias="POLICY_MAX_NEW_HIGH_FINDINGS")
    policy_max_weighted_risk_delta: int = Field(default=5, alias="POLICY_MAX_WEIGHTED_RISK_DELTA")
    policy_warn_on_any_high_findings: bool = Field(default=True, alias="POLICY_WARN_ON_ANY_HIGH_FINDINGS")
    policy_warn_on_partial_scan: bool = Field(default=True, alias="POLICY_WARN_ON_PARTIAL_SCAN")
    upload_retention_days: int = Field(default=30, alias="UPLOAD_RETENTION_DAYS")
    workspace_retention_days: int = Field(default=30, alias="WORKSPACE_RETENTION_DAYS")
    report_retention_days: int = Field(default=30, alias="REPORT_RETENTION_DAYS")
    cleanup_interval_seconds: int = Field(default=3600, alias="CLEANUP_INTERVAL_SECONDS")
    cleanup_on_startup: bool = Field(default=True, alias="CLEANUP_ON_STARTUP")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    @property
    def templates_dir(self) -> Path:
        return BASE_DIR / "backend" / "app" / "templates"

    @property
    def static_dir(self) -> Path:
        return BASE_DIR / "backend" / "app" / "static"

    @property
    def scan_upload_dir(self) -> Path:
        return BASE_DIR / self.scan_upload_dir_name

    @property
    def report_output_dir(self) -> Path:
        return BASE_DIR / self.report_output_dir_name

    @property
    def scan_workspace_dir(self) -> Path:
        return BASE_DIR / self.scan_workspace_dir_name

    @property
    def database_connect_args(self) -> dict[str, bool]:
        if self.database_url.startswith("sqlite"):
            return {"check_same_thread": False}
        return {}

    @property
    def sqlite_database_path(self) -> Path | None:
        if not self.database_url.startswith("sqlite"):
            return None
        parsed = urlparse(self.database_url)
        raw_path = parsed.path or self.database_url.replace("sqlite:///", "", 1)
        if raw_path.startswith("/./"):
            raw_path = raw_path[1:]
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = BASE_DIR / candidate
        return candidate

    @property
    def api_tokens(self) -> list[str]:
        return [token.strip() for token in self.api_tokens_raw.split(",") if token.strip()]

    @property
    def oidc_scopes_list(self) -> list[str]:
        return [scope.strip() for scope in self.oidc_scopes.split() if scope.strip()]

    @property
    def oidc_admin_groups(self) -> list[str]:
        return [group.strip() for group in self.oidc_admin_groups_raw.split(",") if group.strip()]

    @property
    def oidc_reviewer_groups(self) -> list[str]:
        return [group.strip() for group in self.oidc_reviewer_groups_raw.split(",") if group.strip()]

    @property
    def oidc_viewer_groups(self) -> list[str]:
        return [group.strip() for group in self.oidc_viewer_groups_raw.split(",") if group.strip()]


@lru_cache
def get_settings() -> Settings:
    """Cache settings to avoid repeated environment parsing."""
    return Settings()
