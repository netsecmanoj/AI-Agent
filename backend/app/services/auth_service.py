"""Authentication, session, CSRF, and RBAC helpers for the server-rendered UI."""

from __future__ import annotations

import secrets
from secrets import compare_digest
from urllib.parse import quote

from fastapi import HTTPException, Request
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.models.user import User

password_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
ROLE_ADMIN = "admin"
ROLE_REVIEWER = "reviewer"
ROLE_VIEWER = "viewer"
VALID_ROLES = {ROLE_ADMIN, ROLE_REVIEWER, ROLE_VIEWER}


class AuthService:
    """Authenticate and manage local or OIDC-backed users."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_user_by_id(self, user_id: str) -> User | None:
        """Fetch a user by primary key."""
        return self.db.get(User, user_id)

    def get_user_by_username(self, username: str) -> User | None:
        """Fetch a user by unique username."""
        return self.db.execute(select(User).where(User.username == username)).scalars().first()

    def get_user_by_external_identity(self, provider: str, subject: str) -> User | None:
        """Fetch a user by external auth provider and subject."""
        return (
            self.db.execute(
                select(User).where(
                    User.auth_provider == provider,
                    User.external_subject == subject,
                )
            )
            .scalars()
            .first()
        )

    def create_admin_user(self, username: str, password: str) -> User:
        """Create a local admin user with a securely hashed password."""
        return self.create_local_user(username=username, password=password, role=ROLE_ADMIN)

    def create_local_user(self, username: str, password: str, role: str = ROLE_ADMIN) -> User:
        """Create a local user with a securely hashed password."""
        if role not in VALID_ROLES:
            raise ValueError(f"Unsupported role: {role}")
        if self.get_user_by_username(username):
            raise ValueError(f"User already exists: {username}")
        user = User(
            username=username,
            password_hash=self.hash_password(password),
            role=role,
            auth_provider="local",
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def authenticate(self, username: str, password: str) -> User | None:
        """Authenticate a local user by username and password."""
        user = self.get_user_by_username(username)
        if user is None:
            return None
        if user.auth_provider != "local":
            return None
        if not self.verify_password(password, user.password_hash):
            return None
        return user

    def provision_oidc_user(self, claims: dict, *, provider: str = "oidc") -> User:
        """Provision or update a user from OIDC claims."""
        subject = str(claims.get("sub") or "").strip()
        if not subject:
            raise ValueError("OIDC claims did not include a subject.")
        role = map_role_from_claims(claims)
        username = self._resolve_username_from_claims(claims, subject)
        email = self._claim_value(claims, get_settings().oidc_email_claim)
        display_name = self._claim_value(claims, get_settings().oidc_name_claim) or username

        user = self.get_user_by_external_identity(provider, subject)
        if user is None:
            user = self.get_user_by_username(username)
        if user is None:
            user = User(
                username=username,
                password_hash="",
                role=role,
                auth_provider=provider,
                external_subject=subject,
                email=email,
                display_name=display_name,
            )
            self.db.add(user)
        else:
            user.username = username
            user.role = role
            user.auth_provider = provider
            user.external_subject = subject
            user.email = email
            user.display_name = display_name
        self.db.commit()
        self.db.refresh(user)
        return user

    def list_users(self) -> list[User]:
        """Return all users ordered for admin browsing."""
        return self.db.execute(select(User).order_by(User.created_at.asc())).scalars().all()

    def update_user_role(self, user_id: str, role: str) -> User:
        """Update a user's role while preserving at least one admin."""
        if role not in VALID_ROLES:
            raise ValueError(f"Unsupported role: {role}")
        user = self.get_user_by_id(user_id)
        if user is None:
            raise ValueError("User not found.")
        if user.role == ROLE_ADMIN and role != ROLE_ADMIN:
            admin_count = self.db.execute(select(User).where(User.role == ROLE_ADMIN)).scalars().all()
            if len(admin_count) <= 1:
                raise ValueError("At least one admin user must remain.")
        user.role = role
        self.db.commit()
        self.db.refresh(user)
        return user

    @staticmethod
    def _claim_value(claims: dict, claim_name: str) -> str | None:
        value = claims.get(claim_name)
        if value is None:
            return None
        return str(value).strip() or None

    def _resolve_username_from_claims(self, claims: dict, subject: str) -> str:
        settings = get_settings()
        preferred = self._claim_value(claims, settings.oidc_username_claim)
        email = self._claim_value(claims, settings.oidc_email_claim)
        base_username = preferred or (email.split("@", 1)[0] if email and "@" in email else None) or f"oidc-{subject}"
        base_username = base_username.strip()
        existing = self.get_user_by_username(base_username)
        if existing is None or existing.external_subject == subject:
            return base_username
        suffix = 2
        candidate = f"{base_username}-{suffix}"
        while self.get_user_by_username(candidate) is not None:
            suffix += 1
            candidate = f"{base_username}-{suffix}"
        return candidate

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a plaintext password securely."""
        return password_context.hash(password)

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify a plaintext password against a stored hash."""
        return password_context.verify(password, password_hash)


def map_role_from_claims(claims: dict) -> str:
    """Map OIDC claims into a local role using configurable group lists."""
    settings = get_settings()
    claim_value = claims.get(settings.oidc_role_claim)
    groups: list[str] = []
    if isinstance(claim_value, list):
        groups = [str(item).strip() for item in claim_value if str(item).strip()]
    elif isinstance(claim_value, str):
        groups = [part.strip() for part in claim_value.split(",") if part.strip()]

    if groups and any(group in settings.oidc_admin_groups for group in groups):
        return ROLE_ADMIN
    if groups and any(group in settings.oidc_reviewer_groups for group in groups):
        return ROLE_REVIEWER
    if groups and any(group in settings.oidc_viewer_groups for group in groups):
        return ROLE_VIEWER

    default_role = settings.oidc_default_role.strip().lower() or ROLE_VIEWER
    return default_role if default_role in VALID_ROLES else ROLE_VIEWER


def ensure_csrf_token(request: Request) -> str:
    """Return the request session CSRF token, creating one if necessary."""
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def validate_csrf_token(request: Request, submitted_token: str | None) -> None:
    """Reject state-changing form submissions with an invalid CSRF token."""
    session_token = ensure_csrf_token(request)
    if not submitted_token or not compare_digest(submitted_token, session_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def require_authenticated_user(request: Request, db: Session) -> User:
    """Require any authenticated session for protected routes."""
    user_id = request.session.get("user_id")
    if not user_id:
        location = f"/login?next={quote(str(request.url.path))}"
        raise HTTPException(status_code=303, headers={"Location": location}, detail="Authentication required")
    user = AuthService(db).get_user_by_id(user_id)
    if user is None:
        request.session.clear()
        location = f"/login?next={quote(str(request.url.path))}"
        raise HTTPException(status_code=303, headers={"Location": location}, detail="Authentication required")
    request.state.current_user = user
    return user


def require_user_with_roles(request: Request, db: Session, allowed_roles: set[str]) -> User:
    """Require an authenticated user whose role matches one of the allowed roles."""
    user = require_authenticated_user(request, db)
    if user.role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Insufficient role for this action.")
    return user


def require_viewer_user(request: Request, db: Session) -> User:
    """Require viewer-or-higher access."""
    return require_user_with_roles(request, db, {ROLE_VIEWER, ROLE_REVIEWER, ROLE_ADMIN})


def require_reviewer_user(request: Request, db: Session) -> User:
    """Require reviewer-or-admin access."""
    return require_user_with_roles(request, db, {ROLE_REVIEWER, ROLE_ADMIN})


def require_admin_user(request: Request, db: Session) -> User:
    """Require admin access."""
    return require_user_with_roles(request, db, {ROLE_ADMIN})


def user_can_submit_scans(user: User) -> bool:
    """Return whether the user can submit new scans."""
    return user.role in {ROLE_ADMIN, ROLE_REVIEWER}


def user_can_manage_projects(user: User) -> bool:
    """Return whether the user can create or edit projects."""
    return user.role == ROLE_ADMIN
