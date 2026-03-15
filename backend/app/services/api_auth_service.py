"""Token-based authentication helpers for external API and webhook access."""

from __future__ import annotations

from secrets import compare_digest

from fastapi import Header, HTTPException, Request

from backend.app.core.config import get_settings

settings = get_settings()


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(" ", maxsplit=1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


def require_api_token(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_token: str | None = Header(default=None),
) -> str:
    """Require a configured service token for JSON API access."""
    tokens = settings.api_tokens
    if not tokens:
        raise HTTPException(status_code=503, detail="API token authentication is not configured.")
    candidate = _extract_bearer_token(authorization) or (x_api_token.strip() if x_api_token else None)
    if not candidate:
        raise HTTPException(status_code=401, detail="API token required.")
    for valid_token in tokens:
        if compare_digest(candidate, valid_token):
            request.state.api_token_authenticated = True
            return candidate
    raise HTTPException(status_code=401, detail="Invalid API token.")


def require_webhook_token(
    x_webhook_token: str | None = Header(default=None),
    x_gitlab_token: str | None = Header(default=None),
) -> str:
    """Require a shared secret for webhook intake."""
    expected = settings.webhook_shared_secret.strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Webhook shared secret is not configured.")
    candidate = (x_webhook_token or x_gitlab_token or "").strip()
    if not candidate or not compare_digest(candidate, expected):
        raise HTTPException(status_code=401, detail="Invalid webhook token.")
    return candidate
