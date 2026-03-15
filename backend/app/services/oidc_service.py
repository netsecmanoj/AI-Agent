"""Minimal OIDC helpers for session-based SSO login."""

from __future__ import annotations

import secrets
from secrets import compare_digest
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import Request

from backend.app.core.config import get_settings


class OIDCService:
    """Handle OIDC discovery, redirects, token exchange, and userinfo lookup."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def is_enabled(self) -> bool:
        """Return whether OIDC login is configured enough to be used."""
        return bool(
            self.settings.oidc_enabled
            and self.settings.oidc_issuer_url
            and self.settings.oidc_client_id
            and self.settings.oidc_client_secret
        )

    def build_authorization_redirect(self, request: Request, next_path: str | None = None) -> str:
        """Build the provider authorization URL and persist state in the session."""
        if not self.is_enabled():
            raise ValueError("OIDC login is not enabled.")
        discovery = self.fetch_discovery_document()
        authorization_endpoint = discovery.get("authorization_endpoint")
        if not authorization_endpoint:
            raise ValueError("OIDC provider discovery did not return an authorization endpoint.")
        state = secrets.token_urlsafe(24)
        request.session["oidc_state"] = state
        request.session["oidc_next"] = next_path or "/"
        params = {
            "response_type": "code",
            "client_id": self.settings.oidc_client_id,
            "redirect_uri": str(request.url_for("oidc_callback")),
            "scope": " ".join(self.settings.oidc_scopes_list),
            "state": state,
        }
        return f"{authorization_endpoint}?{urlencode(params)}"

    def authenticate_callback(self, request: Request, *, code: str, state: str) -> dict[str, Any]:
        """Validate callback state, exchange the code, and fetch user claims."""
        if not self.is_enabled():
            raise ValueError("OIDC login is not enabled.")
        expected_state = request.session.get("oidc_state")
        if not expected_state or not compare_digest(expected_state, state):
            raise ValueError("OIDC state validation failed.")
        request.session.pop("oidc_state", None)
        tokens = self.exchange_code_for_tokens(request, code=code)
        access_token = tokens.get("access_token")
        if not access_token:
            raise ValueError("OIDC token response did not include an access token.")
        claims = self.fetch_userinfo(access_token)
        if not claims.get("sub"):
            raise ValueError("OIDC userinfo did not include a subject claim.")
        return claims

    def consume_next_path(self, request: Request) -> str:
        """Return the stored post-login path and clear it from the session."""
        return request.session.pop("oidc_next", "/") or "/"

    def fetch_discovery_document(self) -> dict[str, Any]:
        """Fetch the provider discovery document."""
        discovery_url = self.settings.oidc_issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        response = httpx.get(discovery_url, timeout=10.0)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("OIDC discovery document was not valid JSON.")
        return payload

    def exchange_code_for_tokens(self, request: Request, *, code: str) -> dict[str, Any]:
        """Exchange an authorization code for tokens."""
        discovery = self.fetch_discovery_document()
        token_endpoint = discovery.get("token_endpoint")
        if not token_endpoint:
            raise ValueError("OIDC provider discovery did not return a token endpoint.")
        response = httpx.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": str(request.url_for("oidc_callback")),
                "client_id": self.settings.oidc_client_id,
                "client_secret": self.settings.oidc_client_secret,
            },
            timeout=10.0,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("OIDC token response was not valid JSON.")
        return payload

    def fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        """Fetch normalized userinfo claims from the provider."""
        discovery = self.fetch_discovery_document()
        userinfo_endpoint = discovery.get("userinfo_endpoint")
        if not userinfo_endpoint:
            raise ValueError("OIDC provider discovery did not return a userinfo endpoint.")
        response = httpx.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10.0,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("OIDC userinfo response was not valid JSON.")
        return payload
