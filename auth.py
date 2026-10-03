"""Verify real callers against the gateway before any model or administrative tool."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx2


class AccessDenied(Exception):
    """The caller is not a verified LiteLLM proxy administrator."""


class AuthorizationUnavailable(Exception):
    """Identity could not be verified; fail closed without exposing upstream details."""


class EnterpriseRequired(AccessDenied):
    """The gateway does not report a LiteLLM Enterprise license."""

    message = "LiteLLM Admin Agent requires a LiteLLM Enterprise license on your gateway. Contact LiteLLM to enable Enterprise, then try again."


@dataclass(frozen=True)
class Principal:
    user_id: str
    email: str
    source: str
    external_id: str

    @property
    def actor(self) -> str:
        return f"{self.source}:{self.external_id}:{self.user_id}"


class AdminAuthorizer:
    LICENSE_TTL = 3600

    def __init__(self, base_url: str, workspace: str, client: Any):
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("The trusted gateway must be an HTTPS URL without embedded credentials")
        self.base_url = base_url.rstrip("/")
        self.workspace = workspace
        self.client = client
        self._enterprise_until = 0.0

    async def _get(self, path: str, key: str, params: dict | None = None) -> dict:
        try:
            response = await self.client.get(
                self.base_url + path, params=params,
                headers={"Authorization": "Bearer " + key},
                timeout=15, follow_redirects=False,
            )
            if response.status_code in (401, 403):
                raise AccessDenied()
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Unexpected identity response")
            return data
        except AccessDenied:
            raise
        except Exception:
            raise AuthorizationUnavailable() from None

    @staticmethod
    def _admin(record: Any) -> dict:
        if not isinstance(record, dict) or record.get("user_role") != "proxy_admin":
            raise AccessDenied()
        if not isinstance(record.get("user_id"), str) or not record["user_id"]:
            raise AccessDenied()
        if record.get("blocked") or record.get("deleted") or record.get("is_active") is False:
            raise AccessDenied()
        return record

    async def require_gateway_admin(self, bearer: str) -> Principal:
        if not bearer or len(bearer) > 8192 or any(c.isspace() for c in bearer):
            raise AccessDenied()
        # This request authenticates the supplied credential; no caller-provided user ID
        # or role header is trusted. Never substitute the service's admin key here.
        data = await self._get("/user/info", bearer)
        user = self._admin(data.get("user_info"))
        if data.get("user_id") != user["user_id"]:
            raise AccessDenied()
        await self._require_enterprise(bearer)
        return Principal(user["user_id"], str(user.get("user_email") or ""), "gateway", user["user_id"])

    async def _require_enterprise(self, bearer: str) -> None:
        # The license is gateway-wide; only a confirmed Enterprise answer is cached.
        if time.monotonic() < self._enterprise_until:
            return
        if (await self._get("/health/license", bearer)).get("license_type") != "enterprise":
            raise EnterpriseRequired()
        self._enterprise_until = time.monotonic() + self.LICENSE_TTL

    async def slack_email(self, slack_user: str, slack: Any) -> str:
        try:
            response = await slack.users_info(user=slack_user)
            user = response.get("user")
            if not response.get("ok") or not isinstance(user, dict):
                raise AuthorizationUnavailable()
        except (AccessDenied, AuthorizationUnavailable):
            raise
        except Exception:
            raise AuthorizationUnavailable() from None
        if (user.get("id") != slack_user or user.get("team_id") != self.workspace
                or user.get("deleted") or user.get("is_bot") or user.get("is_app_user")
                or user.get("is_restricted") or user.get("is_ultra_restricted")
                or user.get("is_stranger")):
            raise AccessDenied()
        profile = user.get("profile") or {}
        email = profile.get("email")
        if not isinstance(email, str) or not email.strip():
            raise AccessDenied()
        email = email.strip().casefold()
        return email

    async def require_slack_admin(self, slack_user: str, slack: Any, bearer: str) -> Principal:
        email = await self.slack_email(slack_user, slack)
        account = await self.require_gateway_admin(bearer)
        if not account.email.strip() or account.email.strip().casefold() != email:
            raise AccessDenied()
        return Principal(account.user_id, email, "slack", slack_user)
