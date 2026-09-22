"""Verify real callers against the gateway before any model or administrative tool."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx2


class AccessDenied(Exception):
    """The caller is not a verified LiteLLM proxy administrator."""


class AuthorizationUnavailable(Exception):
    """Identity could not be verified; fail closed without exposing upstream details."""


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
    def __init__(self, base_url: str, admin_key: str, workspace: str, client: Any):
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("The trusted gateway must be an HTTPS URL without embedded credentials")
        self.base_url = base_url.rstrip("/")
        self.admin_key = admin_key
        self.workspace = workspace
        self.client = client

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
        return Principal(user["user_id"], str(user.get("user_email") or ""), "gateway", user["user_id"])

    async def require_slack_admin(self, slack_user: str, slack: Any) -> Principal:
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
        # /user/list performs partial matching. Require exactly one *exact* email
        # match over all bounded pages, then refresh that record by immutable ID.
        records = []
        for page in range(1, 6):
            data = await self._get("/user/list", self.admin_key,
                                   {"user_email": email, "page": page, "page_size": 100})
            rows = data.get("users")
            total_pages = data.get("total_pages")
            if not isinstance(rows, list) or not isinstance(total_pages, int) or not 0 <= total_pages <= 5:
                raise AuthorizationUnavailable()
            records.extend(r for r in rows if isinstance(r, dict)
                           and str(r.get("user_email") or "").strip().casefold() == email)
            if page >= total_pages:
                break
        if len(records) != 1 or not isinstance(records[0].get("user_id"), str):
            raise AccessDenied()
        user_id = records[0]["user_id"]
        data = await self._get("/user/info", self.admin_key, {"user_id": user_id})
        account = self._admin(data.get("user_info"))
        if account["user_id"] != user_id or str(account.get("user_email") or "").strip().casefold() != email:
            raise AccessDenied()
        return Principal(user_id, email, "slack", slack_user)
