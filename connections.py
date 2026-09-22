"""Slack-bound SSO connections and encrypted personal session credentials."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import json
import logging
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from aiohttp import web
from cryptography.fernet import Fernet, InvalidToken

from auth import AccessDenied, AuthorizationUnavailable
from sso import OAuthFlow, SignInExpired


class ConnectionRequired(Exception):
    pass


@dataclass(frozen=True)
class Connection:
    user_id: str
    version: str
    credential: str = field(repr=False)
    expires_at: float | None = None


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ConnectionStore:
    def __init__(self, db, encryption_key: str):
        self.db = db
        self.cipher = Fernet(encryption_key.encode())
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS connections (
                owner TEXT PRIMARY KEY, encrypted BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS connection_links (
                token_hash TEXT PRIMARY KEY, owner TEXT NOT NULL UNIQUE,
                expires REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS connection_sso (
                token_hash TEXT PRIMARY KEY, encrypted BLOB NOT NULL
            );
        """)

    def issue(self, owner: str) -> str:
        token = secrets.token_urlsafe(32)
        with self.db:
            self.db.execute("DELETE FROM connection_links WHERE owner=? OR expires<?", (owner, time.time()))
            self.db.execute("INSERT INTO connection_links VALUES(?,?,?)", (digest(token), owner, time.time() + 600))
            self._prune_sso()
        return token

    def _prune_sso(self):
        self.db.execute("DELETE FROM connection_sso WHERE token_hash NOT IN (SELECT token_hash FROM connection_links WHERE expires>?)", (time.time(),))

    def owner(self, token: str, consume=False) -> str:
        if not 40 <= len(token) <= 100:
            raise ConnectionRequired()
        with self.db:
            row = self.db.execute("SELECT owner FROM connection_links WHERE token_hash=? AND expires>?",
                                  (digest(token), time.time())).fetchone()
            if row and consume:
                self.db.execute("DELETE FROM connection_links WHERE token_hash=?", (digest(token),))
                self.db.execute("DELETE FROM connection_sso WHERE token_hash=?", (digest(token),))
        if not row:
            raise ConnectionRequired()
        return row[0]

    def save(self, owner: str, user_id: str, credential: str, expires_at=None) -> None:
        with self.db:
            self._save(owner, user_id, credential, expires_at)

    def _save(self, owner: str, user_id: str, credential: str, expires_at=None) -> None:
        payload = {"owner": owner, "user_id": user_id, "version": secrets.token_urlsafe(24), "credential": credential, "expires_at": expires_at}
        encrypted = self.cipher.encrypt(json.dumps(payload).encode())
        self.db.execute("INSERT OR REPLACE INTO connections VALUES(?,?)", (owner, encrypted))

    def pending(self, token: str) -> dict | None:
        owner = self.owner(token)
        row = self.db.execute("SELECT encrypted FROM connection_sso WHERE token_hash=?", (digest(token),)).fetchone()
        if not row:
            return None
        try:
            data = json.loads(self.cipher.decrypt(row[0], ttl=600))
            if data["owner"] != owner or data["link"] != digest(token):
                raise ValueError()
            if data["flow"]["expires_at"] <= time.time() or "code_verifier" not in data["flow"]:
                raise ValueError()
            return data
        except (InvalidToken, ValueError, KeyError, TypeError):
            raise ConnectionRequired() from None

    def save_pending(self, token: str, csrf: str, flow: OAuthFlow):
        owner = self.owner(token)  # Check again after any awaited gateway request.
        payload = {"owner": owner, "link": digest(token), "csrf": csrf,
                   "flow": asdict(flow)}
        encrypted = self.cipher.encrypt(json.dumps(payload).encode())
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO connection_sso VALUES(?,?)", (digest(token), encrypted))

    def finish(self, token: str, owner: str, user_id: str, credential: str, expires_at=None):
        # No await between the final link check and transaction: disconnect or
        # a newer connect link must invalidate an in-flight login as well.
        if self.owner(token) != owner:
            raise ConnectionRequired()
        with self.db:
            self._save(owner, user_id, credential, expires_at)
            self.db.execute("DELETE FROM connection_links WHERE token_hash=?", (digest(token),))
            self.db.execute("DELETE FROM connection_sso WHERE token_hash=?", (digest(token),))

    def get(self, owner: str) -> Connection:
        row = self.db.execute("SELECT encrypted FROM connections WHERE owner=?", (owner,)).fetchone()
        if not row:
            raise ConnectionRequired()
        try:
            data = json.loads(self.cipher.decrypt(row[0]))
            if data["owner"] != owner:
                raise ValueError()
            expires = data.get("expires_at")
            if expires is not None and expires <= time.time():
                raise ConnectionRequired()
            return Connection(data["user_id"], data["version"], data["credential"], expires)
        except (InvalidToken, ValueError, KeyError, TypeError):
            raise ConnectionRequired() from None

    def disconnect(self, owner: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM connections WHERE owner=?", (owner,))
            self.db.execute("DELETE FROM connection_links WHERE owner=?", (owner,))
            self._prune_sso()


PAGE_HEADERS = {
    # no-referrer makes browsers serialize Origin as "null" on form POSTs.
    # same-origin preserves our CSRF origin check without sending the private
    # connection URL as a referrer to another site.
    "Cache-Control": "no-store", "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
}
COOKIE = "__Host-litellm-connect"
OAUTH_COOKIE = "__Host-litellm-oauth"


def page(title: str, body: str, status=200):
    return web.Response(content_type="text/html", status=status, headers=PAGE_HEADERS, text=f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>body{{font:17px system-ui;max-width:520px;margin:10vh auto;padding:24px;color:#18252f}}
input,select,button,.button{{font:inherit;padding:12px;box-sizing:border-box;width:100%;margin:12px 0}}button,.button{{display:block;text-align:center;text-decoration:none;background:#185c48;color:white;border:0;border-radius:6px;cursor:pointer}}p{{line-height:1.6}}small{{color:#556}}code{{font-size:28px;letter-spacing:3px}}</style>
<main id="connection"><h1>{html.escape(title)}</h1>{body}</main>
<script src="/connect.js" defer></script></html>""")


class Connections:
    def __init__(self, settings, store: ConnectionStore, authorizer, slack, sso):
        self.settings = settings
        self.store = store
        self.authorizer = authorizer
        self.slack = slack
        self.sso = sso
        self._locks = [asyncio.Lock() for _ in range(64)]

    def owner(self, slack_user):
        return self.settings.workspace + ":" + slack_user

    def get(self, slack_user):
        return self.store.get(self.owner(slack_user))

    def disconnect(self, slack_user):
        self.store.disconnect(self.owner(slack_user))

    async def link(self, slack_user):
        await self.authorizer.slack_email(slack_user, self.slack)
        token = self.store.issue(self.owner(slack_user))
        return self.settings.public_url + "/connect/" + token

    def add_routes(self, app):
        app.router.add_get("/connect.js", self.script)
        if self.settings.connection_auth_mode == "sso":
            app.router.add_get("/oauth/callback", self.callback)
        app.router.add_get("/connect/{token}", self.show)
        app.router.add_post("/connect/{token}", self.connect)

    async def script(self, request):
        return web.Response(content_type="application/javascript",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
            text=Path(__file__).with_name("connect.js").read_text())

    async def show(self, request):
        token = request.match_info["token"]
        try:
            self.store.owner(token)
            pending = self.store.pending(token)
            if pending:
                browser = self._browser_cookie(request, token)
                if not hmac.compare_digest(browser["csrf"], pending["csrf"]):
                    raise AccessDenied()
                csrf = browser["csrf"]
            else:
                csrf = secrets.token_urlsafe(32)
        except ConnectionRequired:
            return self._expired()
        except AccessDenied:
            return self._browser_error()
        cookie = self.store.cipher.encrypt(json.dumps({"link": digest(token), "csrf": csrf}).encode()).decode()
        result = page("Connect your LiteLLM account", f"""<p>Sign in through your LiteLLM gateway using the same email as Slack. Your account must be a LiteLLM proxy admin.</p>
<p>LiteLLM will ask you to approve this app, then return you here automatically. Model requests and admin actions will use your own account.</p>
<form method="post"><input type="hidden" name="csrf" value="{csrf}">
<button type="submit" name="action" value="start">Continue with LiteLLM SSO</button></form>
<small>No API key or terminal code needed. Your session is encrypted before it is saved. Send “disconnect” in Slack to remove it, or “connect” when you need to sign in again.</small>""")
        if self.settings.connection_auth_mode == "api_key":
            result = page("Connect your LiteLLM account", f"""<p>Enter a personal LiteLLM virtual key belonging to your own proxy-admin account. Your gateway account email must match your Slack email.</p>
<p>Model usage and admin actions use this key. Do not use the gateway master key or someone else’s key. Never paste a key into Slack.</p>
<form method="post"><input type="hidden" name="csrf" value="{csrf}">
<label for="credential">Personal gateway key</label><input id="credential" name="credential" type="password" required maxlength="8192" autocomplete="off" spellcheck="false">
<button type="submit" name="action" value="connect_key">Connect account</button></form>
<small>Your key is encrypted before storage. This connection expires in 24 hours. Send “disconnect” in Slack to remove it; revoke the key in LiteLLM to invalidate the key itself.</small>""")
        result.set_cookie(COOKIE, cookie, secure=True, httponly=True, samesite="Strict", max_age=600, path="/")
        return result

    def _browser_cookie(self, request, token):
        try:
            cookie = json.loads(self.store.cipher.decrypt(request.cookies.get(COOKIE, "").encode(), ttl=600))
            if not hmac.compare_digest(cookie["link"], digest(token)) or not isinstance(cookie["csrf"], str):
                raise AccessDenied()
            return cookie
        except (InvalidToken, ValueError, KeyError, TypeError):
            raise AccessDenied() from None

    def _browser_error(self):
        return page("Please reopen your connection link", "<p>Your browser session couldn’t be verified. Send <strong>connect</strong> in Slack for a new private link and use the same browser throughout sign-in.</p>", 403)

    def _expired(self):
        return page("Link expired or already used", "<p>Send <strong>connect</strong> to LiteLLM Admin in Slack for a new private link.</p>", 410)

    def _failure(self, exc):
        if isinstance(exc, (ConnectionRequired, SignInExpired)):
            return self._expired()
        if isinstance(exc, AuthorizationUnavailable):
            logging.warning("Account connection rejected (authorization_unavailable)")
            return page("Couldn’t verify access", "<p>The gateway or Slack is temporarily unavailable. Send <strong>connect</strong> in Slack for a new link and try again.</p>", 503)
        logging.warning("Account connection rejected (gateway_account)")
        return page("Couldn’t connect this account", "<p>Sign in to an active LiteLLM proxy-admin account with the same email as Slack. Send <strong>connect</strong> in Slack for a new link.</p>", 403)

    async def connect(self, request):
        try:
            if request.headers.get("Origin") != self.settings.public_url or request.content_type != "application/x-www-form-urlencoded":
                raise AccessDenied()
            form = await request.post()
            token = request.match_info["token"]
            cookie = self._browser_cookie(request, token)
            if not hmac.compare_digest(cookie["csrf"], str(form.get("csrf", ""))):
                raise AccessDenied()
        except (AccessDenied, InvalidToken, ValueError, KeyError, TypeError):
            return self._browser_error()
        expected_action = "connect_key" if self.settings.connection_auth_mode == "api_key" else "start"
        if form.get("action") != expected_action:
            return self._expired()
        async with self._locks[int(digest(token)[:8], 16) % len(self._locks)]:
            try:
                owner = self.store.owner(token)
                workspace, slack_user = owner.split(":", 1)
                if workspace != self.settings.workspace:
                    raise AccessDenied()
                if self.settings.connection_auth_mode == "api_key":
                    credential = str(form.get("credential", ""))
                    if (not 1 <= len(credential) <= 8192 or any(c.isspace() for c in credential)):
                        raise AccessDenied()
                    principal = await self.authorizer.require_slack_admin(slack_user, self.slack, credential)
                    self.store.finish(token, owner, principal.user_id, credential, time.time() + 86400)
                    return self._connected()
                pending = self.store.pending(token)
                if pending and not hmac.compare_digest(pending["csrf"], cookie["csrf"]):
                    return self._browser_error()
                if pending:
                    flow = OAuthFlow(**pending["flow"])
                else:
                    await self.authorizer.slack_email(slack_user, self.slack)
                    flow = await self.sso.start()
                    self.store.save_pending(token, cookie["csrf"], flow)
                url = html.escape(self.sso.sign_in_url(flow), quote=True)
                result = page("Opening LiteLLM sign-in", f'<p>Redirecting to your gateway’s sign-in page…</p><a class="button" data-oauth-redirect href="{url}">Continue to LiteLLM</a>')
                binding = self.store.cipher.encrypt(json.dumps({"token": token, "csrf": cookie["csrf"], "state": flow.state}).encode()).decode()
                result.set_cookie(OAUTH_COOKIE, binding, secure=True, httponly=True, samesite="Lax", max_age=600, path="/")
                return result
            except (AccessDenied, AuthorizationUnavailable, ConnectionRequired, SignInExpired) as exc:
                return self._failure(exc)

    async def callback(self, request):
        try:
            binding = json.loads(self.store.cipher.decrypt(request.cookies.get(OAUTH_COOKIE, "").encode(), ttl=600))
            if len(request.query.getall("state", [])) != 1 or not hmac.compare_digest(binding["state"], request.query["state"]):
                raise AccessDenied()
            token = binding["token"]
        except (AccessDenied, InvalidToken, ValueError, KeyError, TypeError):
            return self._browser_error()
        async with self._locks[int(digest(token)[:8], 16) % len(self._locks)]:
            try:
                owner = self.store.owner(token)
                workspace, slack_user = owner.split(":", 1)
                pending = self.store.pending(token)
                if (workspace != self.settings.workspace or not pending
                        or not hmac.compare_digest(pending["csrf"], binding["csrf"])
                        or not hmac.compare_digest(pending["flow"]["state"], binding["state"])):
                    raise AccessDenied()
                if "error" in request.query:
                    self.store.owner(token, consume=True)
                    return page("Connection cancelled", "<p>Your existing connection has not changed. Send <strong>connect</strong> in Slack when you want to sign in.</p>", 403)
                if len(request.query.getall("code", [])) != 1:
                    raise AccessDenied()
                signed_in = await self.sso.exchange(OAuthFlow(**pending["flow"]), request.query["code"])
                principal = await self.authorizer.require_slack_admin(slack_user, self.slack, signed_in.credential)
                if principal.user_id != signed_in.user_id:
                    raise AccessDenied()
                self.store.finish(token, owner, principal.user_id, signed_in.credential, signed_in.expires_at)
                return self._connected()
            except (AccessDenied, AuthorizationUnavailable, ConnectionRequired, SignInExpired) as exc:
                return self._failure(exc)

    def _connected(self):
        result = page("Account connected", "<p>Return to your private Slack conversation with LiteLLM Admin and send your request again.</p>")
        result.del_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="Strict")
        result.del_cookie(OAUTH_COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
        return result
