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
from sso import DeviceFlow, SignInExpired


class ConnectionRequired(Exception):
    pass


@dataclass(frozen=True)
class Connection:
    user_id: str
    version: str
    credential: str = field(repr=False)


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

    def save(self, owner: str, user_id: str, credential: str) -> None:
        with self.db:
            self._save(owner, user_id, credential)

    def _save(self, owner: str, user_id: str, credential: str) -> None:
        payload = {"owner": owner, "user_id": user_id, "version": secrets.token_urlsafe(24), "credential": credential}
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
            if data["flow"]["expires_at"] <= time.time():
                raise ValueError()
            return data
        except (InvalidToken, ValueError, KeyError, TypeError):
            raise ConnectionRequired() from None

    def save_pending(self, token: str, csrf: str, flow: DeviceFlow, teams=(), user_id=""):
        owner = self.owner(token)  # Check again after any awaited gateway request.
        payload = {"owner": owner, "link": digest(token), "csrf": csrf,
                   "flow": asdict(flow), "teams": teams, "user_id": user_id}
        encrypted = self.cipher.encrypt(json.dumps(payload).encode())
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO connection_sso VALUES(?,?)", (digest(token), encrypted))

    def finish(self, token: str, owner: str, user_id: str, credential: str):
        # No await between the final link check and transaction: disconnect or
        # a newer connect link must invalidate an in-flight login as well.
        if self.owner(token) != owner:
            raise ConnectionRequired()
        with self.db:
            self._save(owner, user_id, credential)
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
            return Connection(data["user_id"], data["version"], data["credential"])
        except (InvalidToken, ValueError, KeyError):
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
        # Bounded locks serialize one-use polls on this single-instance service.
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
        app.router.add_get("/connect/{token}", self.show)
        app.router.add_post("/connect/{token}", self.connect)

    async def script(self, request):
        return web.Response(content_type="application/javascript",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
            text=Path(__file__).with_name("connect.js").read_text())

    async def show(self, request):
        token = request.match_info["token"]
        try:
            pending = self.store.pending(token)
            if pending:
                cookie = self._browser_cookie(request, token)
                if not hmac.compare_digest(cookie["csrf"], pending["csrf"]):
                    raise AccessDenied()
                return self._pending_page(pending)
        except ConnectionRequired:
            return page("Link expired", "<p>Send <strong>connect</strong> to LiteLLM Admin in Slack for a new private link.</p>", 410)
        except AccessDenied:
            return self._browser_error()
        csrf = secrets.token_urlsafe(32)
        cookie = self.store.cipher.encrypt(json.dumps({"link": digest(token), "csrf": csrf}).encode()).decode()
        result = page("Connect your LiteLLM account", f"""<p>Sign in with your BerriAI account through LiteLLM SSO. Your gateway email must match your Slack email, and your account must be a LiteLLM proxy admin.</p>
<p>You’ll confirm a short verification code on the gateway. Model requests and admin actions will use your own account. Your session is encrypted before it is saved.</p>
<form method="post" data-sso-action="start"><input type="hidden" name="csrf" value="{csrf}">
<button type="submit" name="action" value="start">Continue with LiteLLM SSO</button></form>
<small>No API key needed. Send “disconnect” in Slack to remove the saved session. When your session expires, send “connect” to sign in again.</small>""")
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
        return page("Please reopen your connection link", "<p>Your browser session couldn’t be verified. Use the same browser tab where you started signing in, or send <strong>connect</strong> in Slack for a new private link.</p>", 403)

    def _pending_page(self, pending, *, waiting=False):
        csrf = html.escape(pending["csrf"], quote=True)
        if pending["teams"]:
            options = "".join(f'<option value="{html.escape(t, quote=True)}">{html.escape(alias)} ({html.escape(t)})</option>'
                              for t, alias in pending["teams"])
            return page("Choose your LiteLLM team", f"""<p>Choose the team to use for model access and usage attribution. Your current gateway admin permissions will still be verified.</p>
<form method="post" data-sso-action="team"><input type="hidden" name="csrf" value="{csrf}">
<label for="team_id">Your team</label><select id="team_id" name="team_id" required>{options}</select>
<button type="submit" name="action" value="check">Finish connecting</button></form>""")
        flow = DeviceFlow(**pending["flow"])
        url = html.escape(self.sso.sign_in_url(flow), quote=True)
        notice = "<p><strong>Still waiting for sign-in.</strong> Complete SSO and confirm the code in the gateway tab, then try again.</p>" if waiting else ""
        return page("Sign in to LiteLLM", f"""{notice}<p>Open LiteLLM below and sign in with the same email you use in Slack. When it asks for a verification code, enter:</p>
<p><code>{html.escape(flow.user_code)}</code></p>
<a class="button" data-sso-link href="{url}" target="_blank" rel="noopener noreferrer">Open LiteLLM SSO</a>
<p>SSO opens in a new tab using the sign-in provider configured on your gateway. This page will connect automatically after you confirm the code. If asked, return here to choose your team.</p>
<form method="post" data-sso-action="check"><input type="hidden" name="csrf" value="{csrf}">
<button type="submit" name="action" value="check">I’ve signed in — finish connecting</button></form>
<small>This sign-in expires after 10 minutes. Only enter this code on your LiteLLM gateway.</small>""")

    async def connect(self, request):
        # All starts, polls, team choices, and credential saves require this
        # browser binding. Even possession of the private URL is insufficient.
        try:
            if request.headers.get("Origin") != self.settings.public_url or request.content_type != "application/x-www-form-urlencoded":
                raise AccessDenied()
            form = await request.post()
            token = request.match_info["token"]
            cookie = self._browser_cookie(request, token)
            if not hmac.compare_digest(cookie["csrf"], str(form.get("csrf", ""))):
                raise AccessDenied()
        except (AccessDenied, InvalidToken, ValueError, KeyError, TypeError):
            logging.warning("Account connection rejected (browser_session)")
            return self._browser_error()
        async with self._locks[int(digest(token)[:8], 16) % len(self._locks)]:
            return await self._connect(token, cookie["csrf"], form)

    async def _connect(self, token, csrf, form):
        try:
            owner = self.store.owner(token)
            workspace, slack_user = owner.split(":", 1)
            if workspace != self.settings.workspace:
                raise AccessDenied()
            pending = self.store.pending(token)
            if pending and not hmac.compare_digest(pending["csrf"], csrf):
                return self._browser_error()
            action = form.get("action")
            if action == "start":
                if not pending:
                    await self.authorizer.slack_email(slack_user, self.slack)
                    flow = await self.sso.start()
                    self.store.save_pending(token, csrf, flow)
                    pending = self.store.pending(token)
                return self._pending_page(pending)
            if action != "check" or not pending:
                return page("Start with LiteLLM SSO", "<p>Reopen your connection link and choose <strong>Continue with LiteLLM SSO</strong>.</p>", 400)
            team_id = form.get("team_id")
            if team_id is not None and team_id not in {t[0] for t in pending["teams"]}:
                raise AccessDenied()
            if pending["teams"] and not team_id:
                return self._pending_page(pending)
            flow = DeviceFlow(**pending["flow"])
            result = await self.sso.poll(flow, team_id)
            if pending["user_id"] and result.user_id and pending["user_id"] != result.user_id:
                raise AccessDenied()
            if result.teams:
                self.store.save_pending(token, csrf, flow, result.teams, result.user_id)
                return self._pending_page(self.store.pending(token))
            if not result.credential:
                return self._pending_page(pending, waiting=True)
            principal = await self.authorizer.require_slack_admin(slack_user, self.slack, result.credential)
            if principal.user_id != result.user_id:
                raise AccessDenied()
            self.store.finish(token, owner, principal.user_id, result.credential)
            result = page("Account connected", "<p>Return to your private Slack conversation with LiteLLM Admin and send your request again.</p>")
            result.del_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="Strict")
            return result
        except AuthorizationUnavailable:
            logging.warning("Account connection rejected (authorization_unavailable)")
            return page("Couldn’t verify access", "<p>The gateway or Slack is temporarily unavailable. Send <strong>connect</strong> in Slack for a new link and try again.</p>", 503)
        except (ConnectionRequired, SignInExpired):
            logging.warning("Account connection rejected (expired_or_used_link)")
            return page("Link expired or already used", "<p>Send <strong>connect</strong> to LiteLLM Admin in Slack for a new private link.</p>", 410)
        except AccessDenied:
            logging.warning("Account connection rejected (gateway_account)")
            return page("Couldn’t connect this account", "<p>Sign in to an active LiteLLM proxy-admin account with the same email as Slack. Send <strong>connect</strong> in Slack for a new link.</p>", 403)
