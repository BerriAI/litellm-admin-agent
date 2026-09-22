"""Private, one-use Slack account connection links and encrypted personal keys."""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import secrets
import time
from dataclasses import dataclass, field

from aiohttp import web
from cryptography.fernet import Fernet, InvalidToken

from auth import AccessDenied, AuthorizationUnavailable


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
        """)

    def issue(self, owner: str) -> str:
        token = secrets.token_urlsafe(32)
        with self.db:
            self.db.execute("DELETE FROM connection_links WHERE owner=? OR expires<?", (owner, time.time()))
            self.db.execute("INSERT INTO connection_links VALUES(?,?,?)", (digest(token), owner, time.time() + 600))
        return token

    def owner(self, token: str, consume=False) -> str:
        if not 40 <= len(token) <= 100:
            raise ConnectionRequired()
        with self.db:
            row = self.db.execute("SELECT owner FROM connection_links WHERE token_hash=? AND expires>?",
                                  (digest(token), time.time())).fetchone()
            if row and consume:
                self.db.execute("DELETE FROM connection_links WHERE token_hash=?", (digest(token),))
        if not row:
            raise ConnectionRequired()
        return row[0]

    def save(self, owner: str, user_id: str, credential: str) -> None:
        payload = {"owner": owner, "user_id": user_id, "version": secrets.token_urlsafe(24), "credential": credential}
        encrypted = self.cipher.encrypt(json.dumps(payload).encode())
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO connections VALUES(?,?)", (owner, encrypted))

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


PAGE_HEADERS = {
    # no-referrer makes browsers serialize Origin as "null" on form POSTs.
    # same-origin preserves our CSRF origin check without sending the private
    # connection URL as a referrer to another site.
    "Cache-Control": "no-store", "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
}
COOKIE = "__Host-litellm-connect"


def page(title: str, body: str, status=200):
    return web.Response(content_type="text/html", status=status, headers=PAGE_HEADERS, text=f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>body{{font:17px system-ui;max-width:520px;margin:10vh auto;padding:24px;color:#18252f}}
input,button{{font:inherit;padding:12px;box-sizing:border-box;width:100%;margin:12px 0}}button{{background:#185c48;color:white;border:0;border-radius:6px;cursor:pointer}}p{{line-height:1.6}}small{{color:#556}}</style>
<h1>{html.escape(title)}</h1>{body}</html>""")


class Connections:
    def __init__(self, settings, store: ConnectionStore, authorizer, slack):
        self.settings = settings
        self.store = store
        self.authorizer = authorizer
        self.slack = slack

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
        app.router.add_get("/connect/{token}", self.show)
        app.router.add_post("/connect/{token}", self.connect)

    async def show(self, request):
        token = request.match_info["token"]
        try:
            self.store.owner(token)
        except ConnectionRequired:
            return page("Link expired", "<p>Send <strong>connect</strong> to LiteLLM Admin in Slack for a new private link.</p>", 410)
        csrf = secrets.token_urlsafe(32)
        cookie = self.store.cipher.encrypt(json.dumps({"link": digest(token), "csrf": csrf}).encode()).decode()
        gateway = html.escape(self.settings.gateway_url + "/ui", quote=True)
        result = page("Connect your LiteLLM account", f"""<p>Use a personal admin key from <a href="{gateway}" target="_blank" rel="noreferrer">your LiteLLM gateway account</a>. Your gateway email must match your Slack email.</p>
<p>Requests, model access and admin actions will use your account’s permissions. Your key is encrypted before it is saved.</p>
<form method="post"><input type="hidden" name="csrf" value="{csrf}">
<label for="credential">Your personal LiteLLM key</label>
<input id="credential" name="credential" type="password" required maxlength="8192" autocomplete="off" spellcheck="false">
<button type="submit">Connect my account</button></form>
<small>Use your own key, not the gateway master key. Never paste it into Slack. Send “disconnect” in Slack to remove this connection. Expired or revoked keys must be reconnected.</small>""")
        result.set_cookie(COOKIE, cookie, secure=True, httponly=True, samesite="Strict", max_age=600, path="/")
        return result

    async def connect(self, request):
        # Validate the browser before consuming the link or checking credentials.
        # Session errors must not tell the user their gateway key is wrong.
        try:
            if request.headers.get("Origin") != self.settings.public_url or request.content_type != "application/x-www-form-urlencoded":
                raise AccessDenied()
            form = await request.post()
            cookie = json.loads(self.store.cipher.decrypt(request.cookies.get(COOKIE, "").encode(), ttl=600))
            token = request.match_info["token"]
            if (not hmac.compare_digest(cookie["link"], digest(token))
                    or not hmac.compare_digest(cookie["csrf"], str(form.get("csrf", "")))):
                raise AccessDenied()
        except (AccessDenied, InvalidToken, ValueError, KeyError, TypeError):
            logging.warning("Account connection rejected (browser_session)")
            return page("Please reopen your connection link", "<p>Your browser session couldn’t be verified. Open the <strong>Connect account</strong> link from Slack again and submit the form in the same browser tab.</p>", 403)
        try:
            owner = self.store.owner(token, consume=True)
            workspace, slack_user = owner.split(":", 1)
            if workspace != self.settings.workspace:
                raise AccessDenied()
            credential = str(form.get("credential", "")).strip()
            principal = await self.authorizer.require_slack_admin(slack_user, self.slack, credential)
            self.store.save(owner, principal.user_id, credential)
            result = page("Account connected", "<p>Return to your private Slack conversation with LiteLLM Admin and send your request again.</p>")
            result.del_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="Strict")
            return result
        except AuthorizationUnavailable:
            logging.warning("Account connection rejected (authorization_unavailable)")
            return page("Couldn’t verify access", "<p>The gateway or Slack is temporarily unavailable. Send <strong>connect</strong> in Slack for a new link and try again.</p>", 503)
        except ConnectionRequired:
            logging.warning("Account connection rejected (expired_or_used_link)")
            return page("Link expired or already used", "<p>Send <strong>connect</strong> to LiteLLM Admin in Slack for a new private link.</p>", 410)
        except AccessDenied:
            logging.warning("Account connection rejected (gateway_account)")
            return page("Couldn’t connect this account", "<p>Use your own active LiteLLM proxy-admin key with the same email as Slack. Send <strong>connect</strong> in Slack for a new link.</p>", 403)
