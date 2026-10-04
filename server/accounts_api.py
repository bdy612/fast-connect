"""
Client for the Fast Connect accounts backend (Website/backend/Code.gs on Google Apps Script).

The app never touches Google Drive or Gemini itself: logging in, signing up, friends lists,
chat tickets and FastAI all go through this API. The session token is kept in memory only.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

_DIR = os.path.dirname(os.path.abspath(__file__))
_TIMEOUT = 40

_session = {"token": None, "user": None}


def _find_url():
    """The backend URL: environment, then api_url.txt (shipped builds), then the website's config.js."""
    url = os.environ.get("FASTCONNECT_API_URL", "").strip()
    if not url:
        for folder in (_DIR, getattr(sys, "_MEIPASS", _DIR)):
            path = os.path.join(folder, "api_url.txt")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    url = f.read().strip()
                break
    if not url:
        config = os.path.join(_DIR, "..", "Website", "config.js")
        if os.path.exists(config):
            with open(config, "r", encoding="utf-8") as f:
                match = re.search(r"ACCOUNTS_API_URL\s*=\s*'([^']*)'", f.read())
            url = match.group(1).strip() if match else ""
    # Passwords travel over this connection, so it must be https
    # (or the local test server, Website/backend/dev_server.js)
    return url if re.match(r"^(https://|http://(localhost|127\.0\.0\.1)(:\d+)?/)", url) else ""


API_URL = _find_url()


def call(action, timeout=_TIMEOUT, **fields):
    """POST one request to the backend. Always returns a dict with 'ok'."""
    if not API_URL:
        return {"ok": False, "error": "Accounts are not set up yet. You can still continue as a guest."}
    body = json.dumps({"action": action, **fields}).encode("utf-8")
    request = urllib.request.Request(
        API_URL, data=body, headers={"Content-Type": "text/plain;charset=utf-8"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
        if not isinstance(result, dict):
            raise ValueError("unexpected reply")
        return result
    except (urllib.error.URLError, OSError, ValueError):
        return {"ok": False, "error": "Could not reach the Fast Connect server. Check your internet connection."}


def _start_session(result):
    if result.get("ok"):
        _session["token"] = result.get("token")
        _session["user"] = result.get("user")
    return result


def login(username, password):
    return _start_session(call("login", username=username, password=password))


def signup(username, real_name, password):
    return _start_session(call("signup", username=username, real_name=real_name, password=password))


def logout():
    _session["token"] = None
    _session["user"] = None


def is_logged_in():
    return _session["token"] is not None


def current_user():
    """{'username', 'real_name', 'user_number'} of the logged-in account, or None."""
    return _session["user"]


def delete_account(password):
    result = call("deleteAccount", token=_session["token"], password=password)
    if result.get("ok"):
        logout()
    return result


def add_friend(friend):
    """Record our side of a friendship; it counts once the friend has added us too."""
    return call("friendAdd", token=_session["token"], friend=friend)


def chat_ticket(binding):
    """One-time proof of identity for a chat server, tied to one encrypted connection."""
    return call("chatTicket", token=_session["token"], bind=binding)


def ai(kind, model, contents):
    """Ask FastAI through the backend, which holds the Gemini key and the per-account daily limit."""
    if not is_logged_in():
        return {"ok": False, "error": "Log in to your Fast Connect account to use FastAI."}
    return call("ai", timeout=300, token=_session["token"], kind=kind, model=model, contents=contents)


def verify_ticket(ticket):
    """Used by chat servers: who does this ticket belong to?"""
    return call("verifyTicket", ticket=ticket)


def default_server():
    """The official online chat server (host, port) from server_address.txt, or this computer."""
    for folder in (_DIR, getattr(sys, "_MEIPASS", _DIR)):
        path = os.path.join(folder, "server_address.txt")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                text = f.read().strip()
            host, _, port = text.rpartition(":")
            if host and port.isdigit():
                return host, int(port)
    return "127.0.0.1", 9999
