"""HTTP hardening for a localhost-only app.

A web page you visit can fire requests at http://127.0.0.1:5000 from your own browser, and DNS
rebinding can even make a hostile site look "same origin". These hooks close those doors:

* Host header allow-list ........ defeats DNS rebinding
* per-run CSRF token (header) ... a foreign site can neither read nor guess it
* Origin check .................. extra defence for browsers that send Origin
* strict CSP + other headers .... a second layer against XSS, clickjacking and caching of secrets
* rate limiter .................. scrypt is deliberately slow, so protect it from request floods
"""
from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from urllib.parse import urlsplit

from flask import Flask, jsonify, request

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class RateLimiter:
    """Tiny sliding-window limiter (single process is enough for a local tool)."""

    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > window:
                hits.popleft()
            if len(hits) >= limit:
                return False, max(1, int(window - (now - hits[0])) + 1)
            hits.append(now)
            return True, 0


def install_security(app: Flask, allowed_hosts: set[str], csrf_token: str) -> RateLimiter:
    limiter = RateLimiter()

    @app.before_request
    def guard():
        host = (urlsplit("//" + request.host).hostname or "").lower()
        if host not in allowed_hosts:
            return jsonify(error="Invalid Host header."), 400
        if request.method in UNSAFE_METHODS:
            origin = request.headers.get("Origin")
            if origin and urlsplit(origin).netloc.lower() != request.host.lower():
                return jsonify(error="Cross-origin request blocked."), 403
            supplied = request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(supplied.encode(), csrf_token.encode()):
                return jsonify(error="Missing or invalid security token. Reload the page and try again."), 403
        return None

    @app.after_request
    def harden(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.path.startswith("/api/") or request.path == "/":
            response.headers["Cache-Control"] = "no-store"
        return response

    return limiter


def rate_limited(limiter: RateLimiter, name: str, limit: int, window: float = 60.0):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            ok, retry = limiter.allow(f"{name}:{request.remote_addr}", limit, window)
            if not ok:
                response = jsonify(error="Too many requests. Slow down and try again shortly.")
                response.status_code = 429
                response.headers["Retry-After"] = str(retry)
                return response
            return view(*args, **kwargs)
        return wrapper
    return decorator
