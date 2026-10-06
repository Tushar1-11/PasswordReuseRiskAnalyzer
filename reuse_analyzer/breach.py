"""Optional breached-password lookup using the HIBP *k-anonymity* range API.

OFF by default - the tool is fully offline unless you opt in with PRA_BREACH_CHECK=1.
Only the first 5 hex characters of the password's SHA-1 are sent; the full hash (and the
password) never leave the machine and the response is matched locally.
SHA-1 is used here only because the public API requires it; it is never stored.
"""
from __future__ import annotations

import hashlib
import logging
import urllib.request
from typing import Callable

from .config import Settings

log = logging.getLogger(__name__)


class BreachChecker:
    def __init__(self, enabled: bool = False, url: str = "https://api.pwnedpasswords.com/range/",
                 timeout: float = 4.0, fetcher: Callable[[str], str] | None = None):
        if enabled and not url.lower().startswith("https://"):
            raise ValueError("The breach API URL must use https://")
        self.enabled = enabled
        self.url = url
        self.timeout = timeout
        self._fetch = fetcher or self._http_fetch

    @classmethod
    def from_settings(cls, settings: Settings) -> "BreachChecker":
        return cls(settings.breach_check, settings.breach_api_url, settings.breach_timeout)

    def _http_fetch(self, prefix: str) -> str:
        request = urllib.request.Request(
            self.url + prefix,
            headers={"User-Agent": "SmartPasswordReuseAnalyzer/2.0", "Add-Padding": "true"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 (https enforced)
            return response.read().decode("utf-8", "replace")

    def check(self, password: str) -> int | None:
        """Times the password appears in known breaches, 0 if never, None if unknown/disabled."""
        if not self.enabled:
            return None
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
        prefix, suffix = digest[:5], digest[5:]
        try:
            body = self._fetch(prefix)
        except Exception as error:  # network problems must never break the app
            log.warning("Breach lookup failed (%s); continuing offline.", type(error).__name__)
            return None
        for line in body.splitlines():
            candidate, _, count = line.partition(":")
            if candidate.strip().upper() == suffix:
                try:
                    return int(count.strip())
                except ValueError:
                    return 1
        return 0
