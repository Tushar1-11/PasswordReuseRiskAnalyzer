"""Shared test helpers. A tiny scrypt cost keeps the suite fast; production uses 2**14."""
import hashlib
import hmac
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from reuse_analyzer import PasswordReuseAnalyzer, Settings

FAST = Settings(scrypt_log_n=10)
STRONG_A = "k8$Zp!2mQx9#Lw4v"
STRONG_B = "Bq7!vN2#xW9$zL4&"


class Clock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, days):
        self.now += timedelta(days=days)


class AnalyzerCase(unittest.TestCase):
    settings = FAST
    create_analyzer = True

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = Clock()
        self.analyzer = self.make() if self.create_analyzer else None
        self.addCleanup(self.temp.cleanup)

    def make(self, **kwargs):
        analyzer = PasswordReuseAnalyzer(str(self.root / "t.sqlite3"), str(self.root / "key"),
                                         kwargs.pop("settings", self.settings), clock=self.clock, **kwargs)
        analyzer.initialize()
        return analyzer


def make_v1_database(root: Path, rows):
    """Create a database exactly as the ORIGINAL version of the project did."""
    key = os.urandom(32)
    (root / "key").write_bytes(key)
    con = sqlite3.connect(root / "t.sqlite3")
    con.execute("""CREATE TABLE account_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT, platform TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_fingerprint TEXT NOT NULL, sensitivity TEXT NOT NULL, created_at TEXT NOT NULL)""")
    for platform, password, sensitivity in rows:
        fingerprint = hmac.new(key, password.encode(), hashlib.sha256).hexdigest()
        con.execute("INSERT INTO account_entries (platform, password_fingerprint, sensitivity, created_at) VALUES (?,?,?,?)",
                    (platform, fingerprint, sensitivity, "2025-01-01T00:00:00+00:00"))
    con.commit()
    con.close()
