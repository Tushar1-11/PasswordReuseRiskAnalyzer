"""SQLite access, schema creation and the v1 -> v2 migration."""
from __future__ import annotations

import shutil
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .crypto import restrict_permissions

SCHEMA_VERSION = 2

_ENTRY_TABLE = """
CREATE TABLE account_entries (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    platform             TEXT    NOT NULL COLLATE NOCASE,
    username             TEXT    NOT NULL DEFAULT '' COLLATE NOCASE,
    password_fingerprint TEXT    NOT NULL,
    base_fingerprint     TEXT,
    fp_version           INTEGER NOT NULL DEFAULT 2,
    sensitivity          TEXT    NOT NULL CHECK (sensitivity IN ('standard','important','critical')),
    mfa_enabled          INTEGER NOT NULL DEFAULT 0,
    strength_score       INTEGER,
    strength_flags       TEXT    NOT NULL DEFAULT '',
    breach_count         INTEGER,
    created_at           TEXT    NOT NULL,
    updated_at           TEXT    NOT NULL,
    password_changed_at  TEXT    NOT NULL,
    UNIQUE (platform, username)
)
"""


class KeyMismatchError(RuntimeError):
    """The database was fingerprinted with a different key or master passphrase."""


class Database:
    def __init__(self, path: str):
        self.path = str(path)

    @contextmanager
    def connection(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA secure_delete = ON")  # overwrite deleted fingerprints
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    # ------------------------------------------------------------------ setup / migration
    def initialize(self, key_id: str) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        if self._needs_v1_migration():
            shutil.copy2(self.path, self.path + ".v1.bak")  # safety net before touching user data
            restrict_permissions(Path(self.path + ".v1.bak"))
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='account_entries'").fetchone()
            if exists and version < SCHEMA_VERSION:
                self._migrate_v1(db)
            elif not exists:
                db.execute(_ENTRY_TABLE)
            db.execute("CREATE INDEX IF NOT EXISTS idx_entries_fp ON account_entries (password_fingerprint)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_entries_base ON account_entries (base_fingerprint)")
            db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            self._check_key(db, key_id)
            db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        restrict_permissions(Path(self.path))

    def _needs_v1_migration(self) -> bool:
        if not Path(self.path).exists():
            return False
        with self.connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='account_entries'").fetchone()
        return bool(exists) and version < SCHEMA_VERSION

    @staticmethod
    def _migrate_v1(db: sqlite3.Connection) -> None:
        db.execute("ALTER TABLE account_entries RENAME TO account_entries_v1")
        db.execute(_ENTRY_TABLE)
        db.execute(
            """INSERT INTO account_entries
                 (id, platform, username, password_fingerprint, fp_version, sensitivity,
                  created_at, updated_at, password_changed_at)
               SELECT id, platform, '', password_fingerprint, 1, sensitivity,
                      created_at, created_at, created_at
               FROM account_entries_v1"""
        )
        db.execute("DROP TABLE account_entries_v1")

    @staticmethod
    def _check_key(db: sqlite3.Connection, key_id: str) -> None:
        row = db.execute("SELECT value FROM meta WHERE key = 'key_id'").fetchone()
        if row is None:
            db.execute("INSERT INTO meta (key, value) VALUES ('key_id', ?)", (key_id,))
        elif row["value"] != key_id:
            has_rows = db.execute("SELECT 1 FROM account_entries LIMIT 1").fetchone()
            if has_rows:
                raise KeyMismatchError(
                    "This database was created with a different key or master passphrase. "
                    "Restore the original instance/fingerprint.key (and PRA_MASTER_PASSPHRASE) "
                    "or delete the database to start fresh."
                )
            db.execute("UPDATE meta SET value = ? WHERE key = 'key_id'", (key_id,))

    def vacuum(self) -> None:
        """Physically purge deleted data from the file."""
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("VACUUM")
        finally:
            connection.close()
