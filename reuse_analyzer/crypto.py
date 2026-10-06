"""Password fingerprints.

A fingerprint lets two passwords be compared for equality without storing either one.

    fingerprint = HMAC-SHA256( key, scrypt(password, salt) )

* scrypt  - memory-hard KDF: an attacker who steals the database *and* the key still has
            to pay ~40 ms and 16 MiB of RAM for every single guess.
* HMAC    - binds the result to this installation's secret, so fingerprints are useless
            on any other machine and cannot be looked up in precomputed tables.
* key     - 32 random bytes in ``instance/fingerprint.key`` (optionally strengthened by a
            master passphrase that is never written to disk).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import unicodedata
from pathlib import Path

from .config import Settings

FINGERPRINT_VERSION = 2
KEY_BYTES = 32


class KeyFileError(RuntimeError):
    """The key file exists but is unusable (never silently regenerated: that would orphan the DB)."""


def restrict_permissions(path: Path, is_dir: bool = False) -> None:
    """Best effort owner-only permissions (a no-op for most Windows ACL setups)."""
    try:
        os.chmod(path, 0o700 if is_dir else 0o600)
    except OSError:
        pass


def normalize_password(password: str) -> str:
    """NFKC normalisation so visually identical passwords (e.g. composed/decomposed accents) match."""
    return unicodedata.normalize("NFKC", password)


class FingerprintEngine:
    def __init__(self, secret_file: str | os.PathLike, settings: Settings):
        self.settings = settings
        self._file_secret = self._load_or_create(Path(secret_file))
        self._key = self._derive_key(self._file_secret, settings.master_passphrase)
        self._salt = hmac.new(self._key, b"pra:v2:salt", hashlib.sha256).digest()
        # Lets the database detect "wrong key / wrong passphrase" instead of silently never matching.
        self.key_id = hmac.new(self._key, b"pra:key-id", hashlib.sha256).hexdigest()[:16]

    # ------------------------------------------------------------------ key handling
    @staticmethod
    def _load_or_create(path: Path) -> bytes:
        path.parent.mkdir(parents=True, exist_ok=True)
        restrict_permissions(path.parent, is_dir=True)
        if not path.exists():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            try:
                fd = os.open(str(path), flags, 0o600)
            except FileExistsError:  # another process won the race
                pass
            else:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(os.urandom(KEY_BYTES))
        secret = path.read_bytes()
        if len(secret) != KEY_BYTES:
            raise KeyFileError(
                f"{path} must contain exactly {KEY_BYTES} bytes but has {len(secret)}. "
                "Restore your backup of the key; generating a new one would make every stored "
                "fingerprint unusable."
            )
        restrict_permissions(path)
        return secret

    @staticmethod
    def _derive_key(file_secret: bytes, passphrase: str | None) -> bytes:
        if not passphrase:
            return file_secret
        return hmac.new(file_secret, b"pra:passphrase\0" + passphrase.encode("utf-8"), hashlib.sha256).digest()

    # ------------------------------------------------------------------ fingerprints
    def _slow(self, domain: bytes, text: str) -> str:
        s = self.settings
        n = 2 ** s.scrypt_log_n
        derived = hashlib.scrypt(
            domain + b"\0" + normalize_password(text).encode("utf-8"),
            salt=self._salt, n=n, r=s.scrypt_r, p=s.scrypt_p, dklen=32,
            maxmem=256 * s.scrypt_r * n,
        )
        return hmac.new(self._key, b"pra:v2:fp\0" + derived, hashlib.sha256).hexdigest()

    def fingerprint(self, password: str) -> str:
        return self._slow(b"full", password)

    def base_fingerprint(self, base_form: str) -> str:
        """Fingerprint of the 'skeleton' of a password (used to spot near-duplicates)."""
        return self._slow(b"base", base_form)

    def legacy_fingerprint(self, password: str) -> str:
        """v1 scheme (plain HMAC-SHA256). Only used to recognise rows created by the old version."""
        return hmac.new(self._file_secret, password.encode("utf-8"), hashlib.sha256).hexdigest()
