"""Runtime settings. Every value can be overridden with a PRA_* environment variable."""
from __future__ import annotations

import os
from dataclasses import dataclass, replace


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # --- fingerprinting (scrypt is memory-hard, so offline guessing is expensive) ---
    scrypt_log_n: int = 14          # N = 2**14 -> ~16 MiB and ~40 ms per fingerprint
    scrypt_r: int = 8
    scrypt_p: int = 1
    master_passphrase: str | None = None   # optional extra secret mixed into the key

    # --- scoring ---
    stale_days: int = 180
    very_stale_days: int = 365

    # --- optional network feature (OFF by default: the tool is fully offline) ---
    breach_check: bool = False
    breach_api_url: str = "https://api.pwnedpasswords.com/range/"
    breach_timeout: float = 4.0

    # --- input limits ---
    extra_wordlist: str | None = None
    max_password_length: int = 256
    max_import_rows: int = 1000
    max_import_bytes: int = 1_000_000

    @classmethod
    def from_env(cls, **overrides) -> "Settings":
        base = cls(
            scrypt_log_n=_env_int("PRA_SCRYPT_LOG_N", cls.scrypt_log_n),
            master_passphrase=os.environ.get("PRA_MASTER_PASSPHRASE") or None,
            stale_days=_env_int("PRA_STALE_DAYS", cls.stale_days),
            very_stale_days=_env_int("PRA_VERY_STALE_DAYS", cls.very_stale_days),
            breach_check=_env_bool("PRA_BREACH_CHECK", False),
            extra_wordlist=os.environ.get("PRA_WORDLIST") or None,
        )
        return replace(base, **overrides) if overrides else base
