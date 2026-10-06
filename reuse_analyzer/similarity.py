"""Near-duplicate ("password variant") detection.

Attackers do not only replay the exact leaked password; they try the obvious mutations.
Research on password reuse (e.g. PentaPassBreaker, in the project's literature survey) shows
that users "change" a password by bumping a number or adding a symbol. We therefore also
store a fingerprint of a password's *skeleton*:

    "Summer2023!"  ->  "summer"          "P@ssw0rd1"  ->  "password"
    "Summer2024#"  ->  "summer"          "password"   ->  "password"

Two accounts with different passwords but the same skeleton are flagged as "similar".
"""
from __future__ import annotations

import re

from .crypto import normalize_password

_LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "l", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"})
_TRAILING = re.compile(r"[\d\W_]+$")
MIN_BASE_LENGTH = 5  # shorter skeletons would create false positives


def base_form(password: str) -> str | None:
    """Return the skeleton of ``password`` or None if too little is left to compare safely."""
    text = _TRAILING.sub("", normalize_password(password))   # drop trailing digits / symbols
    text = text.lower().translate(_LEET)                    # undo common leet-speak
    return text if len(text) >= MIN_BASE_LENGTH else None
