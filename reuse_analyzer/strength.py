"""Offline password-strength estimation (no network, nothing stored).

This is a deliberately small, explainable estimator in the spirit of zxcvbn: it starts from
the naive "length x character-pool" entropy and then *discounts* the things humans actually
do - common passwords, keyboard walks, repeated characters, years and "Word + digits + symbol".
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .ann import estimate as ann_estimate
from .crypto import normalize_password

_DATA_FILE = Path(__file__).with_name("data") / "common_passwords.txt"
_LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "l", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"})
_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "qazwsxedcrfvtgbyhnujmikolp")
_YEAR = re.compile(r"(?:19|20)\d{2}")
_SCORE_CURVE = [(0, 0), (28, 20), (40, 40), (60, 62), (80, 82), (110, 100)]

SUGGESTIONS = {
    "common": "This is one of the most common passwords - attackers try it first.",
    "common_variant": "This is a common password with a few characters added; attackers try those variants early.",
    "short": "Use at least 12 characters (16+ is better).",
    "sequence": "Avoid sequences such as 'abc', '1234' or keyboard walks like 'qwerty'.",
    "repeat": "Avoid repeated characters such as 'aaaa'.",
    "year": "Avoid years and dates - they are among the first things guessed.",
    "word_pattern": "'Word + digits + symbol' is a well-known pattern. Use a longer random passphrase instead.",
    "single_class": "Mix character types, or better, use a long random passphrase.",
}


@dataclass
class Strength:
    score: int
    label: str
    bits: float
    flags: list[str] = field(default_factory=list)
    length: int = 0
    ann_estimate: dict | None = None

    @property
    def suggestions(self) -> list[str]:
        tips = [SUGGESTIONS[f] for f in self.flags if f in SUGGESTIONS]
        if self.score < 60 and not tips:
            tips.append("Make it longer: length matters more than complexity." if self.length < 14
                        else "Add another random word or a few unpredictable characters.")
        if self.score < 80:
            tips.append("Let a password manager generate a unique random password for this account.")
        return tips

    def to_dict(self) -> dict:
        return {"score": self.score, "label": self.label, "bits": round(self.bits, 1),
                "flags": self.flags, "suggestions": self.suggestions, "ann_estimate": self.ann_estimate}


@lru_cache(maxsize=4)
def load_common_passwords(extra_path: str | None = None) -> frozenset[str]:
    words: set[str] = set()
    paths = [_DATA_FILE] + ([Path(extra_path)] if extra_path else [])
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        words.add(line)
        except OSError:
            continue
    return frozenset(words)


def label_for(score: int) -> str:
    for limit, label in ((20, "Very weak"), (40, "Weak"), (60, "Fair"), (80, "Strong")):
        if score < limit:
            return label
    return "Very strong"


def _score_from_bits(bits: float) -> int:
    for (x0, y0), (x1, y1) in zip(_SCORE_CURVE, _SCORE_CURVE[1:]):
        if bits <= x1:
            return round(y0 + (y1 - y0) * (bits - x0) / (x1 - x0))
    return 100


def _pool_size(password: str) -> int:
    pool = 0
    pool += 26 if re.search(r"[a-z]", password) else 0
    pool += 26 if re.search(r"[A-Z]", password) else 0
    pool += 10 if re.search(r"\d", password) else 0
    pool += 33 if re.search(r"[ -/:-@\[-`{-~]", password) else 0
    pool += 100 if re.search(r"[^\x00-\x7f]", password) else 0
    return max(pool, 10)


def _discounted_length(password: str, flags: list[str]) -> float:
    """Characters that carry no real entropy (runs, walks, years) are discounted."""
    lower = password.lower()
    n = len(password)
    free = [False] * n

    for match in re.finditer(r"(.)\1{2,}", lower):                      # aaaa -> counts as 1 char
        for i in range(match.start() + 1, match.end()):
            free[i] = True
        flags.append("repeat")

    for direction in (1, -1):                                          # abc / 123 / cba / 321
        run = 1
        for i in range(1, n + 1):
            if i < n and ord(lower[i]) - ord(lower[i - 1]) == direction and lower[i].isalnum():
                run += 1
                continue
            if run >= 3:
                for j in range(i - run + 2, i):                       # first two chars still count
                    free[j] = True
                flags.append("sequence")
            run = 1

    for row in _KEYBOARD_ROWS:                                         # qwerty walks, both directions
        for candidate in (row, row[::-1]):
            for size in range(len(candidate), 3, -1):
                for start in range(len(candidate) - size + 1):
                    chunk = candidate[start:start + size]
                    idx = lower.find(chunk)
                    if idx != -1:
                        for j in range(idx + 2, idx + size):
                            free[j] = True
                        flags.append("sequence")

    for match in _YEAR.finditer(lower):                                # a year ~ 7 bits, not 4 digits
        for i in range(match.start() + 2, match.end()):
            free[i] = True
        flags.append("year")

    return float(sum(1 for f in free if not f))


def assess(password: str, common: frozenset[str]) -> Strength:
    pw = normalize_password(password)
    lower = pw.lower()
    flags: list[str] = []
    pool = _pool_size(pw)
    bits = _discounted_length(pw, flags) * math.log2(pool)

    # "Summer2024!", "Tr0ub4dor&3", "Sunshine@123": a (leet-speak) word plus a short numeric/symbol tail.
    # Humans pick these constantly, so they cost an attacker ~16 bits for the word + the tail.
    core = re.sub(r"[\d\W_]+$", "", pw)
    suffix = pw[len(core):]
    decoded = core.lower().translate(_LEET)
    leet_count = sum(1 for a, b in zip(core.lower(), decoded) if a != b)
    if (3 <= len(core) <= 12 and len(suffix) <= 6 and decoded.isalpha() and (suffix or leet_count)
            and core in (core.lower(), core.capitalize(), core.upper())):
        tail_bits = 7 if _YEAR.fullmatch(suffix) else sum(3.3 if c.isdigit() else 5 for c in suffix)
        pattern_bits = 16 + (1 if core != core.lower() else 0) + 2 * leet_count + tail_bits
        if pattern_bits < bits:
            bits = pattern_bits
            flags.append("word_pattern")

    # Words separated by spaces/dashes: ~13 bits per word, ~7 per year, ~3.3 per digit
    # (four random words ~ 52 bits, "Hello World 2024" ~ 33 bits).
    tokens = [t for t in re.split(r"[ \-_.]+", lower) if t]
    if len(tokens) >= 2 and all(t.isalpha() or t.isdigit() for t in tokens):
        bits = min(bits, sum(13 if t.isalpha() else 7 if _YEAR.fullmatch(t) else 3.3 * len(t) for t in tokens))
    elif re.fullmatch(r"[A-Za-z]+", pw):
        if len(pw) <= 10:
            bits = min(bits, 28)
            flags.append("single_class")
        elif pw in (lower, pw.upper(), pw.capitalize()):      # long single-case text is usually joined words
            bits = min(bits, 3.2 * len(pw))
    elif re.fullmatch(r"\d+", pw):
        bits = min(bits, 3.3 * len(pw))
        flags.append("single_class")

    # CamelCase phrases ("MyDogSpot1987"): count each word/number token, not every character.
    camel = re.findall(r"[A-Z][a-z]+|[a-z]+|\d+", pw)
    if len(camel) >= 2 and "".join(camel) == pw:
        bits = min(bits, sum(min(13, 4.7 * len(t)) if t.isalpha() else 7 if _YEAR.fullmatch(t) else 3.3 * len(t) for t in camel))

    stripped = re.sub(r"[\d\W_]+$", "", lower).translate(_LEET)   # strip the tail FIRST, then undo leet
    if lower in common or lower.translate(_LEET) in common:
        flags.insert(0, "common")
        bits = min(bits, 10)
    elif len(stripped) >= 4 and stripped in common:
        flags.insert(0, "common_variant")
        bits = min(bits, 20)

    if len(pw) < 8:
        flags.append("short")
        bits = min(bits, 25)

    flags = list(dict.fromkeys(flags))  # de-duplicate, keep order
    score = max(0, min(100, _score_from_bits(bits)))
    return Strength(score=score, label=label_for(score), bits=bits, flags=flags, length=len(pw),
                    ann_estimate=ann_estimate(pw))
