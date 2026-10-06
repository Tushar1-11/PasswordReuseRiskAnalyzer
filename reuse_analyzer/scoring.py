"""Explainable risk scoring.

Every score is the sum of named *factors* so the UI can show exactly why an account is risky
(an explainable alternative to the black-box models in the literature survey).

Levels: Low < 20 <= Medium < 45 <= High < 70 <= Critical
"""
from __future__ import annotations

from datetime import datetime, timezone

from .config import Settings

SENSITIVITY_WEIGHTS = {"standard": 0, "important": 10, "critical": 20}
VALID_SENSITIVITIES = set(SENSITIVITY_WEIGHTS)

_CRITICAL_HINTS = (
    "bank", "paypal", "upi", "wallet", "crypto", "coinbase", "binance", "zerodha", "groww", "paytm",
    "phonepe", "gpay", "hdfc", "icici", "sbi", "axis", "kotak", "finance", "tax", "insurance",
    "gmail", "google", "outlook", "hotmail", "yahoo", "proton", "icloud", "apple", "microsoft",
    "aws", "azure", "email", "mail",
)
_IMPORTANT_HINTS = (
    "github", "gitlab", "bitbucket", "linkedin", "amazon", "flipkart", "facebook", "instagram",
    "twitter", "x.com", "whatsapp", "telegram", "dropbox", "drive", "slack", "discord", "notion",
    "university", "college", "vit", "student", "office", "netflix", "cloud", "hosting", "domain",
)


def suggest_sensitivity(platform: str) -> str:
    """Heuristic default for the sensitivity dropdown (the user can always override it)."""
    name = platform.lower()
    if any(hint in name for hint in _CRITICAL_HINTS):
        return "critical"
    if any(hint in name for hint in _IMPORTANT_HINTS):
        return "important"
    return "standard"


def level_for(score: int) -> str:
    if score >= 70:
        return "Critical"
    if score >= 45:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def age_days(changed_at: str, now: datetime) -> int:
    try:
        when = datetime.fromisoformat(changed_at)
    except ValueError:
        return 0
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0, (now - when).days)


def _finish(factors: list[tuple[str, int]]) -> dict:
    score = max(0, min(100, sum(points for _, points in factors)))
    return {"score": score, "level": level_for(score),
            "factors": [{"label": label, "points": points} for label, points in factors if points]}


def group_risk(rows: list[dict], settings: Settings) -> dict:
    """Risk of one exact-reuse group: the same password protecting several accounts."""
    count = len(rows)
    factors = [(f"Same password protects {count} accounts", 25 + (count - 2) * 15)]

    top = max(rows, key=lambda r: SENSITIVITY_WEIGHTS[r["sensitivity"]])["sensitivity"]
    if SENSITIVITY_WEIGHTS[top]:
        factors.append((f"Group includes a {top} account", SENSITIVITY_WEIGHTS[top]))
    if any(r["strength_score"] is not None and r["strength_score"] < 40 for r in rows):
        factors.append(("Shared password is weak", 10))
    if any((r["breach_count"] or 0) > 0 for r in rows):
        factors.append(("Shared password appears in known data breaches", 15))
    if max(r["age_days"] for r in rows) > settings.very_stale_days:
        factors.append(("Password unchanged for over a year", 5))
    if all(r["mfa_enabled"] for r in rows):
        factors.append(("Two-factor authentication on every account in the group", -10))
    return _finish(factors)


def single_risk(row: dict, similar_count: int, settings: Settings) -> dict:
    """Risk of an account on its own merits (weak, breached, stale or pattern-reusing password)."""
    flags = row["strength_flags"]
    score = row["strength_score"]
    factors: list[tuple[str, int]] = []

    if (row["breach_count"] or 0) > 0:
        factors.append((f"Password found in {row['breach_count']:,} known breaches", 40))
    elif "common" in flags:
        factors.append(("Password is on the common-password list", 35))
    elif "common_variant" in flags:
        factors.append(("Password is a variant of a very common password", 25))
    elif score is not None and score < 20:
        factors.append(("Password is very weak", 20))
    elif score is not None and score < 40:
        factors.append(("Password is weak", 14))
    elif score is not None and score < 60:
        factors.append(("Password strength is only fair", 6))

    if similar_count:
        factors.append(("Password follows the same pattern as other accounts", min(25, 15 + 5 * (similar_count - 1))))
    if row["age_days"] > settings.very_stale_days:
        factors.append(("Password unchanged for over a year", 10))
    elif row["age_days"] > settings.stale_days:
        factors.append((f"Password unchanged for over {settings.stale_days} days", 5))

    subtotal = sum(points for _, points in factors)
    if subtotal > 0:
        bonus = SENSITIVITY_WEIGHTS[row["sensitivity"]] // 2
        if bonus:
            factors.append((f"{row['sensitivity'].title()} account raises the impact", bonus))
        if row["mfa_enabled"]:
            factors.append(("Two-factor authentication limits the damage", -10))
    return _finish(factors)


def health_score(risks: list[int]) -> dict | None:
    """Overall 'password health' 0-100 (higher is better) plus an A-F grade."""
    if not risks:
        return None
    mean = sum(risks) / len(risks)
    score = max(0, min(100, round(100 - (0.6 * mean + 0.4 * max(risks)))))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
    return {"score": score, "grade": grade}
