"""Sample data for demos and screenshots. Every password here is a made-up example."""
from __future__ import annotations

from datetime import timedelta

DEMO_ACCOUNTS = [
    # platform, username, password, sensitivity, 2FA, days since password changed
    ("Gmail", "student@example.com", "Chennai@2024", "critical", True, 40),
    ("SBI Net Banking", "student01", "Chennai@2024", "critical", False, 200),
    ("Flipkart", "student@example.com", "Chennai@2024", "important", False, 90),
    ("GitHub", "student-dev", "G!thub-Dev-Kx92-vL", "important", True, 30),
    ("LinkedIn", "student@example.com", "Summer2023!", "important", False, 420),
    ("Instagram", "student.gram", "Summer2024!", "standard", False, 60),
    ("Netflix", "family-plan", "iloveyou", "standard", False, 430),
    ("Amazon", "student@example.com", "Brick-Lamp-Orbit-Quill-72", "important", False, 120),
    ("Spotify", "student.music", "mango-Kettle-river-79-zinc", "standard", False, 75),
    ("Zerodha", "AB1234", "tQ9$wLx2!pRm7vZk", "critical", True, 95),
    ("Dropbox", "student@example.com", "qkT8#mZ2vLp9wR4x", "standard", True, 20),
    ("College Portal", "23BCE0000", "Vit@12345", "important", False, 250),
]


def seed_demo(analyzer) -> int:
    """Fill an empty database with sample accounts. Returns how many were added."""
    if analyzer.dashboard()["summary"]["accounts"]:
        return 0
    for platform, username, password, sensitivity, mfa, _ in DEMO_ACCOUNTS:
        analyzer.add_entry(platform, password, sensitivity, username=username, mfa=mfa)
    now = analyzer._clock()
    with analyzer.db.connection() as db:
        for platform, username, _, _, _, days in DEMO_ACCOUNTS:
            db.execute("UPDATE account_entries SET password_changed_at = ? WHERE platform = ? AND username = ?",
                       ((now - timedelta(days=days)).isoformat(), platform, username))
    return len(DEMO_ACCOUNTS)
