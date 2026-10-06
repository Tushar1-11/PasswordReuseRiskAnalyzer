# Changelog

## 2.0.0
**Security fixes**
- Fixed stored XSS: platform names were inserted into the alerts panel with `innerHTML`.
- Added CSRF token, Origin check, Host allow-list (DNS-rebinding), JSON-only API, strict CSP and hardening headers, rate limiting.
- Fingerprints now use scrypt + HMAC (was plain HMAC-SHA-256); NFKC normalisation.
- Key file is validated (never silently regenerated), created with `O_EXCL`, owner-only permissions; key/DB mismatch is detected.
- Release hygiene: the live `fingerprint.key` and SQLite DB are no longer in the zip; `.gitignore` hardened.
- Server refuses non-loopback binding without `--allow-remote`.

**New features**
- Password strength estimation, look-alike (variant) detection, password age, 2FA flag, optional breach check.
- Explainable risk factors, password-health score and grade, prioritised recommendations, reuse map.
- Rotate/update records, multiple accounts per platform (username), search/filter/sort.
- CSV import (browser/password-manager exports), CSV/JSON export, erase-all, password generator, live feedback.
- Dark mode, accessible dialogs/labels, responsive layout.
- `--demo` mode with sample data.

**Engineering**
- Split the single `analyzer.py` into the `reuse_analyzer` package; `analyzer.py` kept as a shim.
- Schema v2 with automatic, backed-up migration from v1 (legacy rows keep working and upgrade on the next match).
- Tests grew from 3 to 80; GitHub Actions workflow; pinned-range dependencies.
