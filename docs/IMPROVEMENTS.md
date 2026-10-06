# Complete improvement report

This lists everything found in the original project, what was changed, and what is still left as future work. Items marked **[bug]** were real defects.

## A. Problems found in the original and how they were fixed

| # | Finding | Severity | Fix in v2 |
|---|---|---|---|
| 1 | **[bug]** The zip shipped the live `instance/fingerprint.key` and the SQLite DB (the key is what makes fingerprints private) | High | Removed; `.gitignore` hardened (`instance/*`, `*.key`, `*.sqlite3`, backups) |
| 2 | **[bug]** Stored XSS: `group.platforms.join(...)` went into `innerHTML` unescaped | High | UI rebuilt with DOM APIs only; strict CSP blocks inline/foreign script; regression tested in a real browser |
| 3 | **[bug]** No CSRF/Origin/Host protection; `get_json(silent=True)` accepted any content type, so a web page you visit could POST records to `127.0.0.1:5000` | High | CSRF token, Origin check, Host allow-list, JSON-only (415 otherwise) |
| 4 | Fast HMAC-SHA-256 fingerprint: if DB + key leak, guessing is extremely cheap | Medium | scrypt (memory-hard) + HMAC, optional master passphrase |
| 5 | Key file: any size accepted; no key/DB mismatch detection; `O_EXCL` race unhandled | Medium | Validated (32 bytes), never silently regenerated, key-id stored in DB, race handled, `0600` |
| 6 | Passwords were not Unicode-normalised, so identical-looking passwords failed to match | Low | NFKC normalisation |
| 7 | No input limits (very long passwords/platform names, huge bodies) | Low | 256-char password cap, 2 MB request cap, control-char rejection, rate limiter |
| 8 | Only one account per platform; had to delete and re-add to change a password | Medium | Unique on (platform, username); **Update/rotate** with age reset |
| 9 | Risk score ignored password strength, age, breaches, 2FA and look-alikes | High (core value) | New explainable factor model; v1 formula kept for plain reuse |
| 10 | Deck promises "password health scores", "visual affected pairs", "real-time warnings" that the code lacked | Medium | Health score + grade, SVG reuse map, live as-you-type check |
| 11 | Single 136-line module, 3 tests, no CI | Medium | `reuse_analyzer` package, 80 tests, GitHub Actions |
| 12 | `README` said nothing about backups, limits or threat model | Low | README + `docs/SECURITY.md` |
| 13 | Debug-server and bind-address risk (`app.run` could be edited to `0.0.0.0` with no login) | Medium | Refuses non-loopback unless `--allow-remote`; debugger never enabled |

## B. New features

1. **Look-alike detection**: catches `Summer2023!` -> `Summer2024!`, the real-world "password rotation" habit described in your literature survey (PentaPassBreaker).
2. **Strength estimator** (offline): common list (302 bundled, extendable), keyboard walks, repeats, years, word+digits+symbol, CamelCase phrases, passphrases.
3. **Explainable scoring**: expand any risk badge to see each factor and its points.
4. **Password-health score** (0-100, grade A-F) and a **prioritised fix list**.
5. **Reuse map** (SVG) showing exact vs look-alike connections.
6. **2FA flag**, **password age/stale detection**, **sensitivity auto-suggestion** (e.g. "SBI", "Gmail" -> critical).
7. **CSV import** from browsers/password managers (in memory only) so users don't have to retype everything.
8. **Export** CSV/JSON (no secrets; CSV formula-injection safe), **erase-all** with typed confirmation + `VACUUM` + `secure_delete`.
9. **Live feedback** while typing, **password generator** (`crypto.getRandomValues`, rejection sampling).
10. **Optional breach check** via HIBP k-anonymity (opt-in; mocked in tests).
11. **Automatic v1 -> v2 migration** with backup; legacy rows keep matching and upgrade for free when their password is seen again.
12. UX: dark mode, responsive, keyboard-accessible dialogs, skip link, ARIA live regions, search/filter/sort.
13. `--demo` mode for presentations/screenshots.

## C. Ideas not implemented (future work / good viva answers)

- **Encrypted-at-rest database** (SQLCipher) and an unlock screen. Today the guarantee is "no plaintext + keyed slow fingerprints".
- **Argon2id** instead of scrypt (needs a third-party package; scrypt keeps the app dependency-free).
- **Browser extension** to check at the moment of sign-up (true real-time prevention).
- **Offline HIBP**: load the downloadable sorted SHA-1 file for breach checks with zero network.
- **Private Set Intersection** for cross-device/team reuse detection (the approach in your literature survey [1]).
- **Learned model** (e.g. ANN) on password-structure features. Not added on purpose: a hand-built, explainable score is easier to defend than a model trained on no real data. If you want it, train on a public dataset and compare against this baseline.
- Packaging as a desktop app (PyInstaller/Tauri); multi-user profiles; scheduled re-check reminders.
