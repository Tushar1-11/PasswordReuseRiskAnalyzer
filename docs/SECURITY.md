# Security notes & threat model

## What is stored (`instance/password_risk.sqlite3`)
Per account: platform, username/email label, sensitivity, 2FA flag, **fingerprint**, **skeleton fingerprint**, strength score + flags, optional breach count, timestamps.
**Never stored:** passwords, password length, character classes, CSV contents, the master passphrase.
Note: strength score/flags reveal *that* a password is weak (not what it is).

## Fingerprint construction
`HMAC-SHA256(key, scrypt(NFKC(password), salt))`, scrypt N=2^14, r=8, p=1 (about 40 ms / 16 MiB per guess). Salt and key are derived from a random 32-byte file (`fingerprint.key`) and an optional master passphrase. A second, domain-separated fingerprint is computed from the password "skeleton" to detect near-duplicates; because skeletons have less entropy they use the same slow KDF.

## Threats and mitigations
| Threat | Mitigation | Residual risk |
|---|---|---|
| Other website calls `http://127.0.0.1:5000` from your browser (CSRF) | per-run CSRF header token, JSON-only, Origin check | none known |
| DNS rebinding | Host header allow-list, loopback-only bind | `--allow-remote` disables the safety net |
| Stored/DOM XSS (e.g. hostile platform name from an imported CSV) | DOM APIs only (no `innerHTML`), strict CSP (`script-src 'self'`) | none known |
| Clickjacking / caching of dashboards | `X-Frame-Options`, `frame-ancestors 'none'`, `no-store` | none |
| DB stolen **without** key | Fingerprints are HMAC-keyed: unusable | none |
| DB **and** key stolen | scrypt makes each guess ~40 ms; optional master passphrase adds a secret that is not on disk | weak passwords can still be guessed; use full-disk encryption |
| Request floods burning CPU (scrypt) | rate limiting, 256-char password cap, 2 MB request cap | local DoS by local user |
| Another local user reading files | `0600` key/DB, `0700` instance dir (POSIX) | Windows relies on user-profile ACLs |
| Formula injection in exported CSV | cells starting with `= + - @` are prefixed with `'` | none |
| Plaintext in logs/errors | never logged or echoed (covered by tests) | memory and swap can't be wiped from Python |

## Network behaviour
Offline by default. With `PRA_BREACH_CHECK=1` only the first 5 hex chars of a SHA-1 are sent to `api.pwnedpasswords.com` over HTTPS (k-anonymity, padded responses). SHA-1 is used solely because that API requires it. For a hard guarantee, run without the flag and block outbound traffic for the process in your firewall.

## Backup & recovery
Keep `instance/fingerprint.key` (and the passphrase, if used) with the database. A mismatch is detected at start-up with a clear error instead of silently failing to match.
