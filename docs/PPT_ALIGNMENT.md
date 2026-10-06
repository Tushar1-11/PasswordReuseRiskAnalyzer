# Aligning the presentation with the real project

Several slides describe things the code didn't do. Examiners notice this, so either change the slide or use the v2 feature. Suggested edits:

| Slide | Says | Reality in v2 | Suggested wording |
|---|---|---|---|
| 8 Novelty | "hashed values", "secure hashing" | HMAC + scrypt keyed fingerprints | "Device-bound, memory-hard fingerprints (scrypt + HMAC-SHA-256)" |
| 8 Novelty | "real-time detection" | live check while typing (debounced) | keep; now true |
| 8 Novelty | "risk scoring" | explainable multi-factor score | "Explainable risk scoring: reuse, strength, age, breaches, 2FA" **(new strength)** |
| *(add)* | | look-alike detection | **New novelty bullet:** "Detects near-duplicate passwords, not just exact reuse" |
| 11 Tech stack | SQLite/**MongoDB**, SHA-256/**bcrypt**, **ANN, TensorFlow/Scikit-learn** | SQLite + scrypt/HMAC; small standard-library ANN for strength preview; no TensorFlow/Scikit-learn | "Flask, SQLite, Python `hashlib` (scrypt, HMAC), vanilla JS/SVG, lightweight ANN (synthetic training data)". Remove MongoDB, bcrypt, TensorFlow and Scikit-learn |
| 12 Implementation | "UI (**Python/Tkinter**)" | Flask web UI | "Local Flask web interface" |
| 12 Implementation | "**encrypted**, offline SQLite" | plaintext-free DB, keyed fingerprints, `0600`; not SQLCipher | "Local SQLite storing only keyed fingerprints (no plaintext)" |
| 12 Implementation | "Block all outbound network traffic" | offline by default; optional opt-in breach check | "Fully offline by default; optional k-anonymity breach check" |
| 12 Implementation | "Never store or process plain text **in memory**" | impossible in Python | "Never written to disk, logs or API responses" |
| 12 Implementation | "Save data only as (Platform, Hash)" | more metadata (sensitivity, 2FA, strength, dates) | "Stores fingerprints plus non-secret metadata" |
| 7 Research gap | "no simple real-time local user-level system" | still valid | keep |

## Slides worth adding
1. **Threat model**: asset, attacker, mitigations (use `docs/SECURITY.md`).
2. **Results / demo**: run `python app.py --demo`, screenshot (`docs/screenshots/`), show the explainable factors.
3. **Testing**: 80 automated tests; list categories (privacy canary tests, CSRF, XSS, migration).
4. **Limitations & future work**: Section C of `IMPROVEMENTS.md`.

## Likely viva questions
- *Why not store a plain SHA-256?* Fast hashes allow cheap offline guessing and rainbow tables; scrypt is memory-hard and the HMAC key makes fingerprints useless elsewhere.
- *Why must the fingerprint be deterministic?* Reuse detection needs equality comparison, so no per-record random salt; the per-install key/salt prevents cross-installation lookup.
- *How do you detect "Summer2023!" vs "Summer2024!"?* Skeleton fingerprint (strip trailing digits/symbols, undo leet-speak) compared by equality.
- *What if the DB is stolen?* See the threat table in `SECURITY.md`.
