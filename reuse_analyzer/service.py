"""PasswordReuseAnalyzer - the application service used by the Flask routes and the tests."""
from __future__ import annotations

import json
import logging
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .breach import BreachChecker
from .config import Settings
from .crypto import FingerprintEngine
from .database import Database
from .importer import parse_password_csv
from .scoring import (SENSITIVITY_WEIGHTS, VALID_SENSITIVITIES, age_days, group_risk, health_score,
                      level_for, single_risk, suggest_sensitivity)
from .similarity import base_form
from .strength import Strength, assess, load_common_passwords

log = logging.getLogger(__name__)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_DUPLICATE = "That platform and username already have a record. Use Update to change it, or delete it first."


def label_of(platform: str, username: str) -> str:
    return f"{platform} ({username})" if username else platform


@dataclass(frozen=True)
class _Material:
    fingerprint: str
    base_fingerprint: str | None
    legacy: str
    strength: Strength


class PasswordReuseAnalyzer:
    def __init__(self, database: str, secret_file: str, settings: Settings | None = None,
                 breach_checker: BreachChecker | None = None, clock: Callable[[], datetime] | None = None):
        self.settings = settings or Settings.from_env()
        self.database = str(database)
        self.secret_file = Path(secret_file)
        self.engine = FingerprintEngine(secret_file, self.settings)
        self.db = Database(self.database)
        self.common = load_common_passwords(self.settings.extra_wordlist)
        self.breach = breach_checker or BreachChecker.from_settings(self.settings)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def initialize(self) -> None:
        self.db.initialize(self.engine.key_id)

    # ================================================================== validation
    def _text(self, value: object, name: str, low: int, high: int) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{name} must be text.")
        value = " ".join(value.split())
        if not low <= len(value) <= high or _CONTROL_CHARS.search(value):
            raise ValueError(f"{name} must be between {low} and {high} characters." if low else f"{name} is too long (max {high}).")
        return value

    def _clean(self, platform: object, username: object, sensitivity: object) -> tuple[str, str, str]:
        platform = self._text(platform, "Platform name", 2, 80)
        username = self._text(username if username is not None else "", "Username", 0, 120)
        if sensitivity not in VALID_SENSITIVITIES:
            raise ValueError("Choose a valid account sensitivity.")
        return platform, username, sensitivity

    def _check_password(self, password: object) -> str:
        if not isinstance(password, str) or not password:
            raise ValueError("Enter a password to analyze.")
        if len(password) > self.settings.max_password_length:
            raise ValueError(f"Passwords longer than {self.settings.max_password_length} characters are not supported.")
        return password

    # ================================================================== helpers
    def _material(self, password: str, cache: dict | None = None) -> _Material:
        if cache is not None and password in cache:
            return cache[password]
        base = base_form(password)
        material = _Material(
            fingerprint=self.engine.fingerprint(password),
            base_fingerprint=self.engine.base_fingerprint(base) if base else None,
            legacy=self.engine.legacy_fingerprint(password),
            strength=assess(password, self.common),
        )
        if cache is not None:
            cache[password] = material
        return material

    def _row(self, row: sqlite3.Row, now: datetime) -> dict:
        data = dict(row)
        data["strength_flags"] = [f for f in data["strength_flags"].split(",") if f]
        data["mfa_enabled"] = bool(data["mfa_enabled"])
        data["age_days"] = age_days(data["password_changed_at"], now)
        data["label"] = label_of(data["platform"], data["username"])
        return data

    def _find_matches(self, db: sqlite3.Connection, material: _Material, exclude_id: int = -1) -> tuple[list[dict], list[dict]]:
        now = self._clock()
        exact = db.execute(
            """SELECT * FROM account_entries
               WHERE id != :ex AND ((fp_version = 2 AND password_fingerprint = :fp)
                                 OR (fp_version = 1 AND password_fingerprint = :legacy))
               ORDER BY platform COLLATE NOCASE, username COLLATE NOCASE""",
            {"ex": exclude_id, "fp": material.fingerprint, "legacy": material.legacy},
        ).fetchall()
        similar = []
        if material.base_fingerprint:
            similar = db.execute(
                """SELECT * FROM account_entries
                   WHERE id != :ex AND fp_version = 2 AND base_fingerprint = :base AND password_fingerprint != :fp
                   ORDER BY platform COLLATE NOCASE, username COLLATE NOCASE""",
                {"ex": exclude_id, "base": material.base_fingerprint, "fp": material.fingerprint},
            ).fetchall()
        return [self._row(r, now) for r in exact], [self._row(r, now) for r in similar]

    def _upgrade_legacy(self, db: sqlite3.Connection, rows: list[dict], material: _Material, breach: int | None) -> None:
        """A v1 row that matched proves we just saw its password, so it can be re-fingerprinted for free."""
        for row in rows:
            if row["fp_version"] == 1:
                db.execute(
                    """UPDATE account_entries SET password_fingerprint = ?, base_fingerprint = ?, fp_version = 2,
                       strength_score = ?, strength_flags = ?, breach_count = COALESCE(?, breach_count), updated_at = ?
                       WHERE id = ?""",
                    (material.fingerprint, material.base_fingerprint, material.strength.score,
                     ",".join(material.strength.flags), breach, self._clock().isoformat(), row["id"]),
                )

    def _hypothetical(self, sensitivity: str, mfa: bool, material: _Material, breach: int | None) -> dict:
        return {"sensitivity": sensitivity, "mfa_enabled": mfa, "strength_score": material.strength.score,
                "strength_flags": material.strength.flags, "breach_count": breach, "age_days": 0}

    def _risk_for(self, hypo: dict, exact: list[dict], similar: list[dict]) -> dict:
        own = single_risk(hypo, len(similar), self.settings)
        if not exact:
            return own
        group = group_risk(exact + [hypo], self.settings)
        return group if group["score"] >= own["score"] else own

    def _verdict(self, hypo: dict, material: _Material, exact: list[dict], similar: list[dict],
                 breach: int | None) -> dict:
        strength = material.strength
        reused_on = [r["label"] for r in exact]
        similar_to = [r["label"] for r in similar]
        advice: list[str] = []
        if breach:
            advice.append(f"This password has appeared in {breach:,} known breaches - never use it again.")
        if reused_on:
            advice.append("Give each account its own password: " + ", ".join(reused_on) + ".")
        if similar_to:
            advice.append("Small variations are easy to guess. Use an unrelated password instead of changing a few characters.")
        advice.extend(strength.suggestions[:2])
        if hypo["sensitivity"] != "standard" and not hypo["mfa_enabled"]:
            advice.append("Turn on two-factor authentication for this account.")

        if reused_on:
            message = "Password reuse detected. Change this password and the matching accounts."
        elif breach:
            message = f"No reuse found, but this password appears in {breach:,} known breaches. Do not use it."
        elif similar_to:
            message = "No exact match, but this password follows the same pattern as: " + ", ".join(similar_to) + "."
        elif strength.score < 40:
            message = f"No reuse found, but this password is {strength.label.lower()}."
        else:
            message = "No matching password fingerprint was found."
        risk = self._risk_for(hypo, exact, similar)
        return {"reused": bool(reused_on), "reused_on": reused_on, "similar": bool(similar_to), "similar_to": similar_to,
                "strength": strength.to_dict(), "breach_count": breach, "risk": risk, "message": message,
                "advice": list(dict.fromkeys(advice))}

    # ================================================================== operations
    def check_password(self, password: object, sensitivity: str = "standard", mfa: bool = False,
                       exclude_id: int | None = None) -> dict:
        """Live preview: nothing is stored and no network call is made."""
        password = self._check_password(password)
        if sensitivity not in VALID_SENSITIVITIES:
            sensitivity = "standard"
        material = self._material(password)
        with self.db.connection() as db:
            exact, similar = self._find_matches(db, material, exclude_id if exclude_id is not None else -1)
        return self._verdict(self._hypothetical(sensitivity, bool(mfa), material, None), material, exact, similar, None)

    def add_entry(self, platform: str, password: object, sensitivity: str = "standard",
                  username: str = "", mfa: bool = False) -> dict:
        platform, username, sensitivity = self._clean(platform, username, sensitivity)
        password = self._check_password(password)
        material = self._material(password)
        breach = self.breach.check(password)  # network call (if enabled) happens before the DB write lock
        now = self._clock().isoformat()
        with self.db.connection() as db:
            try:
                cursor = db.execute(
                    """INSERT INTO account_entries
                       (platform, username, password_fingerprint, base_fingerprint, fp_version, sensitivity, mfa_enabled,
                        strength_score, strength_flags, breach_count, created_at, updated_at, password_changed_at)
                       VALUES (?, ?, ?, ?, 2, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (platform, username, material.fingerprint, material.base_fingerprint, sensitivity, int(bool(mfa)),
                     material.strength.score, ",".join(material.strength.flags), breach, now, now, now),
                )
            except sqlite3.IntegrityError:
                raise ValueError(_DUPLICATE) from None
            exact, similar = self._find_matches(db, material, cursor.lastrowid)
            self._upgrade_legacy(db, exact, material, breach)
        result = self._verdict(self._hypothetical(sensitivity, bool(mfa), material, breach), material, exact, similar, breach)
        result["id"] = cursor.lastrowid
        return result

    def update_entry(self, entry_id: int, *, password: object = None, sensitivity: str | None = None,
                     mfa: bool | None = None, username: str | None = None, platform: str | None = None) -> dict:
        with self.db.connection() as db:
            found = db.execute("SELECT * FROM account_entries WHERE id = ?", (entry_id,)).fetchone()
        if found is None:
            raise LookupError("Account record not found.")
        current = self._row(found, self._clock())
        new_platform, new_username, new_sens = self._clean(
            current["platform"] if platform is None else platform,
            current["username"] if username is None else username,
            current["sensitivity"] if sensitivity is None else sensitivity)
        new_mfa = current["mfa_enabled"] if mfa is None else bool(mfa)
        now = self._clock().isoformat()
        fields = {"platform": new_platform, "username": new_username, "sensitivity": new_sens,
                  "mfa_enabled": int(new_mfa), "updated_at": now}

        material = breach = None
        if password not in (None, ""):
            password = self._check_password(password)
            material = self._material(password)
            same = (material.fingerprint == current["password_fingerprint"] if current["fp_version"] == 2
                    else material.legacy == current["password_fingerprint"])
            if same:
                raise ValueError("The new password is identical to the current one.")
            breach = self.breach.check(password)
            fields.update(password_fingerprint=material.fingerprint, base_fingerprint=material.base_fingerprint,
                          fp_version=2, strength_score=material.strength.score,
                          strength_flags=",".join(material.strength.flags), breach_count=breach,
                          password_changed_at=now)

        assignments = ", ".join(f"{column} = :{column}" for column in fields)
        with self.db.connection() as db:
            try:
                db.execute(f"UPDATE account_entries SET {assignments} WHERE id = :id", {**fields, "id": entry_id})  # noqa: S608 (column names are constants)
            except sqlite3.IntegrityError:
                raise ValueError(_DUPLICATE) from None
            if material:
                exact, similar = self._find_matches(db, material, entry_id)
                self._upgrade_legacy(db, exact, material, breach)

        if material:
            result = self._verdict(self._hypothetical(new_sens, new_mfa, material, breach), material, exact, similar, breach)
            result.update(id=entry_id, rotated=True, updated=True)
            if not result["reused"] and not result["similar"] and not breach and material.strength.score >= 40:
                result["message"] = "Password rotated. It is unique and no reuse was found."
            return result
        view = next(e for e in self.dashboard()["entries"] if e["id"] == entry_id)
        return {"id": entry_id, "rotated": False, "updated": True, "message": "Account updated.",
                "risk": {"score": view["risk_score"], "level": view["risk_level"], "factors": view["risk_factors"]}}

    def delete_entry(self, entry_id: int) -> bool:
        with self.db.connection() as db:
            return db.execute("DELETE FROM account_entries WHERE id = ?", (entry_id,)).rowcount == 1

    def delete_all(self) -> int:
        with self.db.connection() as db:
            count = db.execute("DELETE FROM account_entries").rowcount
        self.db.vacuum()
        return count

    def import_csv(self, text: str) -> dict:
        records, problems = parse_password_csv(text, self.settings.max_import_rows)
        cache: dict[str, _Material] = {}
        now = self._clock().isoformat()
        imported = duplicates = 0
        with self.db.connection() as db:
            seen = {(r["platform"].lower(), r["username"].lower()) for r in db.execute("SELECT platform, username FROM account_entries")}
            for record in records:
                try:
                    platform, username, sensitivity = self._clean(record["platform"], record["username"],
                                                                  suggest_sensitivity(record["platform"]))
                    password = self._check_password(record["password"])
                except ValueError as error:
                    problems.append(f"{record['platform'][:40]}: {error}")
                    continue
                key = (platform.lower(), username.lower())
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
                material = self._material(password, cache)
                stamp = now
                db.execute(
                    """INSERT INTO account_entries
                       (platform, username, password_fingerprint, base_fingerprint, fp_version, sensitivity, mfa_enabled,
                        strength_score, strength_flags, breach_count, created_at, updated_at, password_changed_at)
                       VALUES (?, ?, ?, ?, 2, ?, 0, ?, ?, NULL, ?, ?, ?)""",
                    (platform, username, material.fingerprint, material.base_fingerprint, sensitivity,
                     material.strength.score, ",".join(material.strength.flags), stamp, stamp, stamp),
                )
                imported += 1
        cache.clear()
        summary = self.dashboard()["summary"]
        return {"imported": imported, "skipped_duplicates": duplicates, "skipped_invalid": len(problems),
                "problems": problems[:10], "summary": summary,
                "note": "Imported accounts get an estimated sensitivity and no 2FA flag - review them in the table. "
                        "Password age is unknown for imports, so it starts from today."}

    # ================================================================== reporting
    def _state(self) -> dict:
        now = self._clock()
        with self.db.connection() as db:
            rows = [self._row(r, now) for r in db.execute(
                "SELECT * FROM account_entries ORDER BY platform COLLATE NOCASE, username COLLATE NOCASE")]

        exact_groups: dict[tuple, list[dict]] = defaultdict(list)
        base_groups: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            exact_groups[(row["fp_version"], row["password_fingerprint"])].append(row)
            if row["base_fingerprint"]:
                base_groups[row["base_fingerprint"]].append(row)

        reuse = []
        group_of: dict[int, dict] = {}
        for members in exact_groups.values():
            if len(members) > 1:
                risk = group_risk(members, self.settings)
                reuse.append({"ids": [m["id"] for m in members], "platforms": [m["label"] for m in members], **risk})
                for m in members:
                    group_of[m["id"]] = risk
        reuse.sort(key=lambda g: (-g["score"], g["platforms"]))

        similar, similar_to = [], defaultdict(list)
        for members in base_groups.values():
            if len({m["password_fingerprint"] for m in members}) > 1:
                score = min(60, 25 + 5 * (len(members) - 2))
                similar.append({"ids": [m["id"] for m in members], "platforms": [m["label"] for m in members],
                                "score": score, "level": level_for(score)})
                for m in members:
                    similar_to[m["id"]].extend(o["label"] for o in members
                                               if o["password_fingerprint"] != m["password_fingerprint"])

        entries = []
        for row in rows:
            own = single_risk(row, len(similar_to[row["id"]]), self.settings)
            risk = group_of.get(row["id"])
            risk = risk if risk and risk["score"] >= own["score"] else own
            strength = None
            if row["strength_score"] is not None:
                from .strength import label_for
                strength = {"score": row["strength_score"], "label": label_for(row["strength_score"]), "flags": row["strength_flags"]}
            entries.append({
                "id": row["id"], "platform": row["platform"], "username": row["username"], "label": row["label"],
                "sensitivity": row["sensitivity"], "mfa_enabled": row["mfa_enabled"], "strength": strength,
                "breach_count": row["breach_count"], "password_age_days": row["age_days"],
                "stale": row["age_days"] > self.settings.stale_days, "legacy": row["fp_version"] == 1,
                "password_changed_at": row["password_changed_at"], "created_at": row["created_at"],
                "risk_score": risk["score"], "risk_level": risk["level"], "risk_factors": risk["factors"],
                "reused_with": [o["label"] for o in exact_groups[(row["fp_version"], row["password_fingerprint"])] if o["id"] != row["id"]],
                "similar_with": list(dict.fromkeys(similar_to[row["id"]])),
            })
        return {"entries": entries, "reuse_groups": reuse, "similar_groups": similar}

    def dashboard(self) -> dict:
        state = self._state()
        entries, reuse, similar = state["entries"], state["reuse_groups"], state["similar_groups"]
        scores = [e["risk_score"] for e in entries]
        sensitive = [e for e in entries if e["sensitivity"] != "standard"]
        levels = {name: sum(1 for e in entries if e["risk_level"] == name) for name in ("Low", "Medium", "High", "Critical")}
        summary = {
            "accounts": len(entries),
            "reused_accounts": sum(len(g["platforms"]) for g in reuse),
            "similar_accounts": len({i for g in similar for i in g["ids"]}),
            "weak_accounts": sum(1 for e in entries if e["strength"] and e["strength"]["score"] < 40),
            "stale_accounts": sum(1 for e in entries if e["stale"]),
            "breached_accounts": sum(1 for e in entries if (e["breach_count"] or 0) > 0),
            "legacy_accounts": sum(1 for e in entries if e["legacy"]),
            "mfa_coverage": round(100 * sum(1 for e in sensitive if e["mfa_enabled"]) / len(sensitive)) if sensitive else None,
            "highest_risk": max((g["score"] for g in reuse), default=0),
            "highest_entry_risk": max(scores, default=0),
            "levels": levels,
            "health": health_score(scores),
        }
        return {**state, "summary": summary, "recommendations": self._recommendations(entries, reuse, similar),
                "graph": self._graph(entries, reuse, similar),
                "settings": {"breach_check": self.breach.enabled, "stale_days": self.settings.stale_days}}

    def _recommendations(self, entries: list[dict], reuse: list[dict], similar: list[dict]) -> list[dict]:
        recs: list[dict] = []
        in_reuse = {i for g in reuse for i in g["ids"]}
        for e in entries:
            if (e["breach_count"] or 0) > 0:
                recs.append({"priority": 1, "title": f"Change the password for {e['label']} now",
                             "detail": f"It appears in {e['breach_count']:,} known data breaches.", "ids": [e["id"]]})
        for g in reuse:
            by_id = {e["id"]: e for e in entries}
            top = max((by_id[i] for i in g["ids"]), key=lambda e: SENSITIVITY_WEIGHTS[e["sensitivity"]])
            recs.append({"priority": 1 if g["level"] == "Critical" else 2 if g["level"] == "High" else 3,
                         "title": "Give each of these accounts its own password: " + ", ".join(g["platforms"]),
                         "detail": f"Start with {top['label']} - one breach of any account exposes all of them.", "ids": g["ids"]})
        weak = [e for e in entries if e["id"] not in in_reuse and e["strength"] and e["strength"]["score"] < 40]
        if len(weak) == 1:
            recs.append({"priority": 3, "title": f"Replace the weak password for {weak[0]['label']}",
                         "detail": f"It is rated {weak[0]['strength']['label'].lower()}. Use a long random passphrase.", "ids": [weak[0]["id"]]})
        elif weak:
            recs.append({"priority": 3, "title": f"Replace {len(weak)} weak passwords: " + ", ".join(e["label"] for e in weak[:5]) + ("..." if len(weak) > 5 else ""),
                         "detail": "Let a password manager generate long random passwords, or use a passphrase of 4+ unrelated words.", "ids": [e["id"] for e in weak]})
        for g in similar:
            recs.append({"priority": 3, "title": "These passwords are variations of one another: " + ", ".join(g["platforms"]),
                         "detail": "Attackers try obvious mutations (new year, extra digit, symbol). Use unrelated passwords.", "ids": g["ids"]})
        for e in entries:
            if e["sensitivity"] != "standard" and e["password_age_days"] > self.settings.very_stale_days:
                recs.append({"priority": 4, "title": f"Rotate the old password for {e['label']}",
                             "detail": f"Unchanged for {e['password_age_days']} days.", "ids": [e["id"]]})
        no_mfa = [e for e in entries if e["sensitivity"] != "standard" and not e["mfa_enabled"]]
        if no_mfa:
            recs.append({"priority": 4, "title": "Turn on two-factor authentication for: " + ", ".join(e["label"] for e in no_mfa[:6]) + ("..." if len(no_mfa) > 6 else ""),
                         "detail": "Even a leaked password is much harder to abuse with a second factor.", "ids": [e["id"] for e in no_mfa]})
        legacy = [e for e in entries if e["legacy"]]
        if legacy:
            recs.append({"priority": 5, "title": f"Re-enter the password for {len(legacy)} record(s) from the old version",
                         "detail": "Use Update -> new password to upgrade them to the stronger fingerprint and enable strength checks.", "ids": [e["id"] for e in legacy]})
        recs.sort(key=lambda r: (r["priority"], r["title"]))
        return recs[:12]

    @staticmethod
    def _graph(entries: list[dict], reuse: list[dict], similar: list[dict]) -> dict:
        edges, seen = [], set()
        for kind, groups in (("exact", reuse), ("similar", similar)):   # exact first: it wins on shared pairs
            for g in groups:
                ids = g["ids"][:10]
                pairs = [(a, b) for n, a in enumerate(ids) for b in ids[n + 1:]] if len(ids) <= 10 else list(zip(ids, ids[1:]))
                for a, b in pairs:
                    if (a, b) not in seen and (b, a) not in seen:
                        seen.add((a, b))
                        edges.append({"source": a, "target": b, "type": kind})
        linked = {e["source"] for e in edges} | {e["target"] for e in edges}
        ordered = sorted(entries, key=lambda e: (e["id"] not in linked, -e["risk_score"], e["label"].lower()))[:40]
        nodes = [{"id": e["id"], "label": e["label"], "short": e["platform"], "level": e["risk_level"], "linked": e["id"] in linked} for e in ordered]
        keep = {n["id"] for n in nodes}
        return {"nodes": nodes, "edges": [e for e in edges if e["source"] in keep and e["target"] in keep]}

    def export_rows(self) -> list[dict]:
        """Metadata only: no fingerprints and, of course, no passwords."""
        return [{
            "platform": e["platform"], "username": e["username"], "sensitivity": e["sensitivity"],
            "two_factor": "yes" if e["mfa_enabled"] else "no", "risk_level": e["risk_level"], "risk_score": e["risk_score"],
            "strength": e["strength"]["label"] if e["strength"] else "unknown",
            "known_breaches": "" if e["breach_count"] is None else e["breach_count"],
            "password_age_days": e["password_age_days"], "reused_with": "; ".join(e["reused_with"]),
            "similar_to": "; ".join(e["similar_with"]), "why": "; ".join(f["label"] for f in e["risk_factors"]),
        } for e in self._state()["entries"]]
