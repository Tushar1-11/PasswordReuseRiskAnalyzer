import json
import os
import sqlite3
import unittest

from reuse_analyzer import PasswordReuseAnalyzer
from reuse_analyzer.breach import BreachChecker
from reuse_analyzer.crypto import KeyFileError
from reuse_analyzer.database import KeyMismatchError
from tests.helpers import FAST, STRONG_A, STRONG_B, AnalyzerCase, make_v1_database


class ReuseDetectionTests(AnalyzerCase):
    def test_matching_password_creates_high_risk_group(self):          # original test, still valid
        self.analyzer.add_entry("Email", "correct horse battery staple", "critical")
        result = self.analyzer.add_entry("Bank", "correct horse battery staple", "important")
        dashboard = self.analyzer.dashboard()
        self.assertTrue(result["reused"])
        self.assertEqual(result["reused_on"], ["Email"])
        self.assertEqual(dashboard["summary"]["reused_accounts"], 2)
        self.assertEqual(dashboard["reuse_groups"][0]["level"], "High")

    def test_unique_strong_password_is_low_risk(self):
        self.analyzer.add_entry("Email", STRONG_A, "standard")
        entry = self.analyzer.dashboard()["entries"][0]
        self.assertEqual((entry["risk_level"], entry["risk_score"]), ("Low", 0))

    def test_unique_but_weak_password_is_not_low_risk(self):           # NEW: strength now matters
        result = self.analyzer.add_entry("Email", "unique", "standard")
        self.assertFalse(result["reused"])
        self.assertNotEqual(result["risk"]["level"], "Low")
        self.assertIn("weak", result["message"])

    def test_three_way_reuse_scores_higher_than_two_way(self):
        for name in ("A1", "B2"):
            self.analyzer.add_entry(name, STRONG_A, "standard")
        two = self.analyzer.dashboard()["reuse_groups"][0]["score"]
        self.analyzer.add_entry("C3", STRONG_A, "standard")
        self.assertGreater(self.analyzer.dashboard()["reuse_groups"][0]["score"], two)

    def test_sensitive_account_raises_group_score(self):
        self.analyzer.add_entry("A1", STRONG_A, "standard")
        self.analyzer.add_entry("B2", STRONG_A, "critical")
        factors = [f["label"] for f in self.analyzer.dashboard()["reuse_groups"][0]["factors"]]
        self.assertTrue(any("critical" in f for f in factors))

    def test_two_factor_on_every_account_reduces_group_risk(self):
        self.analyzer.add_entry("A1", STRONG_A, "important", mfa=False)
        self.analyzer.add_entry("B2", STRONG_A, "important", mfa=False)
        without = self.analyzer.dashboard()["reuse_groups"][0]["score"]
        for entry in self.analyzer.dashboard()["entries"]:
            self.analyzer.update_entry(entry["id"], mfa=True)
        self.assertLess(self.analyzer.dashboard()["reuse_groups"][0]["score"], without)

    def test_similar_passwords_are_flagged(self):                      # NEW: variant detection
        self.analyzer.add_entry("LinkedIn", "Summer2023!", "standard")
        result = self.analyzer.add_entry("Instagram", "Summer2024!", "standard")
        self.assertFalse(result["reused"])
        self.assertTrue(result["similar"])
        self.assertEqual(result["similar_to"], ["LinkedIn"])
        self.assertEqual(self.analyzer.dashboard()["summary"]["similar_accounts"], 2)

    def test_unrelated_passwords_are_not_similar(self):
        self.analyzer.add_entry("A1", STRONG_A, "standard")
        self.assertFalse(self.analyzer.add_entry("B2", STRONG_B, "standard")["similar"])

    def test_unicode_normalisation_makes_equivalent_passwords_match(self):
        self.analyzer.add_entry("A1", "caf\u00e9-Lantern-Orbit-92", "standard")          # precomposed é
        self.assertTrue(self.analyzer.add_entry("B2", "cafe\u0301-Lantern-Orbit-92", "standard")["reused"])  # e + combining accent

    def test_stale_password_is_flagged_and_scored(self):
        self.analyzer.add_entry("Old", STRONG_A, "standard")
        self.clock.advance(400)
        entry = self.analyzer.dashboard()["entries"][0]
        self.assertTrue(entry["stale"])
        self.assertGreater(entry["risk_score"], 0)
        self.assertEqual(self.analyzer.dashboard()["summary"]["stale_accounts"], 1)

    def test_check_password_previews_without_saving(self):
        self.analyzer.add_entry("Email", STRONG_A, "critical")
        preview = self.analyzer.check_password(STRONG_A)
        self.assertTrue(preview["reused"])
        self.assertEqual(self.analyzer.dashboard()["summary"]["accounts"], 1)


class RecordManagementTests(AnalyzerCase):
    def test_duplicate_platform_is_rejected_case_insensitively(self):   # original test
        self.analyzer.add_entry("Email", "one", "standard")
        with self.assertRaisesRegex(ValueError, "already have a record"):
            self.analyzer.add_entry("email", "two", "standard")

    def test_same_platform_different_username_is_allowed(self):         # NEW
        self.analyzer.add_entry("Google", STRONG_A, "standard", username="work@x.com")
        self.analyzer.add_entry("Google", STRONG_B, "standard", username="home@x.com")
        self.assertEqual(self.analyzer.dashboard()["summary"]["accounts"], 2)

    def test_validation(self):
        for platform, password, sens in [("x", "p", "standard"), ("Ok", "", "standard"),
                                         ("Ok", None, "standard"), ("Ok", "p", "bogus"), ("a\x00b", "p", "standard")]:
            with self.assertRaises(ValueError, msg=(platform, password, sens)):
                self.analyzer.add_entry(platform, password, sens)
        with self.assertRaisesRegex(ValueError, "longer than"):
            self.analyzer.add_entry("Ok", "x" * 300, "standard")

    def test_rotation_resets_age_and_resolves_reuse(self):
        self.analyzer.add_entry("A1", STRONG_A, "standard")
        b = self.analyzer.add_entry("B2", STRONG_A, "standard")["id"]
        self.clock.advance(200)
        result = self.analyzer.update_entry(b, password=STRONG_B)
        self.assertTrue(result["rotated"])
        self.assertFalse(result["reused"])
        dashboard = self.analyzer.dashboard()
        self.assertEqual(dashboard["reuse_groups"], [])
        self.assertEqual(next(e for e in dashboard["entries"] if e["id"] == b)["password_age_days"], 0)

    def test_rotation_to_the_same_password_is_rejected(self):
        entry = self.analyzer.add_entry("A1", STRONG_A, "standard")["id"]
        with self.assertRaisesRegex(ValueError, "identical"):
            self.analyzer.update_entry(entry, password=STRONG_A)

    def test_metadata_update_keeps_fingerprint_and_age(self):
        entry = self.analyzer.add_entry("A1", STRONG_A, "standard")["id"]
        self.clock.advance(50)
        self.analyzer.update_entry(entry, sensitivity="critical", mfa=True, username="me")
        view = self.analyzer.dashboard()["entries"][0]
        self.assertEqual((view["sensitivity"], view["mfa_enabled"], view["username"], view["password_age_days"]),
                         ("critical", True, "me", 50))

    def test_update_missing_entry_raises_lookup_error(self):
        with self.assertRaises(LookupError):
            self.analyzer.update_entry(999, sensitivity="critical")

    def test_delete_and_delete_all(self):
        a = self.analyzer.add_entry("A1", STRONG_A, "standard")["id"]
        self.analyzer.add_entry("B2", STRONG_B, "standard")
        self.assertTrue(self.analyzer.delete_entry(a))
        self.assertFalse(self.analyzer.delete_entry(a))
        self.assertEqual(self.analyzer.delete_all(), 1)
        self.assertEqual(self.analyzer.dashboard()["summary"]["accounts"], 0)

    def test_recommendations_prioritise_reuse_and_breaches(self):
        self.analyzer.add_entry("Email", STRONG_A, "critical")
        self.analyzer.add_entry("Bank", STRONG_A, "critical")
        recs = self.analyzer.dashboard()["recommendations"]
        self.assertEqual(recs[0]["priority"], 2)          # two critical accounts: score 45 -> "High"
        self.assertIn("Email", recs[0]["title"])


class PrivacyTests(AnalyzerCase):
    def test_plaintext_password_never_reaches_the_database_file(self):
        secret = "Zebra-Unicorn-Plaintext-Canary-4471"
        self.analyzer.add_entry("Canary", secret, "standard")
        self.analyzer.update_entry(1, password=secret + "-v2")
        self.analyzer.delete_all()
        self.analyzer.add_entry("Canary2", secret, "standard")
        raw = (self.root / "t.sqlite3").read_bytes()
        self.assertNotIn(secret.encode(), raw)
        self.assertNotIn(secret.lower().encode(), raw)

    def test_export_contains_no_fingerprints_or_passwords(self):
        self.analyzer.add_entry("Email", STRONG_A, "critical")
        blob = json.dumps(self.analyzer.export_rows())
        fingerprint = self.analyzer.engine.fingerprint(STRONG_A)
        self.assertNotIn(fingerprint, blob)
        self.assertNotIn(STRONG_A, blob)

    def test_fingerprints_differ_between_installations(self):
        other = self.root / "other"
        other.mkdir()
        second = PasswordReuseAnalyzer(str(other / "d.sqlite3"), str(other / "key"), FAST)
        self.assertNotEqual(self.analyzer.engine.fingerprint("same"), second.engine.fingerprint("same"))

    def test_master_passphrase_changes_the_fingerprint_and_is_detected(self):
        self.analyzer.add_entry("Email", STRONG_A, "standard")
        with self.assertRaises(KeyMismatchError):
            self.make(settings=FAST.__class__(scrypt_log_n=10, master_passphrase="extra secret"))

    def test_key_file_is_never_silently_regenerated(self):
        (self.root / "key").write_bytes(b"short")
        with self.assertRaises(KeyFileError):
            self.make()

    @unittest.skipIf(os.name == "nt", "POSIX permissions only")
    def test_key_file_is_owner_only(self):
        self.assertEqual((self.root / "key").stat().st_mode & 0o077, 0)


class MigrationTests(AnalyzerCase):
    create_analyzer = False

    def test_v1_database_is_migrated_and_old_rows_still_match(self):
        make_v1_database(self.root, [("Google", "Hunter-Two-Orchid-55", "standard"), ("GitHub", "Hunter-Two-Orchid-55", "important")])
        analyzer = self.make()
        self.assertTrue((self.root / "t.sqlite3.v1.bak").exists(), "a backup must be made before migrating")
        dashboard = analyzer.dashboard()
        self.assertEqual(dashboard["summary"]["accounts"], 2)
        self.assertEqual(dashboard["summary"]["legacy_accounts"], 2)
        self.assertEqual(len(dashboard["reuse_groups"]), 1, "legacy rows keep their reuse grouping")
        result = analyzer.add_entry("Dropbox", "Hunter-Two-Orchid-55", "standard")
        self.assertEqual(sorted(result["reused_on"]), ["GitHub", "Google"])
        self.assertEqual(analyzer.dashboard()["summary"]["legacy_accounts"], 0, "matched legacy rows are upgraded for free")

    def test_migration_is_idempotent(self):
        make_v1_database(self.root, [("Google", "pw-Alpha-Beta-91", "standard")])
        self.make()
        again = self.make()
        self.assertEqual(again.dashboard()["summary"]["accounts"], 1)

    def test_legacy_rows_can_be_rotated(self):
        make_v1_database(self.root, [("Google", "Old-Legacy-Pass-77", "standard")])
        analyzer = self.make()
        result = analyzer.update_entry(1, password=STRONG_A)
        self.assertTrue(result["rotated"])
        self.assertFalse(analyzer.dashboard()["entries"][0]["legacy"])


class BreachTests(AnalyzerCase):
    def checker(self, body=None, error=None):
        def fetch(prefix):
            if error:
                raise error
            return body(prefix) if callable(body) else body
        return BreachChecker(enabled=True, fetcher=fetch)

    def test_breach_count_is_stored_and_raises_risk(self):
        import hashlib
        suffix = hashlib.sha1(b"Summer2024!").hexdigest().upper()[5:]
        analyzer = self.make(breach_checker=self.checker(f"0000000000000000000000000000000000A:3\r\n{suffix}:12345\r\n"))
        result = analyzer.add_entry("Mail", "Summer2024!", "standard")
        self.assertEqual(result["breach_count"], 12345)
        self.assertIn("breaches", result["message"])
        self.assertEqual(analyzer.dashboard()["summary"]["breached_accounts"], 1)
        self.assertEqual(analyzer.dashboard()["recommendations"][0]["priority"], 1)

    def test_only_a_five_character_prefix_is_ever_sent(self):
        sent = []
        analyzer = self.make(breach_checker=self.checker(lambda p: sent.append(p) or ""))
        analyzer.add_entry("Mail", STRONG_A, "standard")
        self.assertEqual([len(p) for p in sent], [5])

    def test_not_found_means_zero_and_network_failure_means_unknown(self):
        self.assertEqual(self.checker("ABCDE:1").check(STRONG_A), 0)
        self.assertIsNone(self.checker(error=OSError("offline")).check(STRONG_A))

    def test_disabled_by_default_and_https_enforced(self):
        self.assertIsNone(self.analyzer.add_entry("Mail", STRONG_A, "standard")["breach_count"])
        with self.assertRaises(ValueError):
            BreachChecker(enabled=True, url="http://insecure.example/range/")


class CsvImportTests(AnalyzerCase):
    CHROME = "name,url,username,password,note\nGitHub,https://github.com/login,me,Pass-One-Orchid-77,\nnews.site,https://www.news.site/,me,Pass-One-Orchid-77,\n"

    def test_import_creates_records_and_detects_reuse(self):
        result = self.analyzer.import_csv(self.CHROME)
        self.assertEqual((result["imported"], result["skipped_duplicates"]), (2, 0))
        self.assertEqual(result["summary"]["reused_accounts"], 2)

    def test_reimporting_the_same_file_skips_duplicates(self):
        self.analyzer.import_csv(self.CHROME)
        self.assertEqual(self.analyzer.import_csv(self.CHROME)["skipped_duplicates"], 2)

    def test_invalid_rows_are_reported_not_fatal(self):
        result = self.analyzer.import_csv("name,url,username,password\nOK,,me,Pass-Two-Orchid-31\n,,,\nNoPw,,me,\n")
        self.assertEqual((result["imported"], result["skipped_invalid"]), (1, 1))

    def test_import_text_is_not_persisted_anywhere(self):
        self.analyzer.import_csv("name,url,username,password\nCanary,,me,Import-Canary-Pass-8812\n")
        self.assertNotIn(b"Import-Canary-Pass-8812", (self.root / "t.sqlite3").read_bytes())

    def test_sensitivity_is_guessed_from_the_name(self):
        self.analyzer.import_csv("name,url,username,password\nHDFC Bank,,me,Pass-Three-Orchid-12\nRandomForum,,me,Pass-Four-Orchid-34\n")
        by_name = {e["platform"]: e["sensitivity"] for e in self.analyzer.dashboard()["entries"]}
        self.assertEqual((by_name["HDFC Bank"], by_name["RandomForum"]), ("critical", "standard"))


class CompatibilityTests(unittest.TestCase):
    def test_original_import_path_still_works(self):
        from analyzer import PasswordReuseAnalyzer as Legacy
        self.assertIs(Legacy, PasswordReuseAnalyzer)


if __name__ == "__main__":
    unittest.main()
