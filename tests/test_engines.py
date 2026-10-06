import unittest

from reuse_analyzer.config import Settings
from reuse_analyzer.importer import host_of, parse_password_csv
from reuse_analyzer.scoring import (health_score, level_for, group_risk, single_risk, suggest_sensitivity)
from reuse_analyzer.similarity import base_form
from reuse_analyzer.strength import assess, load_common_passwords

COMMON = load_common_passwords()


class StrengthTests(unittest.TestCase):
    def score(self, pw):
        return assess(pw, COMMON)

    def test_common_passwords_are_very_weak(self):
        for pw in ("password", "123456", "qwerty123", "P@ssw0rd", "iloveyou"):
            s = self.score(pw)
            self.assertLess(s.score, 20, pw)
            self.assertIn("common", s.flags, pw)

    def test_word_plus_digits_symbol_pattern_is_weak(self):
        for pw in ("Summer2024!", "Tr0ub4dor&3", "Sunshine@123", "Welcome@2024"):
            self.assertLess(self.score(pw).score, 40, pw)

    def test_random_passwords_are_strong(self):
        for pw in ("k8$Zp!2mQx9#Lw4v", "Bq7!vN2#xW9$zL4&"):
            self.assertGreaterEqual(self.score(pw).score, 80, pw)

    def test_passphrases_beat_short_complex_passwords(self):
        self.assertGreater(self.score("blue-sky-river-moon-42").score, self.score("Xy7$q").score)

    def test_patterns_are_flagged(self):
        self.assertIn("repeat", self.score("aaaaaaaaaaaa").flags)
        self.assertIn("sequence", self.score("abcdefgh12345").flags)
        self.assertIn("year", self.score("MyDogSpot1987").flags)
        self.assertIn("short", self.score("Ab1!").flags)

    def test_longer_is_never_weaker_for_random_suffixes(self):
        self.assertLessEqual(self.score("k8$Zp!2m").score, self.score("k8$Zp!2mQx9#Lw4v").score)

    def test_suggestions_exist_for_weak_passwords(self):
        self.assertTrue(self.score("password").suggestions)

    def test_extra_wordlist_extends_the_common_set(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("zebra-unicorn-canary\n")
        try:
            extra = load_common_passwords(f.name)
            self.assertIn("flags", dir(assess("Zebra-Unicorn-Canary", extra)))
            self.assertIn("common", assess("Zebra-Unicorn-Canary", extra).flags)
        finally:
            os.unlink(f.name)


class SimilarityTests(unittest.TestCase):
    def test_variants_share_a_skeleton(self):
        self.assertEqual(base_form("Summer2023!"), base_form("Summer2024#"))
        self.assertEqual(base_form("P@ssw0rd1"), base_form("password"))
        self.assertEqual(base_form("Tr0ub4dor&3"), "troubador")

    def test_unrelated_passwords_differ(self):
        self.assertNotEqual(base_form("Summer2023!"), base_form("Winter2023!"))

    def test_too_short_skeletons_are_ignored(self):
        self.assertIsNone(base_form("abc123"))
        self.assertIsNone(base_form("12345678"))


class ScoringTests(unittest.TestCase):
    S = Settings()

    def row(self, **kw):
        base = dict(sensitivity="standard", mfa_enabled=False, strength_score=90, strength_flags=[],
                    breach_count=None, age_days=0)
        return {**base, **kw}

    def test_levels(self):
        self.assertEqual([level_for(s) for s in (0, 19, 20, 44, 45, 69, 70, 100)],
                         ["Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"])

    def test_group_formula_matches_original_project(self):             # 25 + 15*(n-2) + max sensitivity weight
        rows = [self.row(sensitivity="critical"), self.row(sensitivity="important")]
        self.assertEqual(group_risk(rows, self.S)["score"], 45)
        rows.append(self.row())
        self.assertEqual(group_risk(rows, self.S)["score"], 60)

    def test_score_is_capped_and_factors_sum_to_score(self):
        rows = [self.row(sensitivity="critical", strength_score=5, breach_count=9, age_days=999) for _ in range(9)]
        risk = group_risk(rows, self.S)
        self.assertEqual(risk["score"], 100)
        single = single_risk(self.row(strength_score=10, age_days=500, sensitivity="critical"), 2, self.S)
        self.assertEqual(single["score"], min(100, max(0, sum(f["points"] for f in single["factors"]))))

    def test_clean_unique_account_has_zero_risk(self):
        self.assertEqual(single_risk(self.row(), 0, self.S)["score"], 0)

    def test_breach_dominates_single_account_risk(self):
        self.assertGreaterEqual(single_risk(self.row(breach_count=50), 0, self.S)["score"], 40)

    def test_health_score(self):
        self.assertIsNone(health_score([]))
        self.assertEqual(health_score([0, 0])["grade"], "A")
        self.assertLess(health_score([80, 80])["score"], health_score([10, 10])["score"])

    def test_sensitivity_suggestions(self):
        self.assertEqual(suggest_sensitivity("HDFC Netbanking"), "critical")
        self.assertEqual(suggest_sensitivity("GitHub"), "important")
        self.assertEqual(suggest_sensitivity("Random forum"), "standard")


class ImporterTests(unittest.TestCase):
    def test_formats(self):
        bitwarden = "folder,name,login_uri,login_username,login_password\n,Site A,https://a.com,u1,pw1\n"
        firefox = "url,username,password\nhttps://www.example.org/login,u2,pw2\n"
        self.assertEqual(parse_password_csv(bitwarden, 10)[0], [{"platform": "Site A", "username": "u1", "password": "pw1"}])
        self.assertEqual(parse_password_csv(firefox, 10)[0][0]["platform"], "example.org")

    def test_bom_and_semicolon(self):
        text = "\ufeffname;username;password\nX;u;p\n"
        self.assertEqual(parse_password_csv(text, 10)[0][0]["password"], "p")

    def test_errors(self):
        with self.assertRaisesRegex(ValueError, "password column"):
            parse_password_csv("a,b\n1,2\n", 10)
        with self.assertRaisesRegex(ValueError, "limit"):
            parse_password_csv("name,password\n" + "x,y\n" * 11, 10)
        with self.assertRaises(ValueError):
            parse_password_csv("   ", 10)

    def test_host_of(self):
        self.assertEqual(host_of("https://www.Example.com:8080/x"), "example.com")
        self.assertEqual(host_of(""), "")


if __name__ == "__main__":
    unittest.main()
