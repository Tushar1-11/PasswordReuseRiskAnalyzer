import io
import json
import logging
import tempfile
import unittest

from app import create_app
from reuse_analyzer import Settings
from tests.helpers import STRONG_A, STRONG_B

TOKEN = "test-token"
H = {"X-CSRF-Token": TOKEN}


class ApiCase(unittest.TestCase):
    config = {}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = create_app({"DATABASE": f"{self.temp.name}/t.db", "SECRET_FILE": f"{self.temp.name}/k",
                               "CSRF_TOKEN": TOKEN, "SETTINGS": Settings(scrypt_log_n=10), "TESTING": True, **self.config})
        self.c = self.app.test_client()

    def add(self, platform, password, **extra):
        return self.c.post("/api/entries", json={"platform": platform, "password": password, **extra}, headers=H)


class EndpointTests(ApiCase):
    def test_original_flow(self):                                    # mirrors the original project's API contract
        self.assertEqual(self.add("Google", STRONG_A).status_code, 201)
        r = self.add("GitHub", STRONG_A)
        self.assertTrue(r.json["reused"])
        data = self.c.get("/api/dashboard").json
        self.assertEqual(data["summary"]["reused_accounts"], 2)
        self.assertEqual(self.c.delete("/api/entries/1", headers=H).status_code, 204)
        self.assertEqual(self.c.delete("/api/entries/1", headers=H).status_code, 404)

    def test_index_and_status(self):
        page = self.c.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(TOKEN.encode(), page.data)
        self.assertFalse(self.c.get("/api/status").json["breach_check"])

    def test_check_does_not_store(self):
        self.add("Google", STRONG_A)
        r = self.c.post("/api/check", json={"password": STRONG_A}, headers=H)
        self.assertTrue(r.json["reused"])
        self.assertEqual(self.c.get("/api/dashboard").json["summary"]["accounts"], 1)

    def test_update_and_validation_errors(self):
        self.add("Google", STRONG_A)
        ok = self.c.put("/api/entries/1", json={"password": STRONG_B, "mfa": True}, headers=H)
        self.assertTrue(ok.json["rotated"])
        self.assertEqual(self.c.put("/api/entries/1", json={"password": STRONG_B}, headers=H).status_code, 400)
        self.assertEqual(self.c.put("/api/entries/99", json={"sensitivity": "critical"}, headers=H).status_code, 404)
        self.assertEqual(self.add("x", "p").status_code, 400)
        self.assertEqual(self.c.get("/api/nope").json["error"], "Not found.")

    def test_erase_requires_confirmation(self):
        self.add("Google", STRONG_A)
        self.assertEqual(self.c.delete("/api/entries", json={}, headers=H).status_code, 400)
        self.assertEqual(self.c.delete("/api/entries", json={"confirm": "ERASE"}, headers=H).json["deleted"], 1)

    def test_suggest(self):
        self.assertEqual(self.c.get("/api/suggest?platform=Gmail").json["sensitivity"], "critical")


class SecurityTests(ApiCase):
    def test_csrf_token_required_for_every_mutation(self):
        self.assertEqual(self.c.post("/api/entries", json={"platform": "Ab", "password": "p"}).status_code, 403)
        self.assertEqual(self.c.post("/api/entries", json={}, headers={"X-CSRF-Token": "wrong"}).status_code, 403)
        self.assertEqual(self.c.delete("/api/entries/1").status_code, 403)
        self.assertEqual(self.c.post("/api/import").status_code, 403)

    def test_foreign_origin_is_blocked_even_with_token(self):
        r = self.c.post("/api/check", json={"password": "x"}, headers={**H, "Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_same_origin_is_allowed(self):
        r = self.c.post("/api/check", json={"password": "x"}, headers={**H, "Origin": "http://localhost"})
        self.assertEqual(r.status_code, 200)

    def test_dns_rebinding_host_is_rejected(self):
        self.assertEqual(self.c.get("/api/status", headers={"Host": "evil.example:5000"}).status_code, 400)
        self.assertEqual(self.c.get("/api/status", headers={"Host": "127.0.0.1:5000"}).status_code, 200)
        self.assertEqual(self.c.get("/api/status", headers={"Host": "[::1]:5000"}).status_code, 200)

    def test_simple_form_posts_are_rejected(self):                   # the original accepted any content-type
        r = self.c.post("/api/entries", data='{"platform":"Evil","password":"x"}', headers={**H, "Content-Type": "text/plain"})
        self.assertEqual(r.status_code, 415)

    def test_security_headers(self):
        r = self.c.get("/")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(self.c.get("/api/dashboard").headers["Cache-Control"], "no-store")

    def test_passwords_are_never_logged(self):
        secret = "Log-Canary-Password-9981"
        with self.assertLogs(level="DEBUG") as captured:
            logging.getLogger().debug("sentinel")
            self.add("Canary", secret)
            self.c.post("/api/check", json={"password": secret}, headers=H)
            self.c.put("/api/entries/1", json={"password": secret + "x"}, headers=H)
        self.assertNotIn(secret, "\n".join(captured.output))

    def test_error_responses_do_not_echo_passwords(self):
        secret = "Echo-Canary-Password-1234"
        r = self.add("x", secret)                                     # invalid platform -> 400
        self.assertNotIn(secret, r.get_data(as_text=True))


class RateLimitTests(ApiCase):
    config = {"RATE_LIMITS": {"check": 3, "write": 100, "import": 1}}

    def test_check_endpoint_is_rate_limited(self):
        codes = [self.c.post("/api/check", json={"password": "x"}, headers=H).status_code for _ in range(5)]
        self.assertEqual(codes, [200, 200, 200, 429, 429])
        self.assertIn("Retry-After", self.c.post("/api/check", json={"password": "x"}, headers=H).headers)


class ImportExportTests(ApiCase):
    def upload(self, text, name="p.csv"):
        return self.c.post("/api/import", data={"file": (io.BytesIO(text.encode()), name)}, headers=H,
                           content_type="multipart/form-data")

    def test_import_then_export(self):
        r = self.upload("name,url,username,password\nGitHub,,me,Pass-One-Orchid-77\nGitLab,,me,Pass-One-Orchid-77\n")
        self.assertEqual(r.json["imported"], 2)
        payload = json.loads(self.c.get("/api/export?format=json").data)
        self.assertEqual(len(payload["accounts"]), 2)
        self.assertNotIn("Pass-One-Orchid-77", self.c.get("/api/export?format=csv").get_data(as_text=True))

    def test_import_errors(self):
        self.assertEqual(self.c.post("/api/import", headers=H).status_code, 400)
        self.assertEqual(self.upload("a,b\n1,2\n").status_code, 400)
        bad = self.c.post("/api/import", data={"file": (io.BytesIO(b"\xff\xfe\x00bad"), "x.csv")}, headers=H,
                          content_type="multipart/form-data")
        self.assertEqual(bad.status_code, 400)

    def test_csv_export_neutralises_formula_injection(self):
        self.add("=HYPERLINK(\"http://evil\")", STRONG_A)
        self.assertIn("'=HYPERLINK", self.c.get("/api/export?format=csv").get_data(as_text=True))

    def test_export_is_an_attachment(self):
        self.assertIn("attachment", self.c.get("/api/export?format=csv").headers["Content-Disposition"])


if __name__ == "__main__":
    unittest.main()
