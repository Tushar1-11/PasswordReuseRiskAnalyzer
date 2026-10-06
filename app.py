from __future__ import annotations

import argparse
import csv
import io
import os
import secrets
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import HTTPException, UnsupportedMediaType

from reuse_analyzer import PasswordReuseAnalyzer, Settings, __version__
from reuse_analyzer.demo import seed_demo
from reuse_analyzer.scoring import suggest_sensitivity
from reuse_analyzer.security import LOOPBACK_HOSTS, install_security, rate_limited


def _flag(value) -> bool:
    return value if isinstance(value, bool) else str(value).strip().lower() in {"1", "true", "yes", "on"}


def _csv_safe(value):
    """Neutralise spreadsheet formula injection in exported cells."""
    return "'" + value if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=os.path.join(app.instance_path, "password_risk.sqlite3"),
        SECRET_FILE=os.path.join(app.instance_path, "fingerprint.key"),
        SETTINGS=None,
        ALLOWED_HOSTS=set(LOOPBACK_HOSTS),
        CSRF_TOKEN=None,
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        RATE_LIMITS={"check": 90, "write": 120, "import": 6},
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    settings = app.config["SETTINGS"] or Settings.from_env()
    analyzer = PasswordReuseAnalyzer(app.config["DATABASE"], app.config["SECRET_FILE"], settings)
    analyzer.initialize()
    app.extensions["reuse_analyzer"] = analyzer

    csrf_token = app.config["CSRF_TOKEN"] or secrets.token_urlsafe(32)
    allowed_hosts = {h.lower() for h in app.config["ALLOWED_HOSTS"]}
    limiter = install_security(app, allowed_hosts, csrf_token)
    limits = app.config["RATE_LIMITS"]

    # ------------------------------------------------------------------ errors (JSON for the API)
    @app.errorhandler(HTTPException)
    def http_error(error: HTTPException):
        if request.path.startswith("/api/"):
            messages = {404: "Not found.", 405: "Method not allowed.", 413: "Request too large.",
                        415: "Send the request as application/json."}
            return jsonify(error=messages.get(error.code, error.description)), error.code
        return error

    @app.errorhandler(LookupError)
    def not_found(error: LookupError):
        return jsonify(error=str(error.args[0]) if error.args else "Not found."), 404

    @app.errorhandler(ValueError)
    def bad_request(error: ValueError):
        return jsonify(error=str(error)), 400

    def body() -> dict:
        if not request.is_json:
            raise UnsupportedMediaType()
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValueError("The request body must be a JSON object.")
        return data

    # ------------------------------------------------------------------ pages and read-only API
    @app.get("/")
    def index():
        return render_template("index.html", csrf_token=csrf_token, version=__version__)

    @app.get("/api/status")
    def status():
        return jsonify(version=__version__, breach_check=analyzer.breach.enabled, kdf="scrypt",
                       passphrase_protected=bool(settings.master_passphrase), stale_days=settings.stale_days)

    @app.get("/api/dashboard")
    def dashboard():
        return jsonify(analyzer.dashboard())

    @app.get("/api/suggest")
    def suggest():
        return jsonify(sensitivity=suggest_sensitivity(request.args.get("platform", "")))

    # ------------------------------------------------------------------ analysis and records
    @app.post("/api/check")
    @rate_limited(limiter, "check", limits["check"])
    def check():
        data = body()
        exclude = data.get("exclude_id")
        return jsonify(analyzer.check_password(data.get("password"), str(data.get("sensitivity", "standard")),
                                               _flag(data.get("mfa", False)), exclude if isinstance(exclude, int) else None))

    @app.post("/api/entries")
    @rate_limited(limiter, "write", limits["write"])
    def add_entry():
        data = body()
        result = analyzer.add_entry(str(data.get("platform", "")), data.get("password"),
                                    str(data.get("sensitivity", "standard")), str(data.get("username") or ""),
                                    _flag(data.get("mfa", False)))
        return jsonify(result), 201

    @app.put("/api/entries/<int:entry_id>")
    @rate_limited(limiter, "write", limits["write"])
    def update_entry(entry_id: int):
        data = body()
        return jsonify(analyzer.update_entry(
            entry_id, password=data.get("password"), sensitivity=data.get("sensitivity"),
            mfa=_flag(data["mfa"]) if "mfa" in data else None, username=data.get("username"),
            platform=data.get("platform")))

    @app.delete("/api/entries/<int:entry_id>")
    @rate_limited(limiter, "write", limits["write"])
    def delete_entry(entry_id: int):
        if not analyzer.delete_entry(entry_id):
            return jsonify({"error": "Account record not found."}), 404
        return "", 204

    @app.delete("/api/entries")
    @rate_limited(limiter, "write", limits["write"])
    def delete_all():
        if body().get("confirm") != "ERASE":
            raise ValueError('Type ERASE to confirm deleting every record.')
        return jsonify(deleted=analyzer.delete_all())

    # ------------------------------------------------------------------ import / export
    @app.post("/api/import")
    @rate_limited(limiter, "import", limits["import"])
    def import_csv():
        upload = request.files.get("file")
        if upload is None:
            raise ValueError("Choose a CSV file to import.")
        raw = upload.stream.read(settings.max_import_bytes + 1)
        if len(raw) > settings.max_import_bytes:
            raise ValueError(f"The file is larger than {settings.max_import_bytes // 1000} KB.")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise ValueError("The file must be UTF-8 text (CSV).") from None
        return jsonify(analyzer.import_csv(text))

    @app.get("/api/export")
    def export():
        rows = analyzer.export_rows()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        if request.args.get("format", "json") == "csv":
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=list(rows[0]) if rows else ["platform"])
            writer.writeheader()
            writer.writerows({k: _csv_safe(v) for k, v in row.items()} for row in rows)
            payload, mime, ext = buffer.getvalue(), "text/csv", "csv"
        else:
            import json
            payload = json.dumps({"exported_at": datetime.now(timezone.utc).isoformat(), "accounts": rows}, indent=2)
            mime, ext = "application/json", "json"
        return Response(payload, mimetype=mime,
                        headers={"Content-Disposition": f"attachment; filename=password-risk-report-{stamp}.{ext}"})

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Smart Password Reuse Risk Analyzer (local web app)")
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--allow-remote", action="store_true",
                        help="permit binding a non-loopback address (NOT recommended: the app has no login)")
    parser.add_argument("--demo", action="store_true", help="use a separate demo database filled with sample accounts")
    args = parser.parse_args()

    if args.host not in LOOPBACK_HOSTS and not args.allow_remote:
        parser.error("Refusing to listen on a non-loopback address: this app has no login screen. "
                     "Pass --allow-remote only if you understand the risk.")

    config: dict = {"ALLOWED_HOSTS": set(LOOPBACK_HOSTS) | ({args.host} if args.allow_remote else set())}
    if args.demo:
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance")
        config.update(DATABASE=os.path.join(base, "demo.sqlite3"), SECRET_FILE=os.path.join(base, "demo.key"))
    app = create_app(config)
    if args.demo:
        added = seed_demo(app.extensions["reuse_analyzer"])
        print(f"Demo mode: {'seeded ' + str(added) + ' sample accounts' if added else 'using existing demo data'}.")
    print(f"Open http://{args.host}:{args.port}  (Ctrl+C to stop)")
    app.run(host=args.host, port=args.port, debug=False)  # never enable the Werkzeug debugger here


if __name__ == "__main__":
    main()
