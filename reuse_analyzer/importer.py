"""Parse password-manager / browser CSV exports (Chrome, Edge, Firefox, Bitwarden, 1Password...).

Exports contain PLAINTEXT passwords, so the text is parsed in memory, fingerprinted and then
discarded - the file content is never written anywhere by this application.
"""
from __future__ import annotations

import csv
import io
from urllib.parse import urlsplit

_PASSWORD = ("password", "login_password", "pass", "pwd")
_USERNAME = ("username", "login_username", "user name", "user", "login", "email")
_NAME = ("name", "title", "website", "site", "account")
_URL = ("url", "login_uri", "uri", "web site", "origin")


def _find(headers: list[str], candidates: tuple[str, ...]) -> int | None:
    lowered = [h.strip().lower() for h in headers]
    for candidate in candidates:
        if candidate in lowered:
            return lowered.index(candidate)
    return None


def host_of(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    parts = urlsplit(url if "://" in url else f"//{url}")
    host = (parts.hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def parse_password_csv(text: str, max_rows: int) -> tuple[list[dict], list[str]]:
    """Return (records, problems). Records: {platform, username, password}."""
    text = text.lstrip("\ufeff")
    if not text.strip():
        raise ValueError("The file is empty.")
    try:
        dialect = csv.Sniffer().sniff(text[:2048], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    headers, body = rows[0], rows[1:]
    password_col = _find(headers, _PASSWORD)
    if password_col is None:
        raise ValueError("Could not find a password column. Expected a header such as: name,url,username,password")
    if len(body) > max_rows:
        raise ValueError(f"The file has {len(body)} rows; the limit is {max_rows}. Split it into smaller files.")
    user_col, name_col, url_col = (_find(headers, c) for c in (_USERNAME, _NAME, _URL))

    def cell(row: list[str], index: int | None) -> str:
        return row[index].strip() if index is not None and index < len(row) else ""

    records: list[dict] = []
    problems: list[str] = []
    for number, row in enumerate(body, start=2):
        if not any(c.strip() for c in row):
            continue
        password = cell(row, password_col)
        platform = cell(row, name_col) or host_of(cell(row, url_col))
        if not password:
            problems.append(f"Row {number}: no password")
        elif not platform:
            problems.append(f"Row {number}: no site name or URL")
        else:
            records.append({"platform": platform, "username": cell(row, user_col), "password": password})
    return records, problems
