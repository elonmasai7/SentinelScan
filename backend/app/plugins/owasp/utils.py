from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning: mysql_",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"SQLite/JDBCDriver",
    r"SQLSTATE\[",
    r"syntax error at or near",
    r"ORA-\d{5}",
]

SENSITIVE_KEYS = {
    "password",
    "pass",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "ssn",
    "credit_card",
}

SSRF_PARAM_HINTS = {"url", "uri", "redirect", "next", "callback", "dest", "link"}


def hash_body(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return min(len(a), len(b)) / max(len(a), len(b))


def safe_json(response_text: str) -> Any:
    try:
        import json

        return json.loads(response_text)
    except Exception:
        return None


def find_sensitive_fields(payload: Any, hits: List[str]) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key.lower() in SENSITIVE_KEYS:
                hits.append(key)
            find_sensitive_fields(value, hits)
    elif isinstance(payload, list):
        for item in payload:
            find_sensitive_fields(item, hits)


def with_query(base_url: str, params: Dict[str, str]) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def get_query_params(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    return dict(parse_qsl(parsed.query, keep_blank_values=True))
