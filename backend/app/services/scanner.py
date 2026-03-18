import hashlib
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Tuple
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db import models
from app.db.session import AsyncSessionLocal


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


def _hash_body(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _cvss_for(severity: str) -> float:
    mapping = {
        "critical": 9.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 3.0,
        "info": 0.0,
    }
    return mapping.get(severity.lower(), 0.0)


def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return min(len(a), len(b)) / max(len(a), len(b))


def _add_finding(findings: List[Dict[str, Any]], title: str, category: str, severity: str, confidence: str, evidence: str, recommendation: str) -> None:
    findings.append(
        {
            "id": str(uuid.uuid4()),
            "title": title,
            "category": category,
            "severity": severity,
            "cvss_score": _cvss_for(severity),
            "confidence": confidence,
            "evidence": evidence,
            "recommendation": recommendation,
        }
    )


def _safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except Exception:
        return None


def _find_sensitive_fields(payload: Any, hits: List[str]) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key.lower() in SENSITIVE_KEYS:
                hits.append(key)
            _find_sensitive_fields(value, hits)
    elif isinstance(payload, list):
        for item in payload:
            _find_sensitive_fields(item, hits)


def _with_query(base_url: str, params: Dict[str, str]) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


async def _fetch(client: httpx.AsyncClient, url: str, headers: Dict[str, str]) -> Tuple[httpx.Response, str]:
    response = await client.get(url, headers=headers, follow_redirects=True)
    text = response.text
    return response, text


async def run_scan(session: AsyncSession, scan_id: str, target_url: str, bearer_token: str | None) -> None:
    settings = get_settings()

    scan = await session.get(models.Scan, scan_id)
    if scan:
        scan.status = "running"
        await session.commit()

    headers: Dict[str, str] = {"User-Agent": settings.user_agent}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    findings: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=settings.request_timeout_s) as client:
        base_response, base_text = await _fetch(client, target_url, headers)
        base_json = _safe_json(base_response)

        # Security headers
        missing_headers = []
        for header in ["Strict-Transport-Security", "Content-Security-Policy", "Access-Control-Allow-Origin"]:
            if header not in base_response.headers:
                missing_headers.append(header)
        if missing_headers:
            _add_finding(
                findings,
                title="Missing Security Headers",
                category="Missing Security Headers",
                severity="medium" if "Content-Security-Policy" in missing_headers else "low",
                confidence="medium",
                evidence=f"Missing headers: {', '.join(missing_headers)}",
                recommendation="Set CORS explicitly, enable HSTS, and define a strict Content-Security-Policy.",
            )

        # Excessive data exposure
        hits: List[str] = []
        if base_json is not None:
            _find_sensitive_fields(base_json, hits)
        if hits:
            _add_finding(
                findings,
                title="Excessive Data Exposure",
                category="Excessive Data Exposure",
                severity="high",
                confidence="high",
                evidence=f"Sensitive fields in response: {', '.join(sorted(set(hits)))}",
                recommendation="Filter sensitive fields server-side and return only required data.",
            )

        # Broken authentication (missing or weak JWT enforcement)
        invalid_headers = {"User-Agent": settings.user_agent, "Authorization": "Bearer invalid"}
        invalid_response, invalid_text = await _fetch(client, target_url, invalid_headers)
        if base_response.status_code == 200 and invalid_response.status_code == 200:
            _add_finding(
                findings,
                title="Broken Authentication or Missing JWT Validation",
                category="Broken Authentication",
                severity="high",
                confidence="medium",
                evidence="Endpoint returned 200 for invalid/missing JWT.",
                recommendation="Enforce JWT validation and require authentication for protected endpoints.",
            )

        # BOLA / IDOR
        parsed = urlparse(target_url)
        path_parts = parsed.path.strip("/").split("/")
        bola_checked = False
        for i, part in enumerate(path_parts):
            if part.isdigit():
                bola_checked = True
                alt_parts = path_parts.copy()
                alt_parts[i] = str(int(part) + 1)
                alt_path = "/" + "/".join(alt_parts)
                alt_url = urlunparse(parsed._replace(path=alt_path))
                alt_response, alt_text = await _fetch(client, alt_url, headers)
                if alt_response.status_code == 200:
                    if _hash_body(base_text) != _hash_body(alt_text) and _similarity(base_text, alt_text) > 0.6:
                        _add_finding(
                            findings,
                            title="Potential BOLA/IDOR",
                            category="BOLA/IDOR",
                            severity="high",
                            confidence="medium",
                            evidence=f"Alternate ID {alt_parts[i]} returned 200 with similar response size.",
                            recommendation="Implement object-level authorization checks on resource access.",
                        )
                break
        if not bola_checked:
            pass

        # SQL injection / query param probing
        query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if query_params:
            for key in list(query_params.keys()):
                payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "'--", "') OR ('1'='1"]
                for payload in payloads:
                    test_params = query_params.copy()
                    test_params[key] = payload
                    test_url = _with_query(target_url, test_params)
                    test_response, test_text = await _fetch(client, test_url, headers)
                    combined_text = f"{test_text}"
                    if test_response.status_code >= 500:
                        _add_finding(
                            findings,
                            title="Potential SQL Injection",
                            category="SQL Injection",
                            severity="critical",
                            confidence="medium",
                            evidence=f"Server error when injecting into {key}.",
                            recommendation="Use parameterized queries and strict input validation.",
                        )
                        break
                    if any(re.search(pat, combined_text, re.IGNORECASE) for pat in SQL_ERROR_PATTERNS):
                        _add_finding(
                            findings,
                            title="Potential SQL Injection",
                            category="SQL Injection",
                            severity="critical",
                            confidence="high",
                            evidence=f"SQL error pattern detected in response for param {key}.",
                            recommendation="Use parameterized queries and avoid string concatenation for SQL.",
                        )
                        break

        # SSRF
        if query_params:
            for key in list(query_params.keys()):
                if key.lower() in SSRF_PARAM_HINTS:
                    for target in ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data"]:
                        test_params = query_params.copy()
                        test_params[key] = target
                        test_url = _with_query(target_url, test_params)
                        test_response, test_text = await _fetch(client, test_url, headers)
                        if "meta-data" in test_text or "localhost" in test_text or test_response.status_code >= 500:
                            _add_finding(
                                findings,
                                title="Potential SSRF",
                                category="SSRF",
                                severity="high",
                                confidence="medium",
                                evidence=f"Response changed when injecting SSRF payload into {key}.",
                                recommendation="Validate and allowlist outbound URLs; block internal IP ranges.",
                            )
                            break

        # Rate limiting
        rate_limit_headers = {"x-ratelimit-remaining", "ratelimit-remaining", "retry-after"}
        probe_statuses: List[int] = []
        for _ in range(settings.rate_limit_probe_requests):
            resp, _ = await _fetch(client, target_url, headers)
            probe_statuses.append(resp.status_code)
            if resp.status_code == 429:
                break
        has_rate_headers = any(h.lower() in rate_limit_headers for h in base_response.headers.keys())
        if 429 not in probe_statuses and not has_rate_headers:
            _add_finding(
                findings,
                title="Missing Rate Limiting",
                category="Rate Limiting",
                severity="medium",
                confidence="medium",
                evidence=f"{len(probe_statuses)} rapid requests without 429 or rate limit headers.",
                recommendation="Apply rate limiting per IP/user and return standard rate limit headers.",
            )

    # Persist findings
    scan = await session.get(models.Scan, scan_id)
    if not scan:
        return

    scan.status = "completed"
    scan.completed_at = datetime.utcnow()
    scan.summary_risk = max((f["cvss_score"] for f in findings), default=0.0)

    for finding in findings:
        session.add(
            models.Finding(
                id=finding["id"],
                scan_id=scan_id,
                title=finding["title"],
                category=finding["category"],
                severity=finding["severity"],
                cvss_score=finding["cvss_score"],
                confidence=finding["confidence"],
                evidence=finding["evidence"],
                recommendation=finding["recommendation"],
            )
        )
    await session.commit()


async def run_scan_background(scan_id: str, target_url: str, bearer_token: str | None) -> None:
    async with AsyncSessionLocal() as session:
        try:
            await run_scan(session, scan_id, target_url, bearer_token)
        except Exception as exc:
            scan = await session.get(models.Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                scan.summary_risk = 0.0
                session.add(scan)
                await session.commit()
