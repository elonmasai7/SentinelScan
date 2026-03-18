from __future__ import annotations

SEVERITY_SCORES = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}


def cvss_score(severity: str) -> float:
    return SEVERITY_SCORES.get(severity.lower(), 0.0)
