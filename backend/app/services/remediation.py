from __future__ import annotations

from typing import Dict

from app.domain.models import FindingDraft


class RemediationService:
    async def explain(self, finding: FindingDraft) -> str:
        raise NotImplementedError


class HeuristicRemediationService(RemediationService):
    def __init__(self) -> None:
        self._templates: Dict[str, str] = {
            "BOLA/IDOR": "Enforce object-level authorization checks in your handlers and ensure IDs are always scoped to the authenticated user or tenant.",
            "Broken Authentication": "Require valid JWTs on protected routes, validate issuer/audience/expiry, and implement refresh token rotation.",
            "Excessive Data Exposure": "Return minimal DTOs, apply field-level filtering, and avoid exposing secrets in API serializers.",
            "Rate Limiting": "Add rate limiting by IP/user, return Retry-After headers, and monitor for abuse patterns.",
            "SQL Injection": "Use parameterized queries and ORM query builders; block dangerous characters at validation boundaries.",
            "SSRF": "Allowlist outbound domains, block internal ranges, and validate URL schemes server-side.",
            "Missing Security Headers": "Set HSTS, define CSP, and explicitly configure CORS with least privilege.",
        }

    async def explain(self, finding: FindingDraft) -> str:
        return self._templates.get(
            finding.category,
            "Apply strict input validation, authentication, and least-privilege principles to mitigate this risk.",
        )


def get_remediation_service() -> RemediationService:
    return HeuristicRemediationService()
