from __future__ import annotations

from typing import List

from app.domain.models import FindingDraft
from app.plugins.base import ScannerPlugin, ScanContext


class MissingSecurityHeadersPlugin(ScannerPlugin):
    name = "missing_security_headers"

    async def run(self, context: ScanContext) -> List[FindingDraft]:
        missing = []
        for header in ["Strict-Transport-Security", "Content-Security-Policy", "Access-Control-Allow-Origin"]:
            if header not in context.base_response.headers:
                missing.append(header)
        if not missing:
            return []

        severity = "medium" if "Content-Security-Policy" in missing else "low"
        return [
            FindingDraft(
                title="Missing Security Headers",
                category="Missing Security Headers",
                severity=severity,
                confidence="medium",
                evidence=f"Missing headers: {', '.join(missing)}",
                recommendation="Set CORS explicitly, enable HSTS, and define a strict Content-Security-Policy.",
                plugin=self.name,
                cwe="CWE-693",
            )
        ]
