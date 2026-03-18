from __future__ import annotations

from typing import List

from app.domain.models import FindingDraft
from app.plugins.base import ScannerPlugin, ScanContext


class BrokenAuthenticationPlugin(ScannerPlugin):
    name = "broken_authentication"

    async def run(self, context: ScanContext) -> List[FindingDraft]:
        invalid_headers = {"User-Agent": context.headers.get("User-Agent", ""), "Authorization": "Bearer invalid"}
        invalid_response = await context.client.get(context.target_url, headers=invalid_headers, follow_redirects=True)
        if context.base_response.status_code == 200 and invalid_response.status_code == 200:
            return [
                FindingDraft(
                    title="Broken Authentication or Missing JWT Validation",
                    category="Broken Authentication",
                    severity="high",
                    confidence="medium",
                    evidence="Endpoint returned 200 for invalid/missing JWT.",
                    recommendation="Enforce JWT validation and require authentication for protected endpoints.",
                    plugin=self.name,
                    cwe="CWE-287",
                )
            ]
        return []
