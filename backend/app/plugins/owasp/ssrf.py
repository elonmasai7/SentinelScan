from __future__ import annotations

from typing import List

from app.domain.models import FindingDraft
from app.plugins.base import ScannerPlugin, ScanContext
from app.plugins.owasp.utils import SSRF_PARAM_HINTS, get_query_params, with_query


class SsrfPlugin(ScannerPlugin):
    name = "ssrf"

    async def run(self, context: ScanContext) -> List[FindingDraft]:
        query_params = get_query_params(context.target_url)
        if not query_params:
            return []

        for key in list(query_params.keys()):
            if key.lower() in SSRF_PARAM_HINTS:
                for target in ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data"]:
                    test_params = query_params.copy()
                    test_params[key] = target
                    test_url = with_query(context.target_url, test_params)
                    test_response = await context.client.get(test_url, headers=context.headers, follow_redirects=True)
                    test_text = test_response.text
                    if "meta-data" in test_text or "localhost" in test_text or test_response.status_code >= 500:
                        return [
                            FindingDraft(
                                title="Potential SSRF",
                                category="SSRF",
                                severity="high",
                                confidence="medium",
                                evidence=f"Response changed when injecting SSRF payload into {key}.",
                                recommendation="Validate and allowlist outbound URLs; block internal IP ranges.",
                                plugin=self.name,
                                cwe="CWE-918",
                            )
                        ]
        return []
