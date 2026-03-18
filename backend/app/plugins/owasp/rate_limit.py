from __future__ import annotations

from typing import List

from app.core.config import get_settings
from app.domain.models import FindingDraft
from app.plugins.base import ScannerPlugin, ScanContext


class RateLimitingPlugin(ScannerPlugin):
    name = "rate_limiting"

    async def run(self, context: ScanContext) -> List[FindingDraft]:
        settings = get_settings()
        rate_limit_headers = {"x-ratelimit-remaining", "ratelimit-remaining", "retry-after"}
        probe_statuses: List[int] = []
        for _ in range(settings.rate_limit_probe_requests):
            resp = await context.client.get(context.target_url, headers=context.headers, follow_redirects=True)
            probe_statuses.append(resp.status_code)
            if resp.status_code == 429:
                break
        has_rate_headers = any(h.lower() in rate_limit_headers for h in context.base_response.headers.keys())
        if 429 not in probe_statuses and not has_rate_headers:
            return [
                FindingDraft(
                    title="Missing Rate Limiting",
                    category="Rate Limiting",
                    severity="medium",
                    confidence="medium",
                    evidence=f"{len(probe_statuses)} rapid requests without 429 or rate limit headers.",
                    recommendation="Apply rate limiting per IP/user and return standard rate limit headers.",
                    plugin=self.name,
                    cwe="CWE-770",
                )
            ]
        return []
