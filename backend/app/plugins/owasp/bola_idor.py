from __future__ import annotations

from typing import List
from urllib.parse import urlparse, urlunparse

from app.domain.models import FindingDraft
from app.plugins.base import ScannerPlugin, ScanContext
from app.plugins.owasp.utils import hash_body, similarity


class BolaIdorPlugin(ScannerPlugin):
    name = "bola_idor"

    async def run(self, context: ScanContext) -> List[FindingDraft]:
        parsed = urlparse(context.target_url)
        path_parts = parsed.path.strip("/").split("/")
        for i, part in enumerate(path_parts):
            if part.isdigit():
                alt_parts = path_parts.copy()
                alt_parts[i] = str(int(part) + 1)
                alt_path = "/" + "/".join(alt_parts)
                alt_url = urlunparse(parsed._replace(path=alt_path))
                alt_response = await context.client.get(alt_url, headers=context.headers, follow_redirects=True)
                alt_text = alt_response.text
                if alt_response.status_code == 200:
                    if hash_body(context.base_text) != hash_body(alt_text) and similarity(context.base_text, alt_text) > 0.6:
                        return [
                            FindingDraft(
                                title="Potential BOLA/IDOR",
                                category="BOLA/IDOR",
                                severity="high",
                                confidence="medium",
                                evidence=f"Alternate ID {alt_parts[i]} returned 200 with similar response size.",
                                recommendation="Implement object-level authorization checks on resource access.",
                                plugin=self.name,
                                cwe="CWE-639",
                            )
                        ]
                break
        return []
