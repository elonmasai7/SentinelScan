from __future__ import annotations

from typing import List

from app.domain.models import FindingDraft
from app.plugins.base import ScannerPlugin, ScanContext
from app.plugins.owasp.utils import find_sensitive_fields


class ExcessiveDataExposurePlugin(ScannerPlugin):
    name = "excessive_data_exposure"

    async def run(self, context: ScanContext) -> List[FindingDraft]:
        if context.base_json is None:
            return []
        hits: List[str] = []
        find_sensitive_fields(context.base_json, hits)
        if not hits:
            return []

        return [
            FindingDraft(
                title="Excessive Data Exposure",
                category="Excessive Data Exposure",
                severity="high",
                confidence="high",
                evidence=f"Sensitive fields in response: {', '.join(sorted(set(hits)))}",
                recommendation="Filter sensitive fields server-side and return only required data.",
                plugin=self.name,
                cwe="CWE-200",
            )
        ]
