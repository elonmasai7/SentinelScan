from __future__ import annotations

import re
from typing import List

from app.domain.models import FindingDraft
from app.plugins.base import ScannerPlugin, ScanContext
from app.plugins.owasp.utils import SQL_ERROR_PATTERNS, get_query_params, with_query


class SqlInjectionPlugin(ScannerPlugin):
    name = "sql_injection"

    async def run(self, context: ScanContext) -> List[FindingDraft]:
        query_params = get_query_params(context.target_url)
        if not query_params:
            return []

        for key in list(query_params.keys()):
            payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "'--", "') OR ('1'='1"]
            for payload in payloads:
                test_params = query_params.copy()
                test_params[key] = payload
                test_url = with_query(context.target_url, test_params)
                test_response = await context.client.get(test_url, headers=context.headers, follow_redirects=True)
                test_text = test_response.text
                if test_response.status_code >= 500:
                    return [
                        FindingDraft(
                            title="Potential SQL Injection",
                            category="SQL Injection",
                            severity="critical",
                            confidence="medium",
                            evidence=f"Server error when injecting into {key}.",
                            recommendation="Use parameterized queries and strict input validation.",
                            plugin=self.name,
                            cwe="CWE-89",
                        )
                    ]
                if any(re.search(pat, test_text, re.IGNORECASE) for pat in SQL_ERROR_PATTERNS):
                    return [
                        FindingDraft(
                            title="Potential SQL Injection",
                            category="SQL Injection",
                            severity="critical",
                            confidence="high",
                            evidence=f"SQL error pattern detected in response for param {key}.",
                            recommendation="Use parameterized queries and avoid string concatenation for SQL.",
                            plugin=self.name,
                            cwe="CWE-89",
                        )
                    ]
        return []
