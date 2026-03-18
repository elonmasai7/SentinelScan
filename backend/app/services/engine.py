from __future__ import annotations

import asyncio
from typing import List

import httpx

from app.core.config import get_settings
from app.domain.models import ScanResult, FindingDraft
from app.plugins.base import ScanContext, default_headers
from app.plugins.registry import PLUGIN_REGISTRY
from app.plugins.owasp.utils import safe_json


async def run_plugins(target_url: str, bearer_token: str | None) -> ScanResult:
    settings = get_settings()
    headers = default_headers(bearer_token)

    async with httpx.AsyncClient(timeout=settings.request_timeout_s) as client:
        base_response = await client.get(target_url, headers=headers, follow_redirects=True)
        base_text = base_response.text
        base_json = safe_json(base_text)

        context = ScanContext(
            target_url=target_url,
            headers=headers,
            client=client,
            base_response=base_response,
            base_text=base_text,
            base_json=base_json,
        )

        semaphore = asyncio.Semaphore(settings.max_concurrency)

        async def run_plugin(plugin_cls) -> List[FindingDraft]:
            async with semaphore:
                plugin = plugin_cls()
                return await plugin.run(context)

        tasks = [run_plugin(plugin_cls) for plugin_cls in PLUGIN_REGISTRY]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    findings: List[FindingDraft] = [finding for group in results for finding in group]
    return ScanResult(findings=findings)
