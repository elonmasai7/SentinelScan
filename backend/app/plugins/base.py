from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import get_settings
from app.domain.models import FindingDraft


@dataclass
class ScanContext:
    target_url: str
    headers: Dict[str, str]
    client: httpx.AsyncClient
    base_response: httpx.Response
    base_text: str
    base_json: Optional[Any]


class ScannerPlugin:
    name: str = "base"

    async def run(self, context: ScanContext) -> List[FindingDraft]:
        return []


def default_headers(bearer_token: str | None) -> Dict[str, str]:
    settings = get_settings()
    headers: Dict[str, str] = {"User-Agent": settings.user_agent}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    return headers
