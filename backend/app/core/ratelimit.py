from __future__ import annotations

import time
from typing import Tuple

from redis.asyncio import Redis

from app.core.config import get_settings


async def check_rate_limit(redis: Redis, key: str) -> Tuple[bool, int, int, int]:
    settings = get_settings()
    if not settings.rate_limit_enabled:
        return True, settings.rate_limit_per_minute, 0, 0

    window = 60
    limit = settings.rate_limit_per_minute
    now = int(time.time())
    current_window = now // window
    window_key = f"rate:{key}:{current_window}"

    current = await redis.incr(window_key)
    if current == 1:
        await redis.expire(window_key, window)
    remaining = max(0, limit - current)
    retry_after = max(0, window - (now % window))
    reset_at = (current_window + 1) * window
    return current <= limit, remaining, retry_after, reset_at
