from __future__ import annotations

from typing import List, Type

from app.plugins.base import ScannerPlugin
from app.plugins.owasp.missing_headers import MissingSecurityHeadersPlugin
from app.plugins.owasp.excessive_data import ExcessiveDataExposurePlugin
from app.plugins.owasp.broken_auth import BrokenAuthenticationPlugin
from app.plugins.owasp.bola_idor import BolaIdorPlugin
from app.plugins.owasp.rate_limit import RateLimitingPlugin
from app.plugins.owasp.sqli import SqlInjectionPlugin
from app.plugins.owasp.ssrf import SsrfPlugin


PLUGIN_REGISTRY: List[Type[ScannerPlugin]] = [
    MissingSecurityHeadersPlugin,
    ExcessiveDataExposurePlugin,
    BrokenAuthenticationPlugin,
    BolaIdorPlugin,
    RateLimitingPlugin,
    SqlInjectionPlugin,
    SsrfPlugin,
]
