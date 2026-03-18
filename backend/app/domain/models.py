from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FindingDraft:
    title: str
    category: str
    severity: str
    confidence: str
    evidence: str
    recommendation: str
    plugin: str
    cwe: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    findings: List[FindingDraft]
