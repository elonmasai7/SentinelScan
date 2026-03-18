from datetime import datetime
from pydantic import BaseModel, Field
from typing import List, Optional


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    email: str


class AuthRegister(BaseModel):
    email: str
    password: str


class AuthLogin(BaseModel):
    email: str
    password: str


class WorkspaceOut(BaseModel):
    id: str
    name: str


class ProjectOut(BaseModel):
    id: str
    name: str
    workspace_id: str


class ScanCreate(BaseModel):
    target_url: str = Field(..., examples=["https://api.example.com/users/1"])
    bearer_token: Optional[str] = Field(default=None, description="Optional JWT for authenticated scans")
    demo_mode: bool = False
    project_id: str


class FindingOut(BaseModel):
    id: str
    title: str
    category: str
    severity: str
    cvss_score: float
    confidence: str
    plugin: str
    cwe: Optional[str]
    evidence: str
    recommendation: str
    remediation: Optional[str]


class ScanOut(BaseModel):
    id: str
    project_id: str
    target_url: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime]
    summary_risk: Optional[float]
    findings: List[FindingOut] = []


class ScanSummary(BaseModel):
    id: str
    project_id: str
    target_url: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime]
    summary_risk: Optional[float]
