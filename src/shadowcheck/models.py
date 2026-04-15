from __future__ import annotations

from pydantic import BaseModel, Field


class ThreatReport(BaseModel):
    cve_id: str = Field(description="CVE identifier such as CVE-2026-1234")
    severity_score: float = Field(ge=0, le=10)
    is_exploitable_locally: bool
    required_remediation: str
    confidence_level: str = Field(description='One of: "Verified" | "Likely" | "Inferred"')


class ServiceFingerprint(BaseModel):
    host: str
    port: int
    open: bool
    banner: str | None = None


class CVERecord(BaseModel):
    cve_id: str
    description: str
    cvss_score: float
    references: list[str] = Field(default_factory=list)
    vulnerable_version_range: str | None = None


class TriageInput(BaseModel):
    repo_url: str | None = None
    installed_packages: dict[str, str] = Field(default_factory=dict)
    ports_to_scan: list[int] = Field(default_factory=lambda: [22, 80, 443, 8080, 8443])
    target_host: str = "127.0.0.1"
