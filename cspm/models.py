"""Data models for CSPM findings and reports."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    """A single security finding."""

    id: str = Field(..., description="Unique finding identifier")
    rule_id: str = Field(default="", description="Rule identifier for compliance mapping")
    service: str = Field(..., description="AWS service (e.g., s3, iam, ec2)")
    resource: str = Field(..., description="Resource ARN or identifier")
    region: str = Field(..., description="AWS region")
    title: str = Field(..., description="Short title of the finding")
    description: str = Field(..., description="Detailed description")
    severity: Severity = Field(..., description="Severity level")
    remediation: str = Field(..., description="Remediation steps")
    references: list[str] = Field(default_factory=list, description="Documentation links")
    raw_details: dict[str, Any] = Field(
        default_factory=dict, description="Raw API response details"
    )
    scanned_at: datetime = Field(default_factory=datetime.utcnow)


class ReportSummary(BaseModel):
    """Summary statistics for a scan report."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    services_scanned: list[str] = Field(default_factory=list)
    scan_duration_seconds: float = 0.0
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    account_id: str = "unknown"


class Report(BaseModel):
    """Complete CSPM scan report."""

    summary: ReportSummary
    findings: list[Finding] = Field(default_factory=list)
    risk_score: int = 0
    risk_summary: dict[str, Any] = Field(default_factory=dict)
    compliance_mappings: dict[str, list[str]] = Field(default_factory=dict)
