"""Tests for data models."""

import json

from cspm.models import Finding, Report, ReportSummary, Severity


def test_finding_creation() -> None:
    """Test creating a Finding."""
    finding = Finding(
        id="TEST-001",
        service="s3",
        resource="my-bucket",
        region="us-east-1",
        title="Test Finding",
        description="A test finding",
        severity=Severity.HIGH,
        remediation="Fix it",
    )
    assert finding.id == "TEST-001"
    assert finding.severity == Severity.HIGH
    assert finding.scanned_at is not None


def test_report_serialization() -> None:
    """Test report serialization to dict and JSON."""
    finding = Finding(
        id="TEST-001",
        service="s3",
        resource="my-bucket",
        region="us-east-1",
        title="Test Finding",
        description="A test finding",
        severity=Severity.HIGH,
        remediation="Fix it",
    )
    summary = ReportSummary(
        total_findings=1,
        high=1,
        services_scanned=["s3"],
        account_id="123456789012",
    )
    report = Report(summary=summary, findings=[finding])

    # Test dict export
    d = report.model_dump(mode="json")
    assert d["summary"]["total_findings"] == 1
    assert d["summary"]["high"] == 1
    assert len(d["findings"]) == 1

    # Test JSON export
    json_str = report.model_dump_json()
    parsed = json.loads(json_str)
    assert parsed["summary"]["account_id"] == "123456789012"


def test_severity_ordering() -> None:
    """Test severity enum values."""
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.LOW.value == "LOW"
    assert Severity.INFO.value == "INFO"
