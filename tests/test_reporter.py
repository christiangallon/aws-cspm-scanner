"""Tests for reporter."""

from cspm.models import Finding, Severity
from cspm.reporter import Reporter


def test_generate_report() -> None:
    """Test report generation."""
    findings = [
        Finding(
            id="TEST-001",
            service="s3",
            resource="bucket1",
            region="us-east-1",
            title="Test 1",
            description="Desc 1",
            severity=Severity.CRITICAL,
            remediation="Fix 1",
        ),
        Finding(
            id="TEST-002",
            service="ec2",
            resource="sg-123",
            region="us-east-1",
            title="Test 2",
            description="Desc 2",
            severity=Severity.HIGH,
            remediation="Fix 2",
        ),
        Finding(
            id="TEST-003",
            service="iam",
            resource="user1",
            region="global",
            title="Test 3",
            description="Desc 3",
            severity=Severity.MEDIUM,
            remediation="Fix 3",
        ),
    ]

    reporter = Reporter(account_id="123456789012")
    report = reporter.generate_report(findings)

    assert report.summary.total_findings == 3
    assert report.summary.critical == 1
    assert report.summary.high == 1
    assert report.summary.medium == 1
    assert report.summary.low == 0
    assert report.summary.info == 0
    assert report.summary.account_id == "123456789012"
    assert sorted(report.summary.services_scanned) == ["ec2", "iam", "s3"]


def test_json_export() -> None:
    """Test JSON export."""
    findings = [
        Finding(
            id="TEST-001",
            service="s3",
            resource="bucket1",
            region="us-east-1",
            title="Test 1",
            description="Desc 1",
            severity=Severity.CRITICAL,
            remediation="Fix 1",
        ),
    ]

    reporter = Reporter()
    report = reporter.generate_report(findings)
    json_str = reporter.to_json(report)

    assert '"CRITICAL"' in json_str
    assert '"TEST-001"' in json_str
    assert '"s3"' in json_str


def test_html_generation() -> None:
    """Test HTML report generation."""
    findings = [
        Finding(
            id="TEST-001",
            service="s3",
            resource="bucket1",
            region="us-east-1",
            title="Test 1",
            description="Desc 1",
            severity=Severity.CRITICAL,
            remediation="Fix 1",
            references=["https://example.com"],
        ),
    ]

    reporter = Reporter(account_id="123456789012")
    report = reporter.generate_report(findings)
    html = reporter._generate_html(report)

    assert "AWS CSPM Report" in html
    assert "CRITICAL" in html
    assert "Test 1" in html
    assert "Fix 1" in html
    assert "123456789012" in html
    assert "https://example.com" in html


def test_empty_report() -> None:
    """Test report with no findings."""
    reporter = Reporter()
    report = reporter.generate_report([])

    assert report.summary.total_findings == 0
    assert len(report.findings) == 0

    html = reporter._generate_html(report)
    assert "No findings detected" in html
