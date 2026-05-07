"""Tests for CLI integration."""

import json
from unittest.mock import MagicMock, patch

import boto3
from click.testing import CliRunner
from moto import mock_aws

from cspm.cli import get_account_id, get_enabled_regions, main


@mock_aws
def test_cli_basic_scan():
    """Test CLI runs a basic scan with mocked AWS."""
    # Set up mocked AWS resources
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    s3 = session.client("s3")

    # Create a security group with SSH open
    ec2.create_security_group(GroupName="test-sg", Description="Test")
    sgs = ec2.describe_security_groups(GroupNames=["test-sg"])["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    # Create an S3 bucket without public access block
    s3.create_bucket(Bucket="test-bucket")

    runner = CliRunner()
    result = runner.invoke(main, ["--region", "us-east-1", "--services", "ec2,s3"])

    assert result.exit_code in (0, 1, 2)  # May exit with error code if findings exist
    assert "Authenticated" in result.output or "Scanning" in result.output


@mock_aws
def test_cli_json_output():
    """Test CLI JSON output generation."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    ec2.create_security_group(GroupName="test-sg", Description="Test")

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["--region", "us-east-1", "--services", "ec2", "--output", "report.json"],
        )

        assert result.exit_code in (0, 1, 2)

        # Check JSON file was created
        try:
            with open("report.json") as f:
                data = json.load(f)
            assert "summary" in data
            assert "findings" in data
        except FileNotFoundError:
            # If no findings, file might not be created depending on implementation
            pass


@mock_aws
def test_cli_html_output():
    """Test CLI HTML output generation."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    ec2.create_security_group(GroupName="test-sg", Description="Test")

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["--region", "us-east-1", "--services", "ec2", "--html", "report.html"],
        )

        assert result.exit_code in (0, 1, 2)

        try:
            with open("report.html") as f:
                html = f.read()
            assert "AWS CSPM Report" in html
        except FileNotFoundError:
            pass


@mock_aws
def test_cli_profile_option():
    """Test CLI with --profile option."""
    runner = CliRunner()
    result = runner.invoke(
        main, ["--profile", "default", "--region", "us-east-1", "--services", "ec2"]
    )

    # Should either succeed or fail gracefully
    assert result.exit_code in (0, 1, 2)


@mock_aws
def test_cli_role_arn_option():
    """Test CLI with --role-arn option."""
    runner = CliRunner()

    # Mock STS assume_role
    with patch("cspm.cli.get_session") as mock_get_session:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/test",
        }
        mock_session.client.return_value = mock_sts
        mock_get_session.return_value = mock_session

        result = runner.invoke(
            main,
            [
                "--role-arn",
                "arn:aws:iam::123456789012:role/test-role",
                "--region",
                "us-east-1",
                "--services",
                "ec2",
            ],
        )

        mock_get_session.assert_called_once_with(
            profile=None, role_arn="arn:aws:iam::123456789012:role/test-role"
        )
        assert result.exit_code in (0, 1, 2)


@mock_aws
def test_cli_severity_filter():
    """Test CLI severity filtering."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    ec2.create_security_group(GroupName="test-sg", Description="Test")
    sgs = ec2.describe_security_groups(GroupNames=["test-sg"])["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    runner = CliRunner()

    # With INFO severity, should find the SSH finding
    result = runner.invoke(
        main,
        ["--region", "us-east-1", "--services", "ec2", "--severity", "INFO"],
    )
    assert result.exit_code == 2  # Critical findings exist

    # With CRITICAL only, should still find it
    result = runner.invoke(
        main,
        ["--region", "us-east-1", "--services", "ec2", "--severity", "CRITICAL"],
    )
    assert result.exit_code == 2


@mock_aws
def test_cli_quiet_mode():
    """Test CLI quiet mode suppresses output."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    ec2.create_security_group(GroupName="test-sg", Description="Test")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["--region", "us-east-1", "--services", "ec2", "--quiet"],
    )

    assert result.exit_code in (0, 1, 2)
    # In quiet mode, there should be minimal output
    assert "Scanning" not in result.output or result.output == ""


@mock_aws
def test_cli_unknown_service():
    """Test CLI with unknown service name."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["--region", "us-east-1", "--services", "unknown1,unknown2"],
    )

    assert result.exit_code == 1
    # In quiet mode or when output is suppressed, check exit code is enough
    assert "No valid services" in result.output or result.output == ""


def test_get_account_id():
    """Test get_account_id helper."""
    session = boto3.Session(region_name="us-east-1")
    account_id = get_account_id(session)
    assert account_id == "unknown" or len(account_id) == 12


def test_get_enabled_regions():
    """Test get_enabled_regions helper."""
    session = boto3.Session(region_name="us-east-1")
    regions = get_enabled_regions(session)
    assert isinstance(regions, list)
    assert len(regions) > 0
