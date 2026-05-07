"""Tests for EC2 scanner."""

import boto3
from moto import mock_aws

from cspm.models import Severity
from cspm.scanners import EC2Scanner


@mock_aws
def test_ec2_ssh_open_to_internet() -> None:
    """Test detection of SSH (22) open to 0.0.0.0/0."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")

    ec2.create_security_group(
        GroupName="test-sg",
        Description="Test security group",
    )
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

    scanner = EC2Scanner(session, "us-east-1")
    findings = scanner.scan()

    ssh_findings = [f for f in findings if "OPEN" in f.id and "22" in f.id]
    assert len(ssh_findings) == 1
    assert ssh_findings[0].severity == Severity.CRITICAL
    assert "SSH" in ssh_findings[0].title


@mock_aws
def test_ec2_rdp_open_to_internet() -> None:
    """Test detection of RDP (3389) open to 0.0.0.0/0."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")

    ec2.create_security_group(
        GroupName="test-sg",
        Description="Test security group",
    )
    sgs = ec2.describe_security_groups(GroupNames=["test-sg"])["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    scanner = EC2Scanner(session, "us-east-1")
    findings = scanner.scan()

    rdp_findings = [f for f in findings if "OPEN" in f.id and "3389" in f.id]
    assert len(rdp_findings) == 1
    assert rdp_findings[0].severity == Severity.CRITICAL


@mock_aws
def test_ec2_all_traffic_open() -> None:
    """Test detection of all traffic open to 0.0.0.0/0."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")

    ec2.create_security_group(
        GroupName="test-sg",
        Description="Test security group",
    )
    sgs = ec2.describe_security_groups(GroupNames=["test-sg"])["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    scanner = EC2Scanner(session, "us-east-1")
    findings = scanner.scan()

    all_traffic = [f for f in findings if "ALL-TRAFFIC" in f.id]
    assert len(all_traffic) == 1
    assert all_traffic[0].severity == Severity.CRITICAL


@mock_aws
def test_ec2_mysql_open() -> None:
    """Test detection of MySQL (3306) open to internet."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")

    ec2.create_security_group(
        GroupName="test-sg",
        Description="Test security group",
    )
    sgs = ec2.describe_security_groups(GroupNames=["test-sg"])["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    scanner = EC2Scanner(session, "us-east-1")
    findings = scanner.scan()

    mysql_findings = [f for f in findings if "OPEN" in f.id and "3306" in f.id]
    assert len(mysql_findings) == 1
    assert mysql_findings[0].severity == Severity.HIGH


@mock_aws
def test_ec2_restricted_sg_no_findings() -> None:
    """Test that properly restricted SG produces no findings."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")

    ec2.create_security_group(
        GroupName="test-sg",
        Description="Test security group",
    )
    sgs = ec2.describe_security_groups(GroupNames=["test-sg"])["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }
        ],
    )

    scanner = EC2Scanner(session, "us-east-1")
    findings = scanner.scan()

    real_findings = [f for f in findings if f.severity != Severity.INFO]
    assert len(real_findings) == 0


@mock_aws
def test_ec2_ipv6_open() -> None:
    """Test detection of IPv6 ::/0 open."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")

    ec2.create_security_group(
        GroupName="test-sg",
        Description="Test security group",
    )
    sgs = ec2.describe_security_groups(GroupNames=["test-sg"])["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        ],
    )

    scanner = EC2Scanner(session, "us-east-1")
    findings = scanner.scan()

    ipv6_findings = [f for f in findings if "ipv6" in f.id]
    assert len(ipv6_findings) == 1
    assert ipv6_findings[0].severity == Severity.CRITICAL
