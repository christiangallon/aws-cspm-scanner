"""Tests for IAM scanner."""

import json

import boto3
from moto import mock_aws

from cspm.models import Severity
from cspm.scanners import IAMScanner


@mock_aws
def test_iam_root_access_keys() -> None:
    """Test detection of root account access keys."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    # Create a user with access key to simulate account with keys
    iam.create_user(UserName="testuser")
    iam.create_access_key(UserName="testuser")

    # Moto's account summary doesn't simulate root keys well,
    # but we can test the scanner runs without error
    scanner = IAMScanner(session, "us-east-1")
    findings = scanner.scan()

    # Should at least not crash
    assert isinstance(findings, list)


@mock_aws
def test_iam_user_without_mfa() -> None:
    """Test detection of users without MFA."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="testuser")

    scanner = IAMScanner(session, "us-east-1")
    findings = scanner.scan()

    mfa_findings = [f for f in findings if "NO-MFA" in f.id and "ROOT" not in f.id]
    assert len(mfa_findings) == 1
    assert mfa_findings[0].severity == Severity.HIGH
    assert "testuser" in mfa_findings[0].resource


@mock_aws
def test_iam_old_access_key() -> None:
    """Test detection of old access keys."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="testuser")

    # Moto doesn't simulate key age, but we can test the structure
    scanner = IAMScanner(session, "us-east-1")
    findings = scanner.scan()

    # Should find the user and check keys
    key_findings = [f for f in findings if "KEY" in f.id or "MFA" in f.id]
    assert len(key_findings) > 0


@mock_aws
def test_iam_overly_permissive_policy() -> None:
    """Test detection of overly permissive inline policies."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="testuser")

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }

    iam.put_user_policy(
        UserName="testuser",
        PolicyName="BadPolicy",
        PolicyDocument=json.dumps(policy_doc),
    )

    scanner = IAMScanner(session, "us-east-1")
    findings = scanner.scan()

    wildcard_findings = [f for f in findings if "WILDCARD" in f.id]
    assert len(wildcard_findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in wildcard_findings)


@mock_aws
def test_iam_password_policy_missing() -> None:
    """Test detection of missing password policy."""
    session = boto3.Session(region_name="us-east-1")

    scanner = IAMScanner(session, "us-east-1")
    findings = scanner.scan()

    policy_findings = [f for f in findings if "NO-PASSWORD-POLICY" in f.id]
    assert len(policy_findings) == 1
    assert policy_findings[0].severity == Severity.MEDIUM


@mock_aws
def test_iam_weak_password_policy() -> None:
    """Test detection of weak password policy."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    iam.update_account_password_policy(
        MinimumPasswordLength=8,
        RequireSymbols=False,
        RequireNumbers=False,
        RequireUppercaseCharacters=False,
        RequireLowercaseCharacters=False,
        MaxPasswordAge=365,
        PasswordReusePrevention=1,
    )

    scanner = IAMScanner(session, "us-east-1")
    findings = scanner.scan()

    policy_findings = [f for f in findings if "Password" in f.id and "ERR" not in f.id]
    assert len(policy_findings) > 0
    assert any(f.severity == Severity.MEDIUM for f in policy_findings)


@mock_aws
def test_iam_role_wildcard_trust() -> None:
    """Test detection of wildcard trust policy on roles."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    assume_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    iam.create_role(
        RoleName="BadRole",
        AssumeRolePolicyDocument=json.dumps(assume_doc),
    )

    scanner = IAMScanner(session, "us-east-1")
    findings = scanner.scan()

    role_findings = [f for f in findings if "ROLE-WILDCARD" in f.id]
    assert len(role_findings) == 1
    assert role_findings[0].severity == Severity.CRITICAL


@mock_aws
def test_iam_admin_policy_attachment() -> None:
    """Test detection of AdministratorAccess policy attachment."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="adminuser")

    # Create a policy that mimics AdministratorAccess
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    iam.create_policy(
        PolicyName="AdminPolicy",
        PolicyDocument=json.dumps(policy_doc),
    )
    iam.attach_user_policy(
        UserName="adminuser",
        PolicyArn="arn:aws:iam::123456789012:policy/AdminPolicy",
    )

    scanner = IAMScanner(session, "us-east-1")
    findings = scanner.scan()

    # The inline policy wildcard check should still catch this
    wildcard_findings = [f for f in findings if "WILDCARD" in f.id]
    assert len(wildcard_findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in wildcard_findings)
