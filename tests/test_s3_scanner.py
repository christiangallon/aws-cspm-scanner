"""Tests for S3 scanner."""

import boto3
from moto import mock_aws

from cspm.models import Severity
from cspm.scanners import S3Scanner


@mock_aws
def test_s3_public_access_block_missing() -> None:
    """Test detection of missing public access block."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="test-bucket")

    scanner = S3Scanner(session, "us-east-1")
    findings = scanner.scan()

    public_findings = [f for f in findings if "PUBLIC-ACCESS" in f.id]
    assert len(public_findings) == 1
    assert public_findings[0].severity == Severity.CRITICAL
    assert "no public access block" in public_findings[0].description.lower()


@mock_aws
def test_s3_public_access_partial_block() -> None:
    """Test detection of partially enabled public access block."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )

    scanner = S3Scanner(session, "us-east-1")
    findings = scanner.scan()

    public_findings = [f for f in findings if "PUBLIC-ACCESS" in f.id]
    assert len(public_findings) == 1
    assert public_findings[0].severity == Severity.HIGH


@mock_aws
def test_s3_encryption_disabled() -> None:
    """Test detection of missing default encryption."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    scanner = S3Scanner(session, "us-east-1")
    findings = scanner.scan()

    enc_findings = [f for f in findings if "ENCRYPTION" in f.id and "ERR" not in f.id]
    assert len(enc_findings) == 1
    assert enc_findings[0].severity == Severity.HIGH


@mock_aws
def test_s3_encryption_sse_s3() -> None:
    """Test detection of SSE-S3 (weaker than SSE-KMS)."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="test-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    },
                }
            ]
        },
    )

    scanner = S3Scanner(session, "us-east-1")
    findings = scanner.scan()

    weak_enc = [f for f in findings if "ENCRYPTION-WEAK" in f.id]
    assert len(weak_enc) == 1
    assert weak_enc[0].severity == Severity.MEDIUM


@mock_aws
def test_s3_versioning_disabled() -> None:
    """Test detection of disabled versioning."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="test-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                    },
                }
            ]
        },
    )

    scanner = S3Scanner(session, "us-east-1")
    findings = scanner.scan()

    ver_findings = [f for f in findings if "VERSIONING" in f.id and "ERR" not in f.id]
    assert len(ver_findings) == 1
    assert ver_findings[0].severity == Severity.MEDIUM


@mock_aws
def test_s3_logging_disabled() -> None:
    """Test detection of disabled access logging."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="test-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                    },
                }
            ]
        },
    )
    s3.put_bucket_versioning(
        Bucket="test-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )

    scanner = S3Scanner(session, "us-east-1")
    findings = scanner.scan()

    log_findings = [f for f in findings if "LOGGING" in f.id and "ERR" not in f.id]
    assert len(log_findings) == 1
    assert log_findings[0].severity == Severity.LOW


@mock_aws
def test_s3_compliant_bucket() -> None:
    """Test that a fully compliant bucket produces no findings."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="log-bucket")
    s3.create_bucket(Bucket="test-bucket")

    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="test-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                    },
                }
            ]
        },
    )
    s3.put_bucket_versioning(
        Bucket="test-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )
    # Moto requires log-delivery group permissions on target bucket for logging
    s3.put_bucket_acl(
        Bucket="log-bucket",
        ACL="log-delivery-write",
    )
    s3.put_bucket_logging(
        Bucket="test-bucket",
        BucketLoggingStatus={
            "LoggingEnabled": {
                "TargetBucket": "log-bucket",
                "TargetPrefix": "logs/",
            }
        },
    )

    # Also secure the log bucket so it doesn't trigger findings
    s3.put_public_access_block(
        Bucket="log-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="log-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                    },
                }
            ]
        },
    )
    s3.put_bucket_versioning(
        Bucket="log-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )
    # Set logging on log-bucket itself to avoid the logging finding
    s3.put_bucket_logging(
        Bucket="log-bucket",
        BucketLoggingStatus={
            "LoggingEnabled": {"TargetBucket": "log-bucket", "TargetPrefix": "self-logs/"}
        },
    )

    scanner = S3Scanner(session, "us-east-1")
    findings = scanner.scan()

    # Filter out error/info findings
    real_findings = [f for f in findings if f.severity not in (Severity.INFO,)]
    assert len(real_findings) == 0
