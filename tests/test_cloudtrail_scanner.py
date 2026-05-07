"""Tests for CloudTrail scanner."""

import json

import boto3
from moto import mock_aws

from cspm.models import Severity
from cspm.scanners import CloudTrailScanner


@mock_aws
def test_cloudtrail_not_enabled() -> None:
    """Test detection of CloudTrail not being enabled."""
    session = boto3.Session(region_name="us-east-1")

    scanner = CloudTrailScanner(session, "us-east-1")
    findings = scanner.scan()

    not_enabled = [f for f in findings if "NOT-ENABLED" in f.id]
    assert len(not_enabled) == 1
    assert not_enabled[0].severity == Severity.CRITICAL


@mock_aws
def test_cloudtrail_not_logging() -> None:
    """Test detection of CloudTrail trail not logging."""
    session = boto3.Session(region_name="us-east-1")
    cloudtrail = session.client("cloudtrail")
    s3 = session.client("s3")

    s3.create_bucket(Bucket="trail-bucket")
    cloudtrail.create_trail(
        Name="test-trail",
        S3BucketName="trail-bucket",
        IsMultiRegionTrail=True,
    )
    # Don't call start_logging

    scanner = CloudTrailScanner(session, "us-east-1")
    findings = scanner.scan()

    not_logging = [f for f in findings if "NOT-LOGGING" in f.id]
    assert len(not_logging) == 1
    assert not_logging[0].severity == Severity.CRITICAL


@mock_aws
def test_cloudtrail_not_multi_region() -> None:
    """Test detection of non-multi-region trail."""
    session = boto3.Session(region_name="us-east-1")
    cloudtrail = session.client("cloudtrail")
    s3 = session.client("s3")

    s3.create_bucket(Bucket="trail-bucket")
    cloudtrail.create_trail(
        Name="test-trail",
        S3BucketName="trail-bucket",
        IsMultiRegionTrail=False,
    )
    cloudtrail.start_logging(Name="test-trail")

    scanner = CloudTrailScanner(session, "us-east-1")
    findings = scanner.scan()

    multi_region = [f for f in findings if "NOT-MULTI-REGION" in f.id]
    assert len(multi_region) == 1
    assert multi_region[0].severity == Severity.MEDIUM


@mock_aws
def test_cloudtrail_no_log_validation() -> None:
    """Test detection of disabled log file validation."""
    session = boto3.Session(region_name="us-east-1")
    cloudtrail = session.client("cloudtrail")
    s3 = session.client("s3")

    s3.create_bucket(Bucket="trail-bucket")
    cloudtrail.create_trail(
        Name="test-trail",
        S3BucketName="trail-bucket",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=False,
    )
    cloudtrail.start_logging(Name="test-trail")

    scanner = CloudTrailScanner(session, "us-east-1")
    findings = scanner.scan()

    validation = [f for f in findings if "NO-VALIDATION" in f.id]
    assert len(validation) == 1
    assert validation[0].severity == Severity.HIGH


@mock_aws
def test_cloudtrail_no_kms() -> None:
    """Test detection of missing KMS encryption."""
    session = boto3.Session(region_name="us-east-1")
    cloudtrail = session.client("cloudtrail")
    s3 = session.client("s3")

    s3.create_bucket(Bucket="trail-bucket")
    cloudtrail.create_trail(
        Name="test-trail",
        S3BucketName="trail-bucket",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
    )
    cloudtrail.start_logging(Name="test-trail")

    scanner = CloudTrailScanner(session, "us-east-1")
    findings = scanner.scan()

    kms = [f for f in findings if "NO-KMS" in f.id]
    assert len(kms) == 1
    assert kms[0].severity == Severity.MEDIUM


@mock_aws
def test_cloudtrail_compliant() -> None:
    """Test that a fully compliant CloudTrail produces minimal findings."""
    session = boto3.Session(region_name="us-east-1")
    cloudtrail = session.client("cloudtrail")
    s3 = session.client("s3")

    s3.create_bucket(Bucket="trail-bucket")
    # Set bucket policy to allow CloudTrail logging
    s3.put_bucket_policy(
        Bucket="trail-bucket",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AWSCloudTrailAclCheck",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": "arn:aws:s3:::trail-bucket",
                    },
                    {
                        "Sid": "AWSCloudTrailWrite",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::trail-bucket/*",
                        "Condition": {
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                        },
                    },
                ],
            }
        ),
    )

    cloudtrail.create_trail(
        Name="test-trail",
        S3BucketName="trail-bucket",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
        KmsKeyId="alias/aws/cloudtrail",
    )
    cloudtrail.start_logging(Name="test-trail")

    # Add event selectors for data events
    cloudtrail.put_event_selectors(
        TrailName="test-trail",
        EventSelectors=[
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": True,
                "DataResources": [
                    {
                        "Type": "AWS::S3::Object",
                        "Values": ["arn:aws:s3:::*"],
                    }
                ],
            }
        ],
    )

    scanner = CloudTrailScanner(session, "us-east-1")
    findings = scanner.scan()

    # Should have no critical/high findings
    serious = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(serious) == 0
