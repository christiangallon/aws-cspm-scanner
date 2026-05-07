"""AWS service security scanners."""

from cspm.scanners.base import BaseScanner
from cspm.scanners.cloudtrail_scanner import CloudTrailScanner
from cspm.scanners.ec2_scanner import EC2Scanner
from cspm.scanners.iam_scanner import IAMScanner
from cspm.scanners.s3_scanner import S3Scanner

__all__ = ["BaseScanner", "S3Scanner", "IAMScanner", "EC2Scanner", "CloudTrailScanner"]
