"""S3 security scanner."""

from typing import Any

from botocore.exceptions import ClientError

from cspm.models import Finding, Severity
from cspm.scanners.base import BaseScanner


class S3Scanner(BaseScanner):
    """Scanner for AWS S3 security posture."""

    @property
    def service_name(self) -> str:
        return "s3"

    def scan(self) -> list[Finding]:
        """Scan all S3 buckets for security issues."""
        findings: list[Finding] = []
        response = self.client.list_buckets()
        buckets = response.get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            findings.extend(self._scan_bucket(bucket_name))

        return findings

    def _get_bucket_region(self, bucket_name: str) -> str:
        """Get the actual region of a bucket."""
        try:
            resp = self.client.get_bucket_location(Bucket=bucket_name)
            region = resp.get("LocationConstraint") or "us-east-1"
            return region
        except Exception:
            return self.region

    def _scan_bucket(self, bucket_name: str) -> list[Finding]:
        """Scan a single bucket for security issues."""
        findings: list[Finding] = []
        region = self._get_bucket_region(bucket_name)

        # Use regional client for bucket-specific calls
        regional_client = self.session.client("s3", region_name=region)

        findings.extend(self._check_public_access(regional_client, bucket_name, region))
        findings.extend(self._check_encryption(regional_client, bucket_name, region))
        findings.extend(self._check_versioning(regional_client, bucket_name, region))
        findings.extend(self._check_logging(regional_client, bucket_name, region))

        return findings

    def _check_public_access(self, client: Any, bucket_name: str, region: str) -> list[Finding]:
        """Check if bucket has public access enabled."""
        findings: list[Finding] = []

        try:
            config = client.get_public_access_block(Bucket=bucket_name)
            rules = config.get("PublicAccessBlockConfiguration", {})

            if not all(
                [
                    rules.get("BlockPublicAcls", False),
                    rules.get("IgnorePublicAcls", False),
                    rules.get("BlockPublicPolicy", False),
                    rules.get("RestrictPublicBuckets", False),
                ]
            ):
                findings.append(
                    Finding(
                        id=f"S3-PUBLIC-ACCESS-{bucket_name}",
                        service="s3",
                        resource=bucket_name,
                        region=region,
                        title="S3 Bucket Public Access Not Fully Blocked",
                        description=(
                            f"Bucket '{bucket_name}' does not have all public access "
                            "block rules enabled. This may allow unintended public access."
                        ),
                        severity=Severity.HIGH,
                        remediation=(
                            "Enable 'Block all public access' in the S3 console or via CLI: "
                            f"aws s3api put-public-access-block --bucket {bucket_name} "
                            "--public-access-block-configuration "
                            "BlockPublicAcls=true,IgnorePublicAcls=true,"
                            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                        references=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                        ],
                        raw_details=rules,
                    )
                )
        except ClientError as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                findings.append(
                    Finding(
                        id=f"S3-PUBLIC-ACCESS-{bucket_name}",
                        service="s3",
                        resource=bucket_name,
                        region=region,
                        title="S3 Bucket Missing Public Access Block",
                        description=(
                            f"Bucket '{bucket_name}' has no public access block configuration. "
                            "It may be publicly accessible."
                        ),
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Immediately configure public access block: "
                            f"aws s3api put-public-access-block --bucket {bucket_name} "
                            "--public-access-block-configuration "
                            "BlockPublicAcls=true,IgnorePublicAcls=true,"
                            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                        references=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                        ],
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=f"S3-PUBLIC-ACCESS-ERR-{bucket_name}",
                        service="s3",
                        resource=bucket_name,
                        region=region,
                        title="S3 Public Access Check Failed",
                        description=f"Could not retrieve public access block: {str(e)}",
                        severity=Severity.INFO,
                        remediation="Verify IAM permissions for s3:GetBucketPublicAccessBlock.",
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    id=f"S3-PUBLIC-ACCESS-ERR-{bucket_name}",
                    service="s3",
                    resource=bucket_name,
                    region=region,
                    title="S3 Public Access Check Failed",
                    description=f"Could not retrieve public access block: {str(e)}",
                    severity=Severity.INFO,
                    remediation="Verify IAM permissions for s3:GetBucketPublicAccessBlock.",
                )
            )

        return findings

    def _check_encryption(self, client: Any, bucket_name: str, region: str) -> list[Finding]:
        """Check if bucket has default encryption enabled."""
        findings: list[Finding] = []

        try:
            encryption = client.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

            if not rules:
                findings.append(
                    Finding(
                        id=f"S3-ENCRYPTION-{bucket_name}",
                        service="s3",
                        resource=bucket_name,
                        region=region,
                        title="S3 Bucket Default Encryption Not Configured",
                        description=(
                            f"Bucket '{bucket_name}' has no default encryption rules applied."
                        ),
                        severity=Severity.HIGH,
                        remediation=(
                            "Enable default encryption with KMS or AES256: "
                            f"aws s3api put-bucket-encryption --bucket {bucket_name} "
                            "--server-side-encryption-configuration file://encryption.json"
                        ),
                        references=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"
                        ],
                    )
                )
            else:
                # Check if using SSE-S3 instead of SSE-KMS
                for rule in rules:
                    algo = (
                        rule.get("ApplyServerSideEncryptionByDefault", {})
                        .get("SSEAlgorithm", "")
                        .upper()
                    )
                    if algo == "AES256":
                        findings.append(
                            Finding(
                                id=f"S3-ENCRYPTION-WEAK-{bucket_name}",
                                service="s3",
                                resource=bucket_name,
                                region=region,
                                title="S3 Bucket Using SSE-S3 Instead of SSE-KMS",
                                description=(
                                    f"Bucket '{bucket_name}' uses SSE-S3 (AES256) which does not "
                                    "provide audit trails or granular key control. Consider SSE-KMS."
                                ),
                                severity=Severity.MEDIUM,
                                remediation=(
                                    "Migrate to SSE-KMS for better auditability and key control: "
                                    f"aws s3api put-bucket-encryption --bucket {bucket_name} "
                                    "--server-side-encryption-configuration file://kms-encryption.json"
                                ),
                                references=[
                                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html"
                                ],
                                raw_details=rule,
                            )
                        )
        except client.exceptions.ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                findings.append(
                    Finding(
                        id=f"S3-ENCRYPTION-{bucket_name}",
                        service="s3",
                        resource=bucket_name,
                        region=region,
                        title="S3 Bucket Default Encryption Disabled",
                        description=(
                            f"Bucket '{bucket_name}' does not have default encryption enabled. "
                            "Objects uploaded without encryption headers will be stored unencrypted."
                        ),
                        severity=Severity.HIGH,
                        remediation=(
                            "Enable default encryption: "
                            f"aws s3api put-bucket-encryption --bucket {bucket_name} "
                            "--server-side-encryption-configuration "
                            '\'"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]\''
                        ),
                        references=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"
                        ],
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=f"S3-ENCRYPTION-ERR-{bucket_name}",
                        service="s3",
                        resource=bucket_name,
                        region=region,
                        title="S3 Encryption Check Failed",
                        description=f"Could not retrieve encryption config: {str(e)}",
                        severity=Severity.INFO,
                        remediation="Verify IAM permissions for s3:GetEncryptionConfiguration.",
                    )
                )

        return findings

    def _check_versioning(self, client: Any, bucket_name: str, region: str) -> list[Finding]:
        """Check if bucket has versioning enabled."""
        findings: list[Finding] = []

        try:
            versioning = client.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get("Status", "Disabled")

            if status != "Enabled":
                findings.append(
                    Finding(
                        id=f"S3-VERSIONING-{bucket_name}",
                        service="s3",
                        resource=bucket_name,
                        region=region,
                        title="S3 Bucket Versioning Not Enabled",
                        description=(
                            f"Bucket '{bucket_name}' has versioning {status.lower()}. "
                            "Accidental deletions or overwrites cannot be recovered."
                        ),
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Enable versioning: "
                            f"aws s3api put-bucket-versioning --bucket {bucket_name} "
                            "--versioning-configuration Status=Enabled"
                        ),
                        references=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
                        ],
                        raw_details=versioning,
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    id=f"S3-VERSIONING-ERR-{bucket_name}",
                    service="s3",
                    resource=bucket_name,
                    region=region,
                    title="S3 Versioning Check Failed",
                    description=f"Could not retrieve versioning config: {str(e)}",
                    severity=Severity.INFO,
                    remediation="Verify IAM permissions for s3:GetBucketVersioning.",
                )
            )

        return findings

    def _check_logging(self, client: Any, bucket_name: str, region: str) -> list[Finding]:
        """Check if bucket has access logging enabled."""
        findings: list[Finding] = []

        try:
            logging = client.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" not in logging:
                findings.append(
                    Finding(
                        id=f"S3-LOGGING-{bucket_name}",
                        service="s3",
                        resource=bucket_name,
                        region=region,
                        title="S3 Bucket Access Logging Disabled",
                        description=(
                            f"Bucket '{bucket_name}' does not have access logging enabled. "
                            "Access patterns and potential abuse cannot be audited."
                        ),
                        severity=Severity.LOW,
                        remediation=(
                            "Enable access logging: "
                            f"aws s3api put-bucket-logging --bucket {bucket_name} "
                            "--bucket-logging-status file://logging.json"
                        ),
                        references=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"
                        ],
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    id=f"S3-LOGGING-ERR-{bucket_name}",
                    service="s3",
                    resource=bucket_name,
                    region=region,
                    title="S3 Logging Check Failed",
                    description=f"Could not retrieve logging config: {str(e)}",
                    severity=Severity.INFO,
                    remediation="Verify IAM permissions for s3:GetBucketLogging.",
                )
            )

        return findings
