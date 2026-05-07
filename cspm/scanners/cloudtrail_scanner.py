"""CloudTrail security scanner."""

from cspm.models import Finding, Severity
from cspm.scanners.base import BaseScanner


class CloudTrailScanner(BaseScanner):
    """Scanner for AWS CloudTrail security posture."""

    @property
    def service_name(self) -> str:
        return "cloudtrail"

    def scan(self) -> list[Finding]:
        """Scan CloudTrail configuration for security issues."""
        findings: list[Finding] = []

        findings.extend(self._check_cloudtrail_enabled())
        findings.extend(self._check_trail_configuration())
        findings.extend(self._check_event_selectors())

        return findings

    def _check_cloudtrail_enabled(self) -> list[Finding]:
        """Check if CloudTrail is enabled."""
        findings: list[Finding] = []

        try:
            response = self.client.describe_trails()
            trails = response.get("trailList", [])

            if not trails:
                findings.append(
                    Finding(
                        id="CLOUDTRAIL-NOT-ENABLED",
                        service="cloudtrail",
                        resource="arn:aws:cloudtrail:::trail/*",
                        region=self.region,
                        title="CloudTrail Not Enabled",
                        description=(
                            "No CloudTrail trails found in this region. "
                            "API activity is not being logged, severely limiting auditability "
                            "and incident response capabilities."
                        ),
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Create a multi-region trail: "
                            "aws cloudtrail create-trail --name management-events "
                            "--s3-bucket-name YOUR-TRAIL-BUCKET --is-multi-region-trail "
                            "&& aws cloudtrail start-logging --name management-events"
                        ),
                        references=[
                            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"
                        ],
                    )
                )
            else:
                # Check if any trail is actually logging
                logging_trails = []
                for trail in trails:
                    trail_name = trail["Name"]
                    # Home region trails only report status in their home region
                    trail_region = trail.get("HomeRegion", self.region)
                    if trail_region == self.region:
                        try:
                            status = self.client.get_trail_status(Name=trail_name)
                            if status.get("IsLogging", False):
                                logging_trails.append(trail)
                        except Exception:
                            pass

                if not logging_trails:
                    findings.append(
                        Finding(
                            id="CLOUDTRAIL-NOT-LOGGING",
                            service="cloudtrail",
                            resource="arn:aws:cloudtrail:::trail/*",
                            region=self.region,
                            title="CloudTrail Trails Not Logging",
                            description=(
                                f"{len(trails)} trail(s) exist but none are actively logging. "
                                "API activity is not being recorded."
                            ),
                            severity=Severity.CRITICAL,
                            remediation=(
                                "Start logging on trails: "
                                "aws cloudtrail start-logging --name TRAIL-NAME"
                            ),
                            references=[
                                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-start-logging.html"
                            ],
                        )
                    )

        except Exception as e:
            findings.append(
                Finding(
                    id="CLOUDTRAIL-CHECK-ERR",
                    service="cloudtrail",
                    resource="arn:aws:cloudtrail:::trail/*",
                    region=self.region,
                    title="CloudTrail Check Failed",
                    description=f"Could not check CloudTrail status: {str(e)}",
                    severity=Severity.INFO,
                    remediation="Verify IAM permissions for cloudtrail:DescribeTrails.",
                )
            )

        return findings

    def _check_trail_configuration(self) -> list[Finding]:
        """Check CloudTrail trail configurations."""
        findings: list[Finding] = []

        try:
            response = self.client.describe_trails()
            trails = response.get("trailList", [])

            for trail in trails:
                trail_name = trail["Name"]
                trail_arn = trail.get("TrailARN", f"arn:aws:cloudtrail:::trail/{trail_name}")
                trail_region = trail.get("HomeRegion", self.region)

                # Only check trails in current region
                if trail_region != self.region:
                    continue

                # Check if multi-region
                if not trail.get("IsMultiRegionTrail", False):
                    findings.append(
                        Finding(
                            id=f"CLOUDTRAIL-NOT-MULTI-REGION-{trail_name}",
                            service="cloudtrail",
                            resource=trail_arn,
                            region=trail_region,
                            title=f"CloudTrail Trail Not Multi-Region: {trail_name}",
                            description=(
                                f"Trail '{trail_name}' is not a multi-region trail. "
                                "Activity in other regions may not be logged."
                            ),
                            severity=Severity.MEDIUM,
                            remediation=(
                                f"Convert to multi-region: aws cloudtrail update-trail "
                                f"--name {trail_name} --is-multi-region-trail"
                            ),
                            references=[
                                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"
                            ],
                            raw_details=trail,
                        )
                    )

                # Check log file validation
                if not trail.get("LogFileValidationEnabled", False):
                    findings.append(
                        Finding(
                            id=f"CLOUDTRAIL-NO-VALIDATION-{trail_name}",
                            service="cloudtrail",
                            resource=trail_arn,
                            region=trail_region,
                            title=f"CloudTrail Log File Validation Disabled: {trail_name}",
                            description=(
                                f"Trail '{trail_name}' does not have log file validation enabled. "
                                "Log integrity cannot be cryptographically verified."
                            ),
                            severity=Severity.HIGH,
                            remediation=(
                                f"Enable validation: aws cloudtrail update-trail "
                                f"--name {trail_name} --enable-log-file-validation"
                            ),
                            references=[
                                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"
                            ],
                            raw_details=trail,
                        )
                    )

                # Check SNS topic for notifications
                if not trail.get("SnsTopicName"):
                    findings.append(
                        Finding(
                            id=f"CLOUDTRAIL-NO-SNS-{trail_name}",
                            service="cloudtrail",
                            resource=trail_arn,
                            region=trail_region,
                            title=f"CloudTrail Trail Without SNS Notifications: {trail_name}",
                            description=(
                                f"Trail '{trail_name}' has no SNS topic configured. "
                                "Real-time notifications for log delivery issues are not available."
                            ),
                            severity=Severity.LOW,
                            remediation=(
                                f"Configure SNS topic: aws cloudtrail update-trail "
                                f"--name {trail_name} --sns-topic-name YOUR-TOPIC"
                            ),
                            references=[
                                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html"
                            ],
                            raw_details=trail,
                        )
                    )

                # Check KMS encryption
                if not trail.get("KmsKeyId"):
                    findings.append(
                        Finding(
                            id=f"CLOUDTRAIL-NO-KMS-{trail_name}",
                            service="cloudtrail",
                            resource=trail_arn,
                            region=trail_region,
                            title=f"CloudTrail Logs Not Encrypted with KMS: {trail_name}",
                            description=(
                                f"Trail '{trail_name}' does not use KMS encryption. "
                                "Log files are encrypted with S3-managed keys (SSE-S3) only."
                            ),
                            severity=Severity.MEDIUM,
                            remediation=(
                                f"Enable KMS encryption: aws cloudtrail update-trail "
                                f"--name {trail_name} --kms-key-id alias/aws/cloudtrail"
                            ),
                            references=[
                                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html"
                            ],
                            raw_details=trail,
                        )
                    )

                # Check S3 bucket is not public
                s3_bucket = trail.get("S3BucketName", "")
                if s3_bucket:
                    findings.extend(
                        self._check_s3_bucket_security(s3_bucket, trail_name, trail_arn)
                    )

        except Exception as e:
            findings.append(
                Finding(
                    id="CLOUDTRAIL-CONFIG-ERR",
                    service="cloudtrail",
                    resource="arn:aws:cloudtrail:::trail/*",
                    region=self.region,
                    title="CloudTrail Configuration Check Failed",
                    description=f"Could not check trail configuration: {str(e)}",
                    severity=Severity.INFO,
                    remediation="Verify IAM permissions for cloudtrail:DescribeTrails.",
                )
            )

        return findings

    def _check_s3_bucket_security(
        self, bucket_name: str, trail_name: str, trail_arn: str
    ) -> list[Finding]:
        """Check that the CloudTrail S3 bucket is properly secured."""
        findings: list[Finding] = []
        s3 = self.session.client("s3")

        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_doc = policy.get("Policy", "{}")
            import json

            doc = json.loads(policy_doc)

            # Check for overly permissive access
            for statement in doc.get("Statement", []):
                principal = statement.get("Principal", {})
                if (principal == "*" or principal.get("AWS") == "*") and statement.get(
                    "Effect"
                ) == "Allow":
                    findings.append(
                        Finding(
                            id=f"CLOUDTRAIL-S3-PUBLIC-{bucket_name}",
                            service="cloudtrail",
                            resource=f"arn:aws:s3:::{bucket_name}",
                            region=self.region,
                            title=f"CloudTrail S3 Bucket May Be Public: {bucket_name}",
                            description=(
                                f"S3 bucket '{bucket_name}' used by CloudTrail trail "
                                f"'{trail_name}' has a policy that may allow public access. "
                                "CloudTrail logs contain sensitive API activity."
                            ),
                            severity=Severity.HIGH,
                            remediation=(
                                "Review and restrict bucket policy to only allow CloudTrail "
                                "service principal."
                            ),
                            references=[
                                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html"
                            ],
                            raw_details=statement,
                        )
                    )

        except s3.exceptions.NoSuchBucketPolicy:
            findings.append(
                Finding(
                    id=f"CLOUDTRAIL-S3-NO-POLICY-{bucket_name}",
                    service="cloudtrail",
                    resource=f"arn:aws:s3:::{bucket_name}",
                    region=self.region,
                    title=f"CloudTrail S3 Bucket Missing Policy: {bucket_name}",
                    description=(
                        f"S3 bucket '{bucket_name}' used by CloudTrail has no bucket policy. "
                        "Access control relies solely on ACLs and IAM."
                    ),
                    severity=Severity.LOW,
                    remediation=(
                        "Add a bucket policy that restricts access to CloudTrail service only."
                    ),
                    references=[
                        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html"
                    ],
                )
            )
        except Exception:
            pass

        return findings

    def _check_event_selectors(self) -> list[Finding]:
        """Check if CloudTrail is logging data events and insights."""
        findings: list[Finding] = []

        try:
            response = self.client.describe_trails()
            trails = response.get("trailList", [])

            for trail in trails:
                trail_name = trail["Name"]
                trail_arn = trail.get("TrailARN", f"arn:aws:cloudtrail:::trail/{trail_name}")
                trail_region = trail.get("HomeRegion", self.region)

                if trail_region != self.region:
                    continue

                try:
                    selectors = self.client.get_event_selectors(TrailName=trail_name)
                    event_selectors = selectors.get("EventSelectors", [])
                    advanced_selectors = selectors.get("AdvancedEventSelectors", [])

                    has_data_events = False
                    for es in event_selectors:
                        if es.get("ReadWriteType") in ("All", "WriteOnly"):
                            has_data_events = True
                            break

                    for aes in advanced_selectors:
                        for field in aes.get("FieldSelectors", []):
                            if field.get("Field") == "eventCategory" and "Data" in field.get(
                                "Equals", []
                            ):
                                has_data_events = True
                                break

                    if not has_data_events:
                        findings.append(
                            Finding(
                                id=f"CLOUDTRAIL-NO-DATA-EVENTS-{trail_name}",
                                service="cloudtrail",
                                resource=trail_arn,
                                region=trail_region,
                                title=f"CloudTrail Not Logging Data Events: {trail_name}",
                                description=(
                                    f"Trail '{trail_name}' is not configured to log data events. "
                                    "S3 object-level and Lambda function activity is not audited."
                                ),
                                severity=Severity.MEDIUM,
                                remediation=(
                                    f"Enable data events: aws cloudtrail put-event-selectors "
                                    f"--trail-name {trail_name} --event-selectors "
                                    '\'[{"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::*"]}]}]\''
                                ),
                                references=[
                                    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"
                                ],
                            )
                        )

                except Exception:
                    pass

        except Exception:
            pass

        return findings
