"""IAM security scanner."""

from typing import Any

from cspm.models import Finding, Severity
from cspm.scanners.base import BaseScanner

# Dangerous IAM actions that indicate overly permissive policies
DANGEROUS_ACTIONS = {
    "*": Severity.CRITICAL,
    "iam:*": Severity.CRITICAL,
    "s3:*": Severity.HIGH,
    "ec2:*": Severity.HIGH,
    "lambda:*": Severity.HIGH,
    "sts:AssumeRole": Severity.MEDIUM,
    "sts:AssumeRoleWithSAML": Severity.MEDIUM,
    "sts:AssumeRoleWithWebIdentity": Severity.MEDIUM,
}

# Managed policies known to be overly permissive
OVERLY_PERMISSIVE_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess": Severity.CRITICAL,
    "arn:aws:iam::aws:policy/PowerUserAccess": Severity.HIGH,
    "arn:aws:iam::aws:policy/ReadOnlyAccess": Severity.LOW,
}


class IAMScanner(BaseScanner):
    """Scanner for AWS IAM security posture."""

    @property
    def service_name(self) -> str:
        return "iam"

    def scan(self) -> list[Finding]:
        """Scan IAM for security issues."""
        findings: list[Finding] = []

        findings.extend(self._scan_users())
        findings.extend(self._scan_roles())
        findings.extend(self._scan_policies())
        findings.extend(self._scan_password_policy())
        findings.extend(self._scan_account_summary())

        return findings

    def _scan_users(self) -> list[Finding]:
        """Scan IAM users for security issues."""
        findings: list[Finding] = []
        paginator = self.client.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                findings.extend(self._check_user_access_keys(username))
                findings.extend(self._check_user_mfa(username))
                findings.extend(self._check_user_inline_policies(username))
                findings.extend(self._check_user_attached_policies(username))

        return findings

    def _check_user_access_keys(self, username: str) -> list[Finding]:
        """Check for old or unused access keys."""
        findings: list[Finding] = []

        try:
            response = self.client.list_access_keys(UserName=username)
            keys = response.get("AccessKeyMetadata", [])

            for key in keys:
                key_id = key["AccessKeyId"]
                status = key["Status"]
                create_date = key["CreateDate"]

                # Check for inactive keys
                if status == "Inactive":
                    findings.append(
                        Finding(
                            id=f"IAM-INACTIVE-KEY-{key_id}",
                            service="iam",
                            resource=f"arn:aws:iam:::user/{username}",
                            region="global",
                            title="Inactive IAM Access Key",
                            description=(
                                f"Access key {key_id} for user '{username}' is inactive. "
                                "Inactive keys should be deleted to reduce attack surface."
                            ),
                            severity=Severity.LOW,
                            remediation=(
                                f"Delete inactive key: "
                                f"aws iam delete-access-key --user-name {username} --access-key-id {key_id}"
                            ),
                            references=[
                                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
                            ],
                            raw_details=key,
                        )
                    )
                    continue

                # Check key age (90 days warning, 180 days critical)
                from datetime import datetime, timezone

                age_days = (datetime.now(timezone.utc) - create_date).days

                if age_days > 180:
                    findings.append(
                        Finding(
                            id=f"IAM-OLD-KEY-{key_id}",
                            service="iam",
                            resource=f"arn:aws:iam:::user/{username}",
                            region="global",
                            title="IAM Access Key Older Than 180 Days",
                            description=(
                                f"Access key {key_id} for user '{username}' is {age_days} days old. "
                                "Rotate access keys regularly (recommended every 90 days)."
                            ),
                            severity=Severity.HIGH,
                            remediation=(
                                "Rotate the access key: create a new key, update applications, "
                                f"then delete the old key: aws iam delete-access-key --user-name {username} "
                                f"--access-key-id {key_id}"
                            ),
                            references=[
                                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey"
                            ],
                            raw_details={"key": key, "age_days": age_days},
                        )
                    )
                elif age_days > 90:
                    findings.append(
                        Finding(
                            id=f"IAM-AGING-KEY-{key_id}",
                            service="iam",
                            resource=f"arn:aws:iam:::user/{username}",
                            region="global",
                            title="IAM Access Key Older Than 90 Days",
                            description=(
                                f"Access key {key_id} for user '{username}' is {age_days} days old. "
                                "Consider rotating it soon."
                            ),
                            severity=Severity.MEDIUM,
                            remediation="Plan to rotate this access key within the next 30 days.",
                            references=[
                                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey"
                            ],
                            raw_details={"key": key, "age_days": age_days},
                        )
                    )

                # Check for unused keys (if last used info available)
                try:
                    last_used = self.client.get_access_key_last_used(AccessKeyId=key_id)
                    last_used_date = last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                    if last_used_date:
                        unused_days = (datetime.now(timezone.utc) - last_used_date).days
                        if unused_days > 90:
                            findings.append(
                                Finding(
                                    id=f"IAM-UNUSED-KEY-{key_id}",
                                    service="iam",
                                    resource=f"arn:aws:iam:::user/{username}",
                                    region="global",
                                    title="Unused IAM Access Key",
                                    description=(
                                        f"Access key {key_id} for user '{username}' has not been used "
                                        f"for {unused_days} days. Consider deleting it."
                                    ),
                                    severity=Severity.MEDIUM,
                                    remediation=(
                                        f"Delete unused key: "
                                        f"aws iam delete-access-key --user-name {username} --access-key-id {key_id}"
                                    ),
                                    references=[
                                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
                                    ],
                                    raw_details={"key": key, "unused_days": unused_days},
                                )
                            )
                except Exception:
                    pass

        except Exception as e:
            findings.append(
                Finding(
                    id=f"IAM-KEY-ERR-{username}",
                    service="iam",
                    resource=f"arn:aws:iam:::user/{username}",
                    region="global",
                    title="IAM Access Key Check Failed",
                    description=f"Could not check access keys: {str(e)}",
                    severity=Severity.INFO,
                    remediation="Verify IAM permissions for iam:ListAccessKeys.",
                )
            )

        return findings

    def _check_user_mfa(self, username: str) -> list[Finding]:
        """Check if user has MFA enabled."""
        findings: list[Finding] = []

        try:
            devices = self.client.list_mfa_devices(UserName=username)
            if not devices.get("MFADevices", []):
                findings.append(
                    Finding(
                        id=f"IAM-NO-MFA-{username}",
                        service="iam",
                        resource=f"arn:aws:iam:::user/{username}",
                        region="global",
                        title="IAM User Without MFA",
                        description=(
                            f"User '{username}' does not have MFA enabled. "
                            "Console access without MFA is a significant security risk."
                        ),
                        severity=Severity.HIGH,
                        remediation=(
                            "Enable MFA: AWS Console → IAM → Users → "
                            f"{username} → Security credentials → Assign MFA device"
                        ),
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                        ],
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    id=f"IAM-MFA-ERR-{username}",
                    service="iam",
                    resource=f"arn:aws:iam:::user/{username}",
                    region="global",
                    title="IAM MFA Check Failed",
                    description=f"Could not check MFA devices: {str(e)}",
                    severity=Severity.INFO,
                    remediation="Verify IAM permissions for iam:ListMFADevices.",
                )
            )

        return findings

    def _check_user_inline_policies(self, username: str) -> list[Finding]:
        """Check user's inline policies for over-permissiveness."""
        findings: list[Finding] = []

        try:
            response = self.client.list_user_policies(UserName=username)
            for policy_name in response.get("PolicyNames", []):
                policy = self.client.get_user_policy(UserName=username, PolicyName=policy_name)
                doc = policy.get("PolicyDocument", {})
                findings.extend(
                    self._analyze_policy_document(
                        doc,
                        f"inline-user-{username}-{policy_name}",
                        f"arn:aws:iam:::user/{username}/policy/{policy_name}",
                    )
                )
        except Exception:
            pass

        return findings

    def _check_user_attached_policies(self, username: str) -> list[Finding]:
        """Check user's attached managed policies."""
        findings: list[Finding] = []

        try:
            response = self.client.list_attached_user_policies(UserName=username)
            for policy in response.get("AttachedPolicies", []):
                arn = policy["PolicyArn"]
                if arn in OVERLY_PERMISSIVE_POLICIES:
                    findings.append(
                        Finding(
                            id=f"IAM-BAD-POLICY-{username}-{policy['PolicyName']}",
                            service="iam",
                            resource=f"arn:aws:iam:::user/{username}",
                            region="global",
                            title=f"Overly Permissive Policy Attached: {policy['PolicyName']}",
                            description=(
                                f"User '{username}' is attached to {policy['PolicyName']}, "
                                "which grants excessive permissions."
                            ),
                            severity=OVERLY_PERMISSIVE_POLICIES[arn],
                            remediation=(
                                f"Detach policy: aws iam detach-user-policy --user-name {username} "
                                f"--policy-arn {arn}"
                            ),
                            references=[
                                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                            ],
                        )
                    )
        except Exception:
            pass

        return findings

    def _scan_roles(self) -> list[Finding]:
        """Scan IAM roles for security issues."""
        findings: list[Finding] = []
        paginator = self.client.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                findings.extend(self._check_role_trust_policy(role))
                findings.extend(self._check_role_inline_policies(role_name))
                findings.extend(self._check_role_attached_policies(role_name))

        return findings

    def _check_role_trust_policy(self, role: dict[str, Any]) -> list[Finding]:
        """Check if role trust policy allows overly broad assume role."""
        findings: list[Finding] = []
        role_name = role["RoleName"]
        assume_doc = role.get("AssumeRolePolicyDocument", {})

        for statement in assume_doc.get("Statement", []):
            principal = statement.get("Principal", {})
            # Check for wildcard principals
            if principal.get("AWS") == "*":
                findings.append(
                    Finding(
                        id=f"IAM-ROLE-WILDCARD-{role_name}",
                        service="iam",
                        resource=role["Arn"],
                        region="global",
                        title="IAM Role with Wildcard Trust Policy",
                        description=(
                            f"Role '{role_name}' allows any AWS account to assume it. "
                            "This is a critical security risk."
                        ),
                        severity=Severity.CRITICAL,
                        remediation=(
                            f"Update trust policy to restrict to specific accounts or services: "
                            f"aws iam update-assume-role-policy --role-name {role_name} "
                            "--policy-document file://trust-policy.json"
                        ),
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html"
                        ],
                        raw_details=statement,
                    )
                )

            # Check for overly broad service principals
            service = principal.get("Service", "")
            if isinstance(service, str) and service == "*":
                findings.append(
                    Finding(
                        id=f"IAM-ROLE-SVC-WILDCARD-{role_name}",
                        service="iam",
                        resource=role["Arn"],
                        region="global",
                        title="IAM Role with Wildcard Service Principal",
                        description=(
                            f"Role '{role_name}' allows any AWS service to assume it. "
                            "Restrict to specific services."
                        ),
                        severity=Severity.HIGH,
                        remediation=(
                            "Update trust policy to specify exact services (e.g., lambda.amazonaws.com)."
                        ),
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"
                        ],
                        raw_details=statement,
                    )
                )

        return findings

    def _check_role_inline_policies(self, role_name: str) -> list[Finding]:
        """Check role inline policies."""
        findings: list[Finding] = []

        try:
            response = self.client.list_role_policies(RoleName=role_name)
            for policy_name in response.get("PolicyNames", []):
                policy = self.client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                doc = policy.get("PolicyDocument", {})
                findings.extend(
                    self._analyze_policy_document(
                        doc,
                        f"inline-role-{role_name}-{policy_name}",
                        f"arn:aws:iam:::role/{role_name}/policy/{policy_name}",
                    )
                )
        except Exception:
            pass

        return findings

    def _check_role_attached_policies(self, role_name: str) -> list[Finding]:
        """Check role attached managed policies."""
        findings: list[Finding] = []

        try:
            response = self.client.list_attached_role_policies(RoleName=role_name)
            for policy in response.get("AttachedPolicies", []):
                arn = policy["PolicyArn"]
                if arn in OVERLY_PERMISSIVE_POLICIES:
                    findings.append(
                        Finding(
                            id=f"IAM-ROLE-BAD-POLICY-{role_name}-{policy['PolicyName']}",
                            service="iam",
                            resource=f"arn:aws:iam:::role/{role_name}",
                            region="global",
                            title=f"Overly Permissive Policy on Role: {policy['PolicyName']}",
                            description=(
                                f"Role '{role_name}' is attached to {policy['PolicyName']}, "
                                "which grants excessive permissions."
                            ),
                            severity=OVERLY_PERMISSIVE_POLICIES[arn],
                            remediation=(
                                f"Detach policy: aws iam detach-role-policy --role-name {role_name} "
                                f"--policy-arn {arn}"
                            ),
                            references=[
                                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                            ],
                        )
                    )
        except Exception:
            pass

        return findings

    def _scan_policies(self) -> list[Finding]:
        """Scan customer-managed policies for over-permissiveness."""
        findings: list[Finding] = []
        paginator = self.client.get_paginator("list_policies")

        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                policy_arn = policy["Arn"]
                try:
                    version = self.client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy["DefaultVersionId"],
                    )
                    doc = version["PolicyVersion"]["Document"]
                    findings.extend(
                        self._analyze_policy_document(
                            doc,
                            f"managed-{policy['PolicyName']}",
                            policy_arn,
                        )
                    )
                except Exception:
                    pass

        return findings

    def _analyze_policy_document(
        self, document: dict[str, Any], finding_id_prefix: str, resource: str
    ) -> list[Finding]:
        """Analyze a policy document for dangerous permissions."""
        findings: list[Finding] = []

        for statement in document.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # Check for wildcard actions
            for action in actions:
                action_upper = action.upper()
                for dangerous, severity in DANGEROUS_ACTIONS.items():
                    if (
                        action_upper == dangerous.upper() or action_upper.endswith(":*")
                    ) and "*" in resources:
                        findings.append(
                            Finding(
                                id=f"IAM-WILDCARD-{finding_id_prefix}-{action}",
                                service="iam",
                                resource=resource,
                                region="global",
                                title="Overly Permissive IAM Policy",
                                description=(
                                    f"Policy grants '{action}' on resource '*'. "
                                    "This violates the principle of least privilege."
                                ),
                                severity=severity,
                                remediation=(
                                    "Refine the policy to restrict actions and resources. "
                                    "Use specific ARNs instead of '*' and limit actions to "
                                    "only those required."
                                ),
                                references=[
                                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                                ],
                                raw_details=statement,
                            )
                        )
                        break

            # Check for wildcard resource with sensitive actions
            if "*" in resources:
                sensitive = [
                    a
                    for a in actions
                    if any(a.upper().startswith(s.upper().rstrip("*")) for s in DANGEROUS_ACTIONS)
                ]
                if sensitive:
                    findings.append(
                        Finding(
                            id=f"IAM-WILDCARD-RES-{finding_id_prefix}",
                            service="iam",
                            resource=resource,
                            region="global",
                            title="IAM Policy with Wildcard Resource",
                            description=(
                                f"Policy allows actions on all resources ('*'). "
                                f"Sensitive actions: {', '.join(sensitive[:5])}"
                            ),
                            severity=Severity.HIGH,
                            remediation=(
                                "Specify exact resource ARNs in the policy instead of '*'."
                            ),
                            references=[
                                "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html"
                            ],
                            raw_details=statement,
                        )
                    )

        return findings

    def _scan_password_policy(self) -> list[Finding]:
        """Check account password policy."""
        findings: list[Finding] = []

        try:
            policy = self.client.get_account_password_policy()["PasswordPolicy"]

            checks = [
                (
                    not policy.get("MinimumPasswordLength", 0) >= 14,
                    "IAM-Password-MinLength",
                    "Password Policy Minimum Length Too Short",
                    "Minimum password length is less than 14 characters.",
                    Severity.MEDIUM,
                    "Set MinimumPasswordLength to at least 14.",
                ),
                (
                    not policy.get("RequireSymbols", False),
                    "IAM-Password-Symbols",
                    "Password Policy Missing Symbol Requirement",
                    "Passwords are not required to contain symbols.",
                    Severity.LOW,
                    "Enable RequireSymbols in the password policy.",
                ),
                (
                    not policy.get("RequireNumbers", False),
                    "IAM-Password-Numbers",
                    "Password Policy Missing Number Requirement",
                    "Passwords are not required to contain numbers.",
                    Severity.LOW,
                    "Enable RequireNumbers in the password policy.",
                ),
                (
                    not policy.get("RequireUppercaseCharacters", False),
                    "IAM-Password-Uppercase",
                    "Password Policy Missing Uppercase Requirement",
                    "Passwords are not required to contain uppercase characters.",
                    Severity.LOW,
                    "Enable RequireUppercaseCharacters in the password policy.",
                ),
                (
                    not policy.get("RequireLowercaseCharacters", False),
                    "IAM-Password-Lowercase",
                    "Password Policy Missing Lowercase Requirement",
                    "Passwords are not required to contain lowercase characters.",
                    Severity.LOW,
                    "Enable RequireLowercaseCharacters in the password policy.",
                ),
                (
                    not policy.get("ExpirePasswords", False),
                    "IAM-Password-Expiry",
                    "Password Policy Does Not Expire Passwords",
                    "Passwords never expire, increasing risk of compromise.",
                    Severity.MEDIUM,
                    "Enable password expiration (MaxPasswordAge <= 90 days).",
                ),
                (
                    policy.get("MaxPasswordAge", 999) > 90,
                    "IAM-Password-MaxAge",
                    "Password Maximum Age Exceeds 90 Days",
                    f"MaxPasswordAge is {policy.get('MaxPasswordAge')} days.",
                    Severity.LOW,
                    "Set MaxPasswordAge to 90 days or less.",
                ),
                (
                    not policy.get("PasswordReusePrevention", 0) >= 5,
                    "IAM-Password-Reuse",
                    "Password Reuse Prevention Too Weak",
                    "Users can reuse recent passwords.",
                    Severity.LOW,
                    "Set PasswordReusePrevention to at least 5.",
                ),
            ]

            for condition, fid, title, desc, severity, remediation in checks:
                if condition:
                    findings.append(
                        Finding(
                            id=fid,
                            service="iam",
                            resource="arn:aws:iam:::account/password-policy",
                            region="global",
                            title=title,
                            description=desc,
                            severity=severity,
                            remediation=remediation,
                            references=[
                                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
                            ],
                            raw_details=policy,
                        )
                    )

        except self.client.exceptions.NoSuchEntityException:
            findings.append(
                Finding(
                    id="IAM-NO-PASSWORD-POLICY",
                    service="iam",
                    resource="arn:aws:iam:::account/password-policy",
                    region="global",
                    title="No Account Password Policy Configured",
                    description=(
                        "The AWS account does not have a custom password policy. "
                        "Default policies may be weaker than recommended."
                    ),
                    severity=Severity.MEDIUM,
                    remediation=(
                        "Create a password policy: aws iam update-account-password-policy "
                        "--minimum-password-length 14 --require-symbols --require-numbers "
                        "--require-uppercase-characters --require-lowercase-characters "
                        "--max-password-age 90 --password-reuse-prevention 5"
                    ),
                    references=[
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
                    ],
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    id="IAM-PASSWORD-POLICY-ERR",
                    service="iam",
                    resource="arn:aws:iam:::account/password-policy",
                    region="global",
                    title="Password Policy Check Failed",
                    description=f"Could not retrieve password policy: {str(e)}",
                    severity=Severity.INFO,
                    remediation="Verify IAM permissions for iam:GetAccountPasswordPolicy.",
                )
            )

        return findings

    def _scan_account_summary(self) -> list[Finding]:
        """Check account-level IAM summary metrics."""
        findings: list[Finding] = []

        try:
            summary = self.client.get_account_summary()["SummaryMap"]

            # Check for root account access keys
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                findings.append(
                    Finding(
                        id="IAM-ROOT-ACCESS-KEYS",
                        service="iam",
                        resource="arn:aws:iam:::root",
                        region="global",
                        title="Root Account Access Keys Present",
                        description=(
                            "The root account has active access keys. "
                            "Root access keys should be deleted and never used."
                        ),
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Delete root access keys immediately: AWS Console → IAM → Dashboard → "
                            "'Delete root access keys'"
                        ),
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
                        ],
                    )
                )

            # Check for root account MFA
            if summary.get("AccountMFAEnabled", 0) == 0:
                findings.append(
                    Finding(
                        id="IAM-ROOT-NO-MFA",
                        service="iam",
                        resource="arn:aws:iam:::root",
                        region="global",
                        title="Root Account Without MFA",
                        description=(
                            "The root account does not have MFA enabled. "
                            "This is the highest-priority security fix."
                        ),
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Enable MFA on root account: AWS Console → IAM → Dashboard → "
                            "'Activate MFA on your root account'"
                        ),
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"
                        ],
                    )
                )

        except Exception as e:
            findings.append(
                Finding(
                    id="IAM-ACCOUNT-SUMMARY-ERR",
                    service="iam",
                    resource="arn:aws:iam:::account",
                    region="global",
                    title="Account Summary Check Failed",
                    description=f"Could not retrieve account summary: {str(e)}",
                    severity=Severity.INFO,
                    remediation="Verify IAM permissions for iam:GetAccountSummary.",
                )
            )

        return findings
