COMPLIANCE_MAP = {
    "S3_PUBLIC_READ": ["CIS 2.1", "SOC2 CC6.6"],
    "S3_NO_ENCRYPTION": ["CIS 2.2"],
    "IAM_USER_NO_MFA": ["CIS 1.2"],
    "SECURITY_GROUP_OPEN": ["CIS 4.1"],
    "CLOUDTRAIL_DISABLED": ["CIS 3.1", "SOC2 CC7.2"],
}


def map_compliance(finding) -> list[str]:
    return COMPLIANCE_MAP.get(finding.rule_id, [])
