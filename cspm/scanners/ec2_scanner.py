"""EC2 security scanner."""

from typing import Any

from cspm.models import Finding, Severity
from cspm.scanners.base import BaseScanner

# High-risk ports that should never be open to 0.0.0.0/0
HIGH_RISK_PORTS = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Medium-risk ports
MEDIUM_RISK_PORTS = {
    20: "FTP Data",
    21: "FTP",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
}


def _port_risk(port: int) -> tuple[Severity, str]:
    """Determine risk level for an open port."""
    if port in HIGH_RISK_PORTS:
        return Severity.HIGH, HIGH_RISK_PORTS[port]
    if port in MEDIUM_RISK_PORTS:
        return Severity.MEDIUM, MEDIUM_RISK_PORTS[port]
    return Severity.LOW, f"Port {port}"


class EC2Scanner(BaseScanner):
    """Scanner for AWS EC2 security posture."""

    @property
    def service_name(self) -> str:
        return "ec2"

    def scan(self) -> list[Finding]:
        """Scan EC2 security groups for open ports."""
        findings: list[Finding] = []

        paginator = self.client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                findings.extend(self._analyze_security_group(sg))

        return findings

    def _analyze_security_group(self, sg: dict[str, Any]) -> list[Finding]:
        """Analyze a single security group for security issues."""
        findings: list[Finding] = []
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "unknown")
        vpc_id = sg.get("VpcId", "default")

        # Check ingress rules
        for rule in sg.get("IpPermissions", []):
            findings.extend(self._check_ingress_rule(sg_id, sg_name, vpc_id, rule))

        # Check for overly permissive egress (less critical but worth noting)
        for rule in sg.get("IpPermissionsEgress", []):
            findings.extend(self._check_egress_rule(sg_id, sg_name, vpc_id, rule))

        return findings

    def _check_ingress_rule(
        self, sg_id: str, sg_name: str, vpc_id: str, rule: dict[str, Any]
    ) -> list[Finding]:
        """Check an ingress rule for security issues."""
        findings: list[Finding] = []

        ip_protocol = rule.get("IpProtocol", "-1")
        from_port = rule.get("FromPort", -1)
        to_port = rule.get("ToPort", -1)

        # Check IPv4 ranges
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                findings.extend(
                    self._create_open_port_findings(
                        sg_id, sg_name, vpc_id, ip_protocol, from_port, to_port, "ipv4"
                    )
                )

        # Check IPv6 ranges
        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6", "")
            if cidr == "::/0":
                findings.extend(
                    self._create_open_port_findings(
                        sg_id, sg_name, vpc_id, ip_protocol, from_port, to_port, "ipv6"
                    )
                )

        return findings

    def _create_open_port_findings(
        self,
        sg_id: str,
        sg_name: str,
        vpc_id: str,
        ip_protocol: str,
        from_port: int,
        to_port: int,
        ip_version: str,
    ) -> list[Finding]:
        """Create findings for open ports to the internet."""
        findings: list[Finding] = []

        # All traffic
        if ip_protocol == "-1":
            findings.append(
                Finding(
                    id=f"EC2-SG-ALL-TRAFFIC-{sg_id}-{ip_version}",
                    service="ec2",
                    resource=f"arn:aws:ec2:::security-group/{sg_id}",
                    region=self.region,
                    title="Security Group Allows All Traffic from Internet",
                    description=(
                        f"Security group '{sg_name}' ({sg_id}) in VPC {vpc_id} allows "
                        f"ALL inbound traffic from {ip_version} internet (0.0.0.0/0 or ::/0). "
                        "This is extremely dangerous."
                    ),
                    severity=Severity.CRITICAL,
                    remediation=(
                        f"Restrict ingress rules: aws ec2 revoke-security-group-ingress "
                        f"--group-id {sg_id} --ip-permissions 'IpProtocol=-1,IpRanges=[{{CidrIp=0.0.0.0/0}}]' "
                        "Then add specific rules for required ports and sources."
                    ),
                    references=[
                        "https://docs.aws.amazon.com/vpc/latest/userguide/security-groups.html"
                    ],
                )
            )
            return findings

        # Port range
        if from_port != to_port:
            port_range = f"{from_port}-{to_port}"
            findings.append(
                Finding(
                    id=f"EC2-SG-RANGE-{sg_id}-{from_port}-{to_port}-{ip_version}",
                    service="ec2",
                    resource=f"arn:aws:ec2:::security-group/{sg_id}",
                    region=self.region,
                    title=f"Security Group Allows Port Range {port_range} from Internet",
                    description=(
                        f"Security group '{sg_name}' ({sg_id}) allows ports {port_range}/"
                        f"{ip_protocol} from {ip_version} internet. Port ranges should be minimized."
                    ),
                    severity=Severity.MEDIUM,
                    remediation=(
                        f"Split into individual port rules and restrict source CIDRs: "
                        f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                        f"--protocol {ip_protocol} --port {from_port}-{to_port} --cidr 0.0.0.0/0"
                    ),
                    references=[
                        "https://docs.aws.amazon.com/vpc/latest/userguide/security-groups.html"
                    ],
                )
            )
            return findings

        # Single port
        port = from_port
        severity, service_name = _port_risk(port)

        # Special case: SSH/RDP should be CRITICAL when open
        if port in (22, 3389):
            severity = Severity.CRITICAL

        findings.append(
            Finding(
                id=f"EC2-SG-OPEN-{sg_id}-{port}-{ip_version}",
                service="ec2",
                resource=f"arn:aws:ec2:::security-group/{sg_id}",
                region=self.region,
                title=f"Security Group Allows {service_name} ({port}) from Internet",
                description=(
                    f"Security group '{sg_name}' ({sg_id}) allows {service_name} (port {port})/"
                    f"{ip_protocol} from {ip_version} internet. "
                    f"This exposes {service_name} to brute force and exploitation."
                ),
                severity=severity,
                remediation=(
                    f"Restrict access: replace 0.0.0.0/0 with specific CIDRs or use a bastion host. "
                    f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                    f"--protocol {ip_protocol} --port {port} --cidr 0.0.0.0/0"
                ),
                references=[
                    "https://docs.aws.amazon.com/vpc/latest/userguide/security-groups.html",
                    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html",
                ],
            )
        )

        return findings

    def _check_egress_rule(
        self, sg_id: str, sg_name: str, vpc_id: str, rule: dict[str, Any]
    ) -> list[Finding]:
        """Check egress rules. Only flag truly concerning ones."""
        findings: list[Finding] = []

        ip_protocol = rule.get("IpProtocol", "-1")

        # Flag all-traffic egress as informational
        if ip_protocol == "-1":
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    findings.append(
                        Finding(
                            id=f"EC2-SG-EGRESS-ALL-{sg_id}",
                            service="ec2",
                            resource=f"arn:aws:ec2:::security-group/{sg_id}",
                            region=self.region,
                            title="Security Group Allows All Egress Traffic",
                            description=(
                                f"Security group '{sg_name}' ({sg_id}) allows all outbound traffic. "
                                "While common, consider restricting egress for sensitive workloads."
                            ),
                            severity=Severity.INFO,
                            remediation=(
                                "Review and restrict egress rules to required destinations only."
                            ),
                            references=[
                                "https://docs.aws.amazon.com/vpc/latest/userguide/security-groups.html"
                            ],
                        )
                    )

        return findings
