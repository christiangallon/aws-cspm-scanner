# 🔒 AWS Cloud Security Posture Management (CSPM) Scanner

A production-grade, modular AWS security scanning tool built with **Python** and **boto3**. It audits your AWS infrastructure for misconfigurations across S3, IAM, EC2, and CloudTrail — generating actionable JSON and HTML reports with severity ratings, risk scoring, compliance mapping, and remediation guidance.

---

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Scanners](#scanners)
- [Output Formats](#output-formats)
- [Risk Scoring](#risk-scoring)
- [Compliance Mapping](#compliance-mapping)
- [Development](#development)
- [CI/CD](#cicd)
- [Docker](#docker)
- [Screenshots](#screenshots)
- [License](#license)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Multi-Service Scanning** | S3, IAM, EC2 Security Groups, CloudTrail |
| **Severity Classification** | CRITICAL → HIGH → MEDIUM → LOW → INFO |
| **Risk Scoring** | 0-100 risk score based on weighted severity |
| **Compliance Mapping** | CIS, SOC2, and custom framework mappings |
| **Cross-Account Scanning** | Assume roles for multi-account audits |
| **Actionable Remediation** | Every finding includes CLI commands and doc links |
| **Parallel Execution** | Multi-region scanning with configurable workers |
| **Rich Console Output** | Color-coded terminal report via Rich |
| **JSON & HTML Reports** | Machine-readable and human-friendly outputs |
| **Exit Codes** | `0`=clean, `1`=medium, `2`=critical/high — CI/CD friendly |
| **Docker Support** | Run anywhere with the included Dockerfile |
| **86% Test Coverage** | Comprehensive test suite with moto mocks |

---

## 🏗️ Architecture

```
aws-cspm/
├── cspm/
│   ├── __init__.py
│   ├── models.py              # Pydantic data models + severity weights
│   ├── reporter.py            # Report generation (JSON, HTML, console)
│   ├── cli.py                 # Click CLI entrypoint
│   ├── risk.py                # Risk scoring engine
│   ├── compliance.py          # CIS/SOC2 compliance mappings
│   ├── utils/
│   │   └── aws_session.py     # AWS session + role assumption
│   └── scanners/
│       ├── __init__.py
│       ├── base.py            # Abstract scanner interface
│       ├── s3_scanner.py      # S3: public access, encryption, versioning
│       ├── iam_scanner.py     # IAM: policies, keys, MFA, password policy
│       ├── ec2_scanner.py     # EC2: security group open ports
│       └── cloudtrail_scanner.py  # CloudTrail: logging, encryption, config
├── tests/                     # pytest + moto test suite (44 tests)
├── Dockerfile                 # Container image
├── Makefile                   # CI pipeline commands
├── pyproject.toml             # Modern Python packaging
└── README.md
```

---

## 🚀 Installation

### Prerequisites

- Python 3.10+
- AWS credentials configured (`~/.aws/credentials` or env vars)
- Appropriate IAM permissions (see below)

### Quick Install

```bash
git clone https://github.com/yourusername/aws-cspm.git
cd aws-cspm
pip install -e ".[dev]"
```

### AWS IAM Permissions

The scanner requires read-only access to the services it audits:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucket*",
        "s3:ListAllMyBuckets",
        "iam:Get*",
        "iam:List*",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRegions",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "sts:GetCallerIdentity",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 🖥️ Usage

### Basic Scan

```bash
aws-cspm
```

### Scan Specific Services

```bash
aws-cspm --services s3,ec2
```

### Scan Specific Region

```bash
aws-cspm --region us-east-1
```

### Cross-Account Scan (Assume Role)

```bash
aws-cspm --role-arn arn:aws:iam::123456789012:role/CSPMScannerRole
```

### Use AWS Profile

```bash
aws-cspm --profile production
```

### Export Reports

```bash
aws-cspm --output report.json --html report.html
```

### Filter by Severity

```bash
aws-cspm --severity HIGH
```

### Full Options

```bash
aws-cspm --help
```

---

## 🔍 Scanners

### S3 Scanner

| Check | Severity | Description |
|-------|----------|-------------|
| Public Access Block | CRITICAL/HIGH | Missing or incomplete public access block |
| Default Encryption | HIGH | No SSE-S3 or SSE-KMS configured |
| Weak Encryption | MEDIUM | Using SSE-S3 instead of SSE-KMS |
| Versioning | MEDIUM | Versioning disabled or suspended |
| Access Logging | LOW | Logging not enabled |

### IAM Scanner

| Check | Severity | Description |
|-------|----------|-------------|
| Root Access Keys | CRITICAL | Root account has active access keys |
| Root MFA | CRITICAL | Root account lacks MFA |
| Wildcard Trust Policy | CRITICAL | Role allows any AWS account to assume it |
| Admin Policy Attached | CRITICAL | AdministratorAccess policy in use |
| Wildcard IAM Policy | CRITICAL/HIGH | `Action: *` on `Resource: *` |
| User Without MFA | HIGH | Console user lacks MFA device |
| Old Access Keys | HIGH | Key age > 180 days |
| Unused Access Keys | MEDIUM | Key unused > 90 days |
| Weak Password Policy | MEDIUM/LOW | Missing complexity requirements |

### EC2 Scanner

| Check | Severity | Description |
|-------|----------|-------------|
| All Traffic Open | CRITICAL | Security group allows all inbound traffic |
| SSH Open (0.0.0.0/0) | CRITICAL | Port 22 exposed to internet |
| RDP Open (0.0.0.0/0) | CRITICAL | Port 3389 exposed to internet |
| Database Ports Open | HIGH | MySQL, PostgreSQL, MongoDB, Redis exposed |
| Port Range Open | MEDIUM | Range of ports exposed instead of single ports |
| HTTP/HTTPS Open | MEDIUM | Port 80/443 open (context-dependent) |

### CloudTrail Scanner

| Check | Severity | Description |
|-------|----------|-------------|
| Not Enabled | CRITICAL | No CloudTrail trails exist |
| Not Logging | CRITICAL | Trails exist but not actively logging |
| Log Validation Disabled | HIGH | Cannot cryptographically verify log integrity |
| Not Multi-Region | MEDIUM | Trail only covers one region |
| No KMS Encryption | MEDIUM | Logs encrypted with S3-managed keys only |
| No Data Events | MEDIUM | S3 object-level and Lambda events not logged |
| No SNS Notifications | LOW | No real-time delivery alerts |

---

## 📊 Output Formats

### Console (Rich)

```
┌─────────────────────────────────────────────────────────────┐
│ Scan Details                                                │
│ Account: 123456789012                                       │
│ Risk Score: 67/100                                          │
│ Services Scanned: cloudtrail, ec2, iam, s3                  │
│ Scanned At: 2024-01-15T10:30:00                             │
└─────────────────────────────────────────────────────────────┘
┌──────────────────┬───────┐
│ Severity         │ Count │
├──────────────────┼───────┤
│ CRITICAL         │ 2     │
│ HIGH             │ 5     │
│ MEDIUM           │ 3     │
│ LOW              │ 1     │
│ INFO             │ 0     │
│ ──────────       │ ───   │
│ Total            │ 11    │
└──────────────────┴───────┘

Risk Score: 67/100
🟠 High risk level — significant issues found
```

### JSON

```json
{
  "summary": {
    "total_findings": 11,
    "critical": 2,
    "high": 5,
    "medium": 3,
    "low": 1,
    "info": 0,
    "services_scanned": ["s3", "iam", "ec2", "cloudtrail"],
    "scan_duration_seconds": 12.34,
    "scanned_at": "2024-01-15T10:30:00",
    "account_id": "123456789012"
  },
  "risk_score": 67,
  "risk_summary": {
    "total": 11,
    "by_severity": {
      "CRITICAL": 2,
      "HIGH": 5,
      "MEDIUM": 3,
      "LOW": 1
    }
  },
  "compliance_mappings": {
    "S3_PUBLIC_READ": ["CIS 2.1", "SOC2 CC6.6"],
    "IAM_USER_NO_MFA": ["CIS 1.2"]
  },
  "findings": [
    {
      "id": "S3-PUBLIC-ACCESS-my-bucket",
      "rule_id": "S3_PUBLIC_READ",
      "service": "s3",
      "resource": "my-bucket",
      "region": "us-east-1",
      "title": "S3 Bucket Missing Public Access Block",
      "description": "Bucket 'my-bucket' has no public access block configuration...",
      "severity": "CRITICAL",
      "remediation": "aws s3api put-public-access-block --bucket my-bucket ...",
      "references": ["https://docs.aws.amazon.com/..."],
      "scanned_at": "2024-01-15T10:30:00"
    }
  ]
}
```

### HTML

A fully styled HTML report with severity-colored cards, summary dashboard, risk score gauge, compliance mappings, and clickable references.

---

## 🎯 Risk Scoring

The scanner calculates a **0-100 risk score** based on weighted severity counts:

| Severity | Weight |
|----------|--------|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 2 |
| INFO | 1 |

Formula: `score = min(100, (total_weight / 50) * 100)`

| Score | Level | Action |
|-------|-------|--------|
| 80-100 | 🔴 Critical | Immediate action required |
| 50-79 | 🟠 High | Significant issues found |
| 20-49 | 🟡 Medium | Review recommended |
| 0-19 | 🟢 Low | Posture looks good |

---

## 📋 Compliance Mapping

Findings are mapped to compliance frameworks automatically:

| Rule ID | CIS Control | SOC2 |
|---------|-------------|------|
| S3_PUBLIC_READ | CIS 2.1 | CC6.6 |
| S3_NO_ENCRYPTION | CIS 2.2 | — |
| IAM_USER_NO_MFA | CIS 1.2 | — |
| SECURITY_GROUP_OPEN | CIS 4.1 | — |
| CLOUDTRAIL_DISABLED | CIS 3.1 | CC7.2 |

Add custom mappings in `cspm/compliance.py`.

---

## 🧪 Development

### Setup

```bash
pip install -e ".[dev]"
pre-commit install
```

### Run Tests

```bash
make test          # Run all tests with 70% coverage threshold
pytest             # Run all tests
pytest -v          # Verbose output
pytest tests/test_s3_scanner.py  # Specific test file
```

### Lint & Format

```bash
make format        # Check formatting
make format-fix    # Auto-fix formatting
```

### Full CI Pipeline

```bash
make ci            # Run format check, tests, and Docker build
```

### Test Coverage

```bash
pytest --cov=cspm --cov-report=html
open htmlcov/index.html
```

---

## 🔄 CI/CD Integration

The scanner exits with meaningful codes:

| Exit Code | Meaning |
|-----------|---------|
| `0` | No findings or only INFO/LOW |
| `1` | MEDIUM findings detected |
| `2` | CRITICAL or HIGH findings detected |

### GitHub Actions Example

```yaml
name: Security Scan
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM
  workflow_dispatch:

jobs:
  cspm:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/CSPMScannerRole
          aws-region: us-east-1
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e .
      - run: aws-cspm --output report.json --html report.html
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: cspm-report
          path: |
            report.json
            report.html
```

---

## 🐳 Docker

Build and run with Docker:

```bash
# Build
docker build -t aws-cspm:latest .

# Run
docker run --rm -v ~/.aws:/root/.aws aws-cspm --region us-east-1

# With role assumption
docker run --rm -v ~/.aws:/root/.aws aws-cspm \
  --role-arn arn:aws:iam::123456789012:role/ScannerRole
```

---

## 📸 Screenshots

*Console output and HTML report examples would be shown here in a real README.*

---

## 🛡️ Security Considerations

- **Read-Only**: The scanner only reads configuration; it never modifies resources.
- **Least Privilege**: Use the provided IAM policy; do not attach `AdministratorAccess`.
- **Sensitive Data**: Reports may contain resource names and ARNs. Store securely.
- **Rate Limiting**: The scanner respects AWS API rate limits via boto3's built-in retry logic.

---

## 📝 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📬 Contact

Built by [Your Name](https://github.com/yourusername) — cloud security engineer and Python enthusiast.

> *"Security is not a product, but a process."* — Bruce Schneier
