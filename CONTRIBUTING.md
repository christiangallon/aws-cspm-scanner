# Contributing to AWS CSPM Scanner

Thank you for your interest in contributing! This document provides guidelines for getting started.

## Development Setup

```bash
git clone https://github.com/yourusername/aws-cspm.git
cd aws-cspm
pip install -e ".[dev]"
pre-commit install
```

## Code Style

- **Formatter**: ruff
- **Linter**: ruff
- **Type Checker**: mypy (strict mode)
- **Line Length**: 100 characters
- **Python Version**: 3.10+

## CI Pipeline

All pull requests must pass the full CI pipeline:

```bash
make ci    # Runs format check, tests with 70% coverage, and Docker build
```

Individual steps:

```bash
make test      # Run tests with coverage (fails if < 70%)
make format    # Check code formatting
make docker    # Build Docker image
```

## Adding a New Scanner

1. Create a new file in `cspm/scanners/`
2. Inherit from `BaseScanner`
3. Implement `service_name` property and `scan()` method
4. Add tests in `tests/`
5. Register in `cspm/scanners/__init__.py` and `cspm/cli.py`

Example:

```python
from cspm.models import Finding, Severity
from cspm.scanners.base import BaseScanner

class RDSScanner(BaseScanner):
    @property
    def service_name(self) -> str:
        return "rds"

    def scan(self) -> list[Finding]:
        findings = []
        # Your scanning logic here
        return findings
```

## Adding Risk Scoring

Risk scores are automatically calculated from severity weights defined in `cspm/models.py`:

```python
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
    "INFO": 1
}
```

To adjust scoring sensitivity, modify the denominator in `cspm/risk.py`:

```python
score = min(100, int((total / 50) * 100))  # 50 = normalization factor
```

## Adding Compliance Mappings

Add new framework mappings in `cspm/compliance.py`:

```python
COMPLIANCE_MAP = {
    "YOUR_RULE_ID": ["CIS X.Y", "SOC2 CCZ.Z"],
}
```

Ensure findings set the `rule_id` field for automatic mapping.

## Testing

All scanners must have comprehensive tests using `moto` mocks:

```python
from moto import mock_aws

@mock_aws
def test_rds_public_access() -> None:
    session = boto3.Session(region_name="us-east-1")
    # ... setup ...
    scanner = RDSScanner(session, "us-east-1")
    findings = scanner.scan()
    # ... assertions ...
```

## Pull Request Process

1. Ensure tests pass: `make ci`
2. Update README if adding features
3. Add tests for new functionality
4. Update version in `pyproject.toml` if applicable

## Reporting Issues

Please include:
- Python version
- AWS region
- Full error traceback
- Minimal reproduction steps
