"""Base scanner interface."""

from abc import ABC, abstractmethod
from typing import Any

from cspm.models import Finding


class BaseScanner(ABC):
    """Abstract base class for all AWS service scanners."""

    def __init__(self, session: Any, region: str = "us-east-1") -> None:
        """Initialize scanner with boto3 session.

        Args:
            session: boto3 Session object.
            region: AWS region to scan.
        """
        self.session = session
        self.region = region
        self.client = session.client(self.service_name, region_name=region)

    @property
    @abstractmethod
    def service_name(self) -> str:
        """AWS service name (e.g., 's3', 'iam', 'ec2')."""
        ...

    @abstractmethod
    def scan(self) -> list[Finding]:
        """Run the security scan and return findings.

        Returns:
            List of security findings.
        """
        ...
