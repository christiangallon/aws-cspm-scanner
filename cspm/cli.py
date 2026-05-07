"""Command-line interface for AWS CSPM scanner."""

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
import click
from botocore.exceptions import ClientError, NoCredentialsError
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from cspm.models import Finding
from cspm.reporter import Reporter
from cspm.scanners import CloudTrailScanner, EC2Scanner, IAMScanner, S3Scanner
from cspm.utils.aws_session import get_session

console = Console()

SCANNER_MAP = {
    "s3": S3Scanner,
    "iam": IAMScanner,
    "ec2": EC2Scanner,
    "cloudtrail": CloudTrailScanner,
}

DEFAULT_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
    "ap-northeast-1",
]


def get_account_id(session: boto3.Session) -> str:
    """Get the AWS account ID."""
    try:
        sts = session.client("sts")
        account: str = sts.get_caller_identity()["Account"]
        return account
    except Exception:
        return "unknown"


def get_enabled_regions(session: boto3.Session) -> list[str]:
    """Get list of enabled regions for the account."""
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        regions = ec2.describe_regions(AllRegions=False)["Regions"]
        return [r["RegionName"] for r in regions]
    except Exception:
        return ["us-east-1"]


def run_scanner(scanner_cls: type, session: boto3.Session, region: str) -> list[Finding]:
    """Run a single scanner in a region."""
    try:
        scanner = scanner_cls(session, region)
        findings: list[Finding] = scanner.scan()
        return findings
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in (
            "UnauthorizedOperation",
            "AccessDenied",
            "AccessDeniedException",
        ):
            console.print(f"[yellow]⚠ {scanner_cls.__name__} in {region}: Access denied[/yellow]")
        else:
            console.print(f"[red]✗ {scanner_cls.__name__} in {region}: {error_code}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]✗ {scanner_cls.__name__} in {region}: {str(e)}[/red]")
        return []


@click.command()
@click.option(
    "--profile",
    help="AWS profile to use",
    default=None,
)
@click.option(
    "--role-arn",
    help="Assume role for cross-account scanning",
    default=None,
)
@click.option(
    "--region",
    help="AWS region (default: all enabled regions)",
    default=None,
)
@click.option(
    "--services",
    help="Comma-separated services to scan (s3,iam,ec2,cloudtrail)",
    default="s3,iam,ec2,cloudtrail",
)
@click.option(
    "--output",
    "-o",
    help="Output JSON file path",
    default=None,
)
@click.option(
    "--html",
    "html_output",
    help="Output HTML file path",
    default=None,
)
@click.option(
    "--severity",
    help="Minimum severity to report (CRITICAL,HIGH,MEDIUM,LOW,INFO)",
    default="INFO",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
)
@click.option(
    "--workers",
    help="Number of parallel scanner workers",
    default=8,
    type=int,
)
@click.option(
    "--quiet",
    is_flag=True,
    help="Suppress console output",
)
def main(
    profile: str | None,
    role_arn: str | None,
    region: str | None,
    services: str,
    output: str | None,
    html_output: str | None,
    severity: str,
    workers: int,
    quiet: bool,
) -> None:
    """AWS Cloud Security Posture Management (CSPM) Scanner.

    Scans AWS services for security misconfigurations and generates
    a detailed report with severity levels and remediation steps.
    """
    if quiet:
        console.quiet = True

    # Validate AWS credentials
    try:
        session = get_session(profile=profile, role_arn=role_arn)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        console.print(f"[green]✓ Authenticated as {identity['Arn']}[/green]")
    except NoCredentialsError:
        console.print(
            "[red]✗ AWS credentials not found. Configure with:[/red]\n"
            "  aws configure\n"
            "  or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
        )
        sys.exit(1)
    except ClientError as e:
        console.print(f"[red]✗ AWS authentication failed: {e}[/red]")
        sys.exit(1)

    # Determine regions
    if region:
        regions = [region]
    else:
        regions = get_enabled_regions(session)
        console.print(f"[blue]ℹ Scanning {len(regions)} enabled regions[/blue]")

    # Determine services
    service_names = [s.strip().lower() for s in services.split(",")]
    scanner_classes = []
    for name in service_names:
        if name in SCANNER_MAP:
            scanner_classes.append(SCANNER_MAP[name])
        else:
            console.print(f"[yellow]⚠ Unknown service: {name}[/yellow]")

    if not scanner_classes:
        console.print("[red]✗ No valid services to scan[/red]")
        sys.exit(1)

    # Run scans
    start_time = time.time()
    all_findings: list[Finding] = []

    # IAM and S3 are global - only scan once
    regional_scanners = []
    global_scanners = []
    for sc in scanner_classes:
        if sc in (IAMScanner,):
            global_scanners.append((sc, "us-east-1"))
        else:
            regional_scanners.append(sc)

    tasks = list(global_scanners)
    for sc in regional_scanners:
        for r in regions:
            tasks.append((sc, r))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(tasks))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(run_scanner, sc, session, r): (sc.__name__, r) for sc, r in tasks
            }

            for future in as_completed(futures):
                scanner_name, reg = futures[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                    progress.update(
                        task,
                        advance=1,
                        description=f"Scanning... {scanner_name} in {reg} ({len(findings)} findings)",
                    )
                except Exception as e:
                    progress.update(
                        task, advance=1, description=f"Scanning... {scanner_name} in {reg} (error)"
                    )
                    console.print(f"[red]✗ {scanner_name} in {reg}: {str(e)}[/red]")

    scan_duration = time.time() - start_time

    # Filter by severity
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_rank = severity_rank[severity]
    filtered_findings = [f for f in all_findings if severity_rank[f.severity.value] <= min_rank]

    # Generate report
    reporter = Reporter(account_id=account_id)
    report = reporter.generate_report(filtered_findings)
    report.summary.scan_duration_seconds = round(scan_duration, 2)

    # Console output
    if not quiet:
        reporter.print_console(report)

    # JSON output
    if output:
        reporter.write_json_file(report, output)
        console.print(f"[green]✓ JSON report written to {output}[/green]")

    # HTML output
    if html_output:
        reporter.write_html_file(report, html_output)
        console.print(f"[green]✓ HTML report written to {html_output}[/green]")

    # Print risk score summary
    if not quiet:
        console.print(f"\n[bold]Risk Score: {report.risk_score}/100[/bold]")
        if report.risk_score >= 80:
            console.print("[red]🔴 Critical risk level — immediate action required[/red]")
        elif report.risk_score >= 50:
            console.print("[yellow]🟠 High risk level — significant issues found[/yellow]")
        elif report.risk_score >= 20:
            console.print("[yellow]🟡 Medium risk level — review recommended[/yellow]")
        else:
            console.print("[green]🟢 Low risk level — posture looks good[/green]")

    # Exit with error code if critical/high findings exist
    if report.summary.critical > 0 or report.summary.high > 0:
        sys.exit(2)
    elif report.summary.medium > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
