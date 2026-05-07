"""Report generation and formatting."""

from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cspm.compliance import map_compliance
from cspm.models import Finding, Report, ReportSummary, Severity
from cspm.risk import calculate_risk_score, summarize_findings


class Reporter:
    """Generates and formats CSPM scan reports."""

    SEVERITY_ORDER = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]

    SEVERITY_COLORS = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "bright_red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    def __init__(self, account_id: str = "unknown") -> None:
        self.account_id = account_id
        self.console = Console()

    def generate_report(self, findings: list[Finding]) -> Report:
        """Generate a report from findings."""
        summary = ReportSummary(
            total_findings=len(findings),
            critical=sum(1 for f in findings if f.severity == Severity.CRITICAL),
            high=sum(1 for f in findings if f.severity == Severity.HIGH),
            medium=sum(1 for f in findings if f.severity == Severity.MEDIUM),
            low=sum(1 for f in findings if f.severity == Severity.LOW),
            info=sum(1 for f in findings if f.severity == Severity.INFO),
            services_scanned=sorted({f.service for f in findings}),
            account_id=self.account_id,
        )

        # Build compliance mappings
        compliance_mappings: dict[str, list[str]] = {}
        for finding in findings:
            mapping = map_compliance(finding)
            if mapping:
                compliance_mappings[finding.rule_id] = mapping

        report = Report(
            summary=summary,
            findings=findings,
            risk_score=calculate_risk_score(findings),
            risk_summary=summarize_findings(findings),
            compliance_mappings=compliance_mappings,
        )
        return report

    def to_json(self, report: Report, indent: int = 2) -> str:
        """Export report to JSON string."""
        return report.model_dump_json(indent=indent)

    def to_dict(self, report: Report) -> dict[str, Any]:
        """Export report to dictionary."""
        return report.model_dump(mode="json")

    def print_console(self, report: Report) -> None:
        """Print a formatted report to the console."""
        self._print_summary(report)
        self._print_findings(report.findings)

    def _print_summary(self, report: Report) -> None:
        """Print the summary section."""
        summary = report.summary

        # Severity breakdown table
        table = Table(title="CSPM Scan Summary", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        for sev in self.SEVERITY_ORDER:
            count = getattr(summary, sev.value.lower(), 0)
            color = self.SEVERITY_COLORS.get(sev, "white")
            table.add_row(f"[{color}]{sev.value}[/{color}]", str(count))

        table.add_row("─" * 10, "─" * 5, style="dim")
        table.add_row("[bold]Total[/bold]", str(summary.total_findings))

        # Info panel
        info_text = (
            f"Account: [cyan]{summary.account_id}[/cyan]\n"
            f"Risk Score: [cyan]{report.risk_score}/100[/cyan]\n"
            f"Services Scanned: [cyan]{', '.join(summary.services_scanned) or 'N/A'}[/cyan]\n"
            f"Scanned At: [cyan]{summary.scanned_at.isoformat()}[/cyan]"
        )

        self.console.print()
        self.console.print(Panel(info_text, title="Scan Details", border_style="blue"))
        self.console.print(table)
        self.console.print()

    def _print_findings(self, findings: list[Finding]) -> None:
        """Print detailed findings."""
        if not findings:
            self.console.print("[green]✓ No findings detected.[/green]")
            return

        # Sort by severity order
        severity_rank = {s: i for i, s in enumerate(self.SEVERITY_ORDER)}
        sorted_findings = sorted(findings, key=lambda f: severity_rank.get(f.severity, 99))

        for finding in sorted_findings:
            self._print_finding(finding)

    def _print_finding(self, finding: Finding) -> None:
        """Print a single finding."""
        color = self.SEVERITY_COLORS.get(finding.severity, "white")
        severity_tag = f"[{color} bold]{finding.severity.value}[/{color} bold]"

        title = f"{severity_tag} {finding.title}"

        # Compliance mapping
        compliance = map_compliance(finding)
        compliance_text = ""
        if compliance:
            compliance_text = f"\n[bold]Compliance:[/bold] {', '.join(compliance)}"

        content = (
            f"[bold]ID:[/bold] {finding.id}\n"
            f"[bold]Rule ID:[/bold] {finding.rule_id}\n"
            f"[bold]Service:[/bold] {finding.service}\n"
            f"[bold]Resource:[/bold] {finding.resource}\n"
            f"[bold]Region:[/bold] {finding.region}\n"
            f"[bold]Description:[/bold] {finding.description}\n"
            f"{compliance_text}"
        )

        if finding.remediation:
            content += f"\n[bold yellow]Remediation:[/bold yellow] {finding.remediation}"

        if finding.references:
            content += "\n\n[bold]References:[/bold]"
            for ref in finding.references:
                content += f"\n  • {ref}"

        border = "red" if finding.severity == Severity.CRITICAL else "yellow"
        self.console.print(Panel(content, title=title, border_style=border))
        self.console.print()

    def write_json_file(self, report: Report, path: str) -> None:
        """Write report to a JSON file."""
        with open(path, "w") as f:
            f.write(self.to_json(report))

    def write_html_file(self, report: Report, path: str) -> None:
        """Write report to an HTML file."""
        html = self._generate_html(report)
        with open(path, "w") as f:
            f.write(html)

    def _generate_html(self, report: Report) -> str:
        """Generate HTML report."""
        summary = report.summary
        severity_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
            "INFO": "#6b7280",
        }

        findings_html = ""
        for finding in report.findings:
            color = severity_colors.get(finding.severity.value, "#6b7280")
            refs = ""
            if finding.references:
                refs = (
                    "<h4>References</h4><ul>"
                    + "".join(f'<li><a href="{r}">{r}</a></li>' for r in finding.references)
                    + "</ul>"
                )

            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="severity" style="background: {color};">{finding.severity.value}</span>
                    <span class="title">{finding.title}</span>
                </div>
                <div class="finding-body">
                    <p><strong>ID:</strong> {finding.id}</p>
                    <p><strong>Rule ID:</strong> {finding.rule_id}</p>
                    <p><strong>Service:</strong> {finding.service}</p>
                    <p><strong>Resource:</strong> {finding.resource}</p>
                    <p><strong>Region:</strong> {finding.region}</p>
                    <p><strong>Description:</strong> {finding.description}</p>
                    <div class="remediation">
                        <strong>Remediation:</strong> {finding.remediation}
                    </div>
                    {refs}
                </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS CSPM Report - {summary.account_id}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #1f2937;
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ margin-bottom: 1rem; color: #111827; }}
        .summary {{
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}
        .summary-card {{
            text-align: center;
            padding: 1rem;
            border-radius: 6px;
            background: #f9fafb;
        }}
        .summary-card .count {{
            font-size: 2rem;
            font-weight: bold;
        }}
        .summary-card .label {{
            font-size: 0.875rem;
            color: #6b7280;
            text-transform: uppercase;
        }}
        .finding {{
            background: white;
            border-radius: 8px;
            margin-bottom: 1rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .finding-header {{
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #e5e7eb;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .severity {{
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .title {{ font-weight: 600; }}
        .finding-body {{ padding: 1.5rem; }}
        .finding-body p {{ margin-bottom: 0.5rem; }}
        .remediation {{
            background: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 6px;
            padding: 1rem;
            margin-top: 1rem;
        }}
        .meta {{
            color: #6b7280;
            font-size: 0.875rem;
            margin-top: 1rem;
        }}
        a {{ color: #2563eb; }}
        ul {{ margin-left: 1.5rem; margin-top: 0.5rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 AWS Cloud Security Posture Management Report</h1>
        <div class="summary">
            <p><strong>Account:</strong> {summary.account_id}</p>
            <p><strong>Risk Score:</strong> {report.risk_score}/100</p>
            <p><strong>Scanned At:</strong> {summary.scanned_at.isoformat()}</p>
            <p><strong>Services:</strong> {", ".join(summary.services_scanned) or "N/A"}</p>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="count" style="color: {severity_colors["CRITICAL"]}">{summary.critical}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-card">
                    <div class="count" style="color: {severity_colors["HIGH"]}">{summary.high}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-card">
                    <div class="count" style="color: {severity_colors["MEDIUM"]}">{summary.medium}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-card">
                    <div class="count" style="color: {severity_colors["LOW"]}">{summary.low}</div>
                    <div class="label">Low</div>
                </div>
                <div class="summary-card">
                    <div class="count" style="color: {severity_colors["INFO"]}">{summary.info}</div>
                    <div class="label">Info</div>
                </div>
                <div class="summary-card">
                    <div class="count" style="color: #111827">{summary.total_findings}</div>
                    <div class="label">Total</div>
                </div>
            </div>
        </div>
        {findings_html if findings_html else '<p style="text-align:center;color:#059669;font-size:1.25rem;">✓ No findings detected</p>'}
        <div class="meta">
            <p>Generated by AWS CSPM Scanner v1.0.0</p>
        </div>
    </div>
</body>
</html>"""
