from collections import Counter

from cspm.models import SEVERITY_WEIGHTS


def calculate_risk_score(findings: list[dict]) -> int:
    total = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)

    if total == 0:
        return 0

    score = min(100, int((total / 50) * 100))
    return score


def summarize_findings(findings: list[dict]) -> dict[str, int]:
    counts = Counter(f.severity for f in findings)

    return {"total": len(findings), "by_severity": dict(counts)}
