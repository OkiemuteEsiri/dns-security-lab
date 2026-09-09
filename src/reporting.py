from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from .assessment import posture_score
from .models import DNSZone, Finding


def build_markdown_report(zones: list[DNSZone], findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    score = posture_score(findings, len(zones))
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    lines = [
        "# DNS Security Assessment Report",
        "",
        f"Generated: {generated}",
        "",
        "## Executive Summary",
        "",
        f"- Zones assessed: **{len(zones)}**",
        f"- Total findings: **{len(findings)}**",
        f"- Critical: **{counts['critical']}**",
        f"- High: **{counts['high']}**",
        f"- Medium: **{counts['medium']}**",
        f"- Low: **{counts['low']}**",
        f"- Defensive posture score: **{score}/100**",
        "",
        "> This report is generated from synthetic inventory and demonstrates defensive assessment methodology. It is not evidence of a live environment compromise.",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append("No control failures were identified in the supplied inventory.")
    else:
        for index, finding in enumerate(findings, start=1):
            mappings = ", ".join(finding.mitre_attack) if finding.mitre_attack else "Not mapped"
            lines.extend([
                f"### {index}. {finding.title}",
                "",
                f"- Control: `{finding.control_id}`",
                f"- Zone: `{finding.zone}`",
                f"- Severity: **{finding.severity.upper()}**",
                f"- MITRE ATT&CK context: {mappings}",
                f"- Evidence: {finding.evidence}",
                f"- Remediation: {finding.remediation}",
                "",
            ])

    lines.extend([
        "## Validation Workflow",
        "",
        "1. Assign the finding to an accountable DNS/domain owner.",
        "2. Apply the approved configuration change in a controlled environment.",
        "3. Re-export or regenerate the inventory after change propagation.",
        "4. Re-run the assessment and confirm the relevant control no longer triggers.",
        "5. Preserve change evidence and document accepted residual risk where remediation is intentionally deferred.",
        "",
    ])
    return "\n".join(lines)
