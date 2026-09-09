from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .models import DNSZone, Finding


SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 7, "critical": 10}


def load_inventory(path: str | Path) -> list[DNSZone]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("inventory root must be a JSON list")

    zones = [DNSZone.from_dict(item) for item in data]
    names = [zone.name for zone in zones]
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        raise ValueError(f"duplicate zones: {', '.join(duplicates)}")
    return zones


def assess_zone(zone: DNSZone) -> list[Finding]:
    findings: list[Finding] = []

    if not zone.dnssec_enabled:
        findings.append(Finding(
            "DNS-001", zone.name, "DNSSEC is not enabled", "high",
            "The synthetic inventory records dnssec_enabled=false.",
            "Enable DNSSEC, publish DS records through the registrar, and validate the chain of trust before closing the finding.",
            ("T1584.001",),
        ))

    if not zone.transfer_restricted:
        findings.append(Finding(
            "DNS-002", zone.name, "Zone transfer controls are not restricted", "high",
            "The synthetic inventory records transfer_restricted=false.",
            "Restrict AXFR/IXFR to approved secondary servers and verify unauthorized transfer attempts are refused.",
            ("T1590.002",),
        ))

    if zone.recursion_exposed:
        findings.append(Finding(
            "DNS-003", zone.name, "Recursive DNS service is exposed", "critical",
            "The synthetic inventory records recursion_exposed=true.",
            "Disable public recursion on authoritative infrastructure or constrain recursion to approved client networks; validate externally using a controlled test resolver.",
            ("T1583.001",),
        ))

    if zone.dmarc_policy in {"missing", "none"}:
        severity = "high" if zone.dmarc_policy == "missing" else "medium"
        findings.append(Finding(
            "DNS-004", zone.name, "DMARC enforcement is insufficient", severity,
            f"DMARC policy is recorded as {zone.dmarc_policy!r}.",
            "Publish DMARC and progress safely toward p=reject after monitoring legitimate mail sources and alignment.",
            ("T1566",),
        ))

    if not zone.spf_present:
        findings.append(Finding(
            "DNS-005", zone.name, "SPF record is missing", "medium",
            "The synthetic inventory records spf_present=false.",
            "Publish a narrowly scoped SPF record for authorized senders and validate DNS lookup count and alignment.",
            ("T1566",),
        ))

    if not zone.caa_present:
        findings.append(Finding(
            "DNS-006", zone.name, "CAA policy is absent", "low",
            "The synthetic inventory records caa_present=false.",
            "Publish CAA records for approved certificate authorities and confirm intended issuance paths remain functional.",
        ))

    if zone.stale_records > 0:
        severity = "high" if zone.stale_records >= 5 else "medium"
        findings.append(Finding(
            "DNS-007", zone.name, "Stale DNS records require review", severity,
            f"The synthetic inventory contains {zone.stale_records} stale record(s).",
            "Reconcile records against asset ownership, remove orphaned entries, and confirm removed names no longer resolve to unintended resources.",
            ("T1584.001",),
        ))

    if zone.public_admin_records > 0:
        findings.append(Finding(
            "DNS-008", zone.name, "Administrative naming is exposed in public DNS", "medium",
            f"The synthetic inventory records {zone.public_admin_records} public administrative hostname(s).",
            "Review whether administrative hostnames must be publicly resolvable, reduce unnecessary disclosure, and validate required management access through approved paths.",
            ("T1590.002",),
        ))

    return findings


def assess_inventory(zones: list[DNSZone]) -> list[Finding]:
    findings: list[Finding] = []
    for zone in zones:
        findings.extend(assess_zone(zone))
    return sorted(findings, key=lambda f: (-SEVERITY_WEIGHT[f.severity], f.zone, f.control_id))


def posture_score(findings: list[Finding], zone_count: int) -> int:
    if zone_count <= 0:
        return 100
    penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    maximum = zone_count * 25
    return max(0, round(100 * (1 - min(penalty, maximum) / maximum)))
