from __future__ import annotations

from dataclasses import dataclass
from typing import Any


VALID_SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class DNSZone:
    name: str
    authoritative_servers: tuple[str, ...]
    dnssec_enabled: bool
    transfer_restricted: bool
    recursion_exposed: bool
    dmarc_policy: str
    spf_present: bool
    caa_present: bool
    stale_records: int
    public_admin_records: int
    provider: str = "synthetic"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DNSZone":
        required = {
            "name",
            "authoritative_servers",
            "dnssec_enabled",
            "transfer_restricted",
            "recursion_exposed",
            "dmarc_policy",
            "spf_present",
            "caa_present",
            "stale_records",
            "public_admin_records",
        }
        missing = sorted(required - raw.keys())
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")

        name = str(raw["name"]).strip().lower()
        if not name or "." not in name:
            raise ValueError("zone name must be a valid-looking DNS name")

        servers = tuple(str(v).strip().lower() for v in raw["authoritative_servers"])
        if len(servers) < 2:
            raise ValueError("at least two authoritative servers are required")

        stale = int(raw["stale_records"])
        admin = int(raw["public_admin_records"])
        if stale < 0 or admin < 0:
            raise ValueError("record counters cannot be negative")

        dmarc = str(raw["dmarc_policy"]).strip().lower()
        if dmarc not in {"none", "quarantine", "reject", "missing"}:
            raise ValueError("unsupported DMARC policy")

        return cls(
            name=name,
            authoritative_servers=servers,
            dnssec_enabled=bool(raw["dnssec_enabled"]),
            transfer_restricted=bool(raw["transfer_restricted"]),
            recursion_exposed=bool(raw["recursion_exposed"]),
            dmarc_policy=dmarc,
            spf_present=bool(raw["spf_present"]),
            caa_present=bool(raw["caa_present"]),
            stale_records=stale,
            public_admin_records=admin,
            provider=str(raw.get("provider", "synthetic")),
        )


@dataclass(frozen=True)
class Finding:
    control_id: str
    zone: str
    title: str
    severity: str
    evidence: str
    remediation: str
    mitre_attack: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity}")
