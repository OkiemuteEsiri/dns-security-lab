# Assessment Methodology

## Control objectives

The assessment focuses on common DNS and domain-control weaknesses that can increase attack surface, information disclosure, email abuse risk, certificate-governance risk, or resilience concerns.

| Control | Condition | Default severity | Validation intent |
|---|---|---:|---|
| DNS-001 | DNSSEC disabled | High | Confirm a valid chain of trust after enablement |
| DNS-002 | Zone transfer unrestricted | High | Confirm unauthorized AXFR/IXFR is refused |
| DNS-003 | Public recursion exposed | Critical | Confirm recursion is unavailable to unapproved networks |
| DNS-004 | DMARC missing / non-enforcing | High / Medium | Confirm published policy and mail alignment |
| DNS-005 | SPF absent | Medium | Confirm authorized-sender policy exists and is valid |
| DNS-006 | CAA absent | Low | Confirm approved CA issuance paths are constrained |
| DNS-007 | Stale records | Medium / High | Confirm orphaned records are removed and ownership reconciled |
| DNS-008 | Public administrative naming | Medium | Confirm unnecessary management naming is no longer public |

## Risk classification

Severity represents defensive remediation urgency for the modeled condition, not proof of exploitation. A critical rating indicates a configuration pattern with potentially significant abuse or amplification impact if exposed as represented by the input.

The portfolio posture score is deliberately simple and explainable. It uses fixed severity weights and a bounded per-zone penalty. It is useful for prioritization demonstrations but is not a substitute for business-specific quantitative risk analysis.

## MITRE ATT&CK mappings

Mappings are contextual rather than evidentiary:

- **T1590.002 – Gather Victim Network Information: DNS**: public DNS information and transfer exposure can support reconnaissance.
- **T1584.001 – Compromise Infrastructure: Domains**: domain/DNS control weaknesses can be relevant to infrastructure abuse scenarios.
- **T1566 – Phishing**: weak email-authentication controls can increase spoofing and phishing exposure.
- **T1583.001 – Acquire Infrastructure: Domains**: DNS/domain infrastructure is relevant context for adversary-controlled infrastructure, although exposed recursion alone does not demonstrate this technique occurred.

## Remediation lifecycle

1. **Triage** – validate ownership, business purpose, and whether the inventory accurately represents the zone.
2. **Prioritize** – address public recursion and transfer exposure before hygiene-only issues where business context is otherwise equal.
3. **Change** – implement through approved DNS, registrar, mail, or certificate-management processes.
4. **Validate** – regenerate the inventory and re-run controls; supplement with authorized external validation where appropriate.
5. **Close or accept** – retain evidence of successful validation, or record compensating controls and formally accepted residual risk.

## Limitations

- Input is configuration metadata, not packet capture or authoritative live-state proof.
- DNSSEC presence alone does not prove correct key rotation or registrar hygiene.
- SPF/DMARC checks model policy presence and enforcement state rather than full mail-flow correctness.
- CAA absence is treated as governance hygiene, not an exploitable vulnerability by itself.
- Stale-record detection depends on upstream ownership and lifecycle data quality.
