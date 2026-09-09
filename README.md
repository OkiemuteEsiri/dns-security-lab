# DNS Security Assessment & Hardening Lab

A defensive security-engineering project for assessing DNS and domain-control posture from structured inventory data. The lab demonstrates how DNS security findings can be normalized, risk-classified, mapped to relevant adversary context, remediated, and revalidated without performing intrusive scans or targeting live infrastructure.

## Problem Statement

DNS is both a critical dependency and a high-value control plane. Weak resolver exposure, permissive zone transfers, missing DNSSEC, stale records, weak email-authentication policy, and poor certificate-authority governance can materially increase attack surface or make reconnaissance and abuse easier.

This project converts those concerns into a deterministic assessment workflow suitable for security engineering, vulnerability management, and infrastructure risk reviews.

## What This Project Demonstrates

- defensive DNS security control design;
- normalized configuration and inventory modeling;
- input validation and duplicate detection;
- deterministic finding generation;
- severity-based prioritization;
- evidence-preserving reporting;
- remediation and revalidation workflow design;
- MITRE ATT&CK contextual mapping;
- Python unit testing;
- CI-based source compilation, unit testing, and smoke assessment;
- risk communication for both engineering and security stakeholders.

## Architecture

```text
+-------------------------------+
| DNS inventory / config export |
| (synthetic in this repo)      |
+---------------+---------------+
                |
                v
+---------------+---------------+
| src/models.py                 |
| Schema + fail-closed checks   |
+---------------+---------------+
                |
                v
+---------------+---------------+
| src/assessment.py             |
| Deterministic control engine  |
+---------------+---------------+
                |
        +-------+--------+
        |                |
        v                v
 severity/evidence   ATT&CK context
        |                |
        +-------+--------+
                |
                v
+---------------+---------------+
| src/reporting.py              |
| Metrics + Markdown findings   |
+---------------+---------------+
                |
                v
+---------------+---------------+
| Remediation / revalidation    |
+-------------------------------+
```

See [`docs/architecture.md`](docs/architecture.md) for the detailed component and trust-boundary view.

## Defensive Controls

| ID | Control | Risk classification |
|---|---|---:|
| DNS-001 | DNSSEC disabled | High |
| DNS-002 | Zone transfer not restricted | High |
| DNS-003 | Recursive DNS exposed | Critical |
| DNS-004 | DMARC missing or non-enforcing | High / Medium |
| DNS-005 | SPF missing | Medium |
| DNS-006 | CAA absent | Low |
| DNS-007 | Stale DNS records | Medium / High |
| DNS-008 | Public administrative naming | Medium |

Severity represents remediation urgency for the modeled configuration condition. It does **not** claim exploitation or compromise.

## Repository Structure

```text
.
├── .github/workflows/ci.yml
├── data/
│   └── synthetic_dns_inventory.json
├── docs/
│   ├── architecture.md
│   └── methodology.md
├── reports/
│   └── example-assessment.md
├── src/
│   ├── __init__.py
│   ├── assessment.py
│   ├── cli.py
│   ├── models.py
│   └── reporting.py
└── tests/
    └── test_assessment.py
```

## Usage

Requirements: Python 3.11+; no third-party packages are required.

Run the tests:

```bash
python -m unittest discover -s tests -v
```

Generate a report from the included synthetic inventory:

```bash
python -m src.cli data/synthetic_dns_inventory.json --output reports/generated-assessment.md
```

The CLI validates the inventory, evaluates each zone, calculates a bounded portfolio posture score, and renders findings with evidence, severity, remediation, and ATT&CK context.

## Synthetic Dataset

`data/synthetic_dns_inventory.json` contains three fictional `.test` zones designed to exercise the implemented controls:

- a retail-style zone with missing DNSSEC, monitoring-only DMARC, stale records, and no CAA policy;
- a self-hosted manufacturing-style zone with exposed recursion, unrestricted transfer, weak mail controls, and stale records;
- a hardened reference zone that should generate no findings.

The dataset is intentionally synthetic and contains no employer, client, production, or personally identifiable data.

## Example Output

The committed [`reports/example-assessment.md`](reports/example-assessment.md) shows how the same findings can be communicated as:

- portfolio-level metrics;
- prioritized remediation actions;
- evidence-backed control failures;
- explicit technical closure criteria.

For the provided synthetic dataset, the example report contains 11 findings, including one critical recursive-DNS exposure. That result is demonstration data only and does not describe a real environment.

## MITRE ATT&CK Context

Relevant contextual mappings include:

- **T1590.002 — Gather Victim Network Information: DNS**
- **T1584.001 — Compromise Infrastructure: Domains**
- **T1566 — Phishing**
- **T1583.001 — Acquire Infrastructure: Domains**

ATT&CK mappings are used to explain why a control may matter in an adversary lifecycle. A mapping is not evidence that a technique occurred.

## Remediation & Validation Workflow

1. Validate zone ownership and confirm the source inventory is current.
2. Prioritize public recursion, transfer exposure, and high-impact domain-control issues.
3. Implement changes through approved DNS, registrar, certificate, or mail-administration workflows.
4. Allow for required propagation and operational verification.
5. Regenerate the source inventory.
6. Re-run the assessment and confirm the control no longer triggers.
7. Where behavior is externally observable, retain results from an explicitly authorized validation source.
8. Document residual risk and compensating controls for accepted exceptions.

Detailed control intent and validation guidance are in [`docs/methodology.md`](docs/methodology.md).

## CI/CD Security Checks

The GitHub Actions workflow uses read-only repository permissions and performs:

- Python source/test compilation;
- unit-test discovery and execution;
- a synthetic report-generation smoke test;
- output verification that the report was produced and contains the expected report heading.

The workflow intentionally does not use repository secrets, cloud credentials, live DNS targets, or production integrations.

## Design Decisions

### Deterministic controls

Control logic is explicit rather than opaque. A reviewer can trace each finding to a specific inventory attribute and understand why its severity was assigned.

### Fail-closed inventory handling

Malformed input, unsupported DMARC policy values, duplicate zone names, negative counters, and insufficient authoritative-server data are rejected before assessment.

### Evidence before inference

The engine reports configuration evidence, not attacker intent. For example, `recursion_exposed=true` is treated as a control failure; it is not described as proof of DNS abuse.

### Revalidation as part of remediation

A security finding is not considered closed merely because a change ticket exists. The methodology requires updated evidence and a repeat assessment.

## Limitations

- The project evaluates structured metadata, not live packet or DNS-query telemetry.
- DNSSEC presence does not prove correct key lifecycle management or registrar security.
- SPF and DMARC checks model policy posture rather than complete mail-flow validation.
- CAA absence is treated as a governance weakness rather than an exploit by itself.
- Stale-record accuracy depends on upstream lifecycle and ownership data.
- The posture score is an explainable prioritization aid, not a quantitative loss model.
- No live transfer attempts, recursion testing, cache poisoning, spoofing, or production record changes are performed.

## Skills Demonstrated

**Network Security:** DNS architecture, authoritative/recursive separation, transfer restrictions, DNSSEC, record hygiene.

**Security Engineering:** control design, schema validation, deterministic analytics, evidence handling, defensive automation.

**Vulnerability & Exposure Management:** severity classification, prioritization, remediation ownership, validation and closure criteria.

**Detection / Threat Context:** ATT&CK-informed reasoning without overstating evidence.

**Software Engineering:** modular Python, immutable domain models, unit tests, CLI design, Markdown reporting, CI.

**Risk Communication:** engineering-focused evidence and remediation plus portfolio-level posture metrics.

## Roadmap

- add configurable policy thresholds through a versioned YAML policy file;
- model delegated subdomains and registrar-lock posture;
- add provider-adapter examples for safely normalized DNS exports;
- add historical assessment comparison and remediation ageing;
- add structured JSON/SARIF output for pipeline integration;
- extend tests for malformed inventory and report rendering;
- add optional authorized validation interfaces while keeping active testing disabled by default.

## Ethical & Safety Scope

This repository is designed for defensive learning and portfolio demonstration. It contains no real credentials, confidential employer/client information, unsafe offensive payloads, exploit automation, or production targeting. Any future integration with real infrastructure should require explicit authorization and least-privilege read-only access wherever possible.

## License

Use the repository for defensive security education, lab work, and portfolio demonstration subject to the repository license and applicable authorization requirements.
