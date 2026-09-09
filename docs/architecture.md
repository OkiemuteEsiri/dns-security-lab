# Architecture

## Objective

This project demonstrates a defensive DNS security assessment pipeline that evaluates exported or synthetic DNS configuration data without performing intrusive scanning or interacting with live production infrastructure.

## Components

```text
Synthetic / exported DNS inventory
            |
            v
      src/models.py
  schema + validation
            |
            v
    src/assessment.py
 deterministic controls
            |
            +----> severity + ATT&CK context
            |
            v
    src/reporting.py
 posture metrics + evidence
            |
            v
      Markdown report
            ^
            |
       src/cli.py
```

## Design principles

- **Deterministic:** identical input produces identical findings and ordering.
- **Fail closed on malformed inventory:** missing required fields, unsupported policy values, duplicate zone names, and invalid counters are rejected.
- **Evidence preserving:** each finding records the specific inventory condition that caused the control failure.
- **Defensive only:** the toolkit does not send DNS queries, attempt zone transfers, enumerate real infrastructure, or modify DNS records.
- **Provider neutral:** the core model represents security-relevant properties independent of a specific DNS vendor.
- **Revalidation oriented:** remediation guidance includes a concrete control condition that can be reassessed after change implementation.

## Data flow

1. JSON inventory is parsed into immutable `DNSZone` objects.
2. Schema and relationship checks validate the assessment input.
3. Each zone is evaluated against explicit defensive controls.
4. Findings are sorted by severity and stable identifiers.
5. A bounded posture score is calculated for portfolio-level communication.
6. Markdown reporting renders evidence, remediation, ATT&CK context, and a validation workflow.

## Security boundaries

The project intentionally excludes:

- live recursive-resolution testing;
- unauthorized AXFR/IXFR attempts;
- DNS cache poisoning or spoofing techniques;
- credential collection;
- production DNS modification;
- real customer, employer, or client domain information.

Those boundaries keep the repository suitable for demonstrating security-engineering reasoning while avoiding operational targeting.
