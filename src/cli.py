from __future__ import annotations

import argparse
from pathlib import Path

from .assessment import assess_inventory, load_inventory
from .reporting import build_markdown_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess synthetic DNS security posture")
    parser.add_argument("inventory", help="Path to JSON DNS inventory")
    parser.add_argument("--output", default="reports/generated-assessment.md", help="Markdown report output path")
    args = parser.parse_args()

    zones = load_inventory(args.inventory)
    findings = assess_inventory(zones)
    report = build_markdown_report(zones, findings)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"assessed={len(zones)} findings={len(findings)} report={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
