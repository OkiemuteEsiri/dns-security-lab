import json
import tempfile
import unittest
from pathlib import Path

from src.assessment import assess_inventory, assess_zone, load_inventory, posture_score
from src.models import DNSZone


class DNSAssessmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secure = DNSZone.from_dict({
            "name": "secure.example.test",
            "authoritative_servers": ["ns1.test", "ns2.test"],
            "dnssec_enabled": True,
            "transfer_restricted": True,
            "recursion_exposed": False,
            "dmarc_policy": "reject",
            "spf_present": True,
            "caa_present": True,
            "stale_records": 0,
            "public_admin_records": 0,
        })

    def test_secure_zone_has_no_findings(self) -> None:
        self.assertEqual(assess_zone(self.secure), [])

    def test_public_recursion_is_critical(self) -> None:
        risky = DNSZone.from_dict({**self.secure.__dict__, "recursion_exposed": True})
        findings = assess_zone(risky)
        self.assertTrue(any(f.control_id == "DNS-003" and f.severity == "critical" for f in findings))

    def test_missing_dnssec_is_high(self) -> None:
        risky = DNSZone.from_dict({**self.secure.__dict__, "dnssec_enabled": False})
        findings = assess_zone(risky)
        self.assertTrue(any(f.control_id == "DNS-001" and f.severity == "high" for f in findings))

    def test_stale_record_threshold_changes_severity(self) -> None:
        medium = DNSZone.from_dict({**self.secure.__dict__, "stale_records": 1})
        high = DNSZone.from_dict({**self.secure.__dict__, "stale_records": 5})
        self.assertEqual(next(f for f in assess_zone(medium) if f.control_id == "DNS-007").severity, "medium")
        self.assertEqual(next(f for f in assess_zone(high) if f.control_id == "DNS-007").severity, "high")

    def test_duplicate_zone_inventory_fails_closed(self) -> None:
        payload = [{
            "name": "dup.example.test",
            "authoritative_servers": ["ns1.test", "ns2.test"],
            "dnssec_enabled": True,
            "transfer_restricted": True,
            "recursion_exposed": False,
            "dmarc_policy": "reject",
            "spf_present": True,
            "caa_present": True,
            "stale_records": 0,
            "public_admin_records": 0,
        }] * 2
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate zones"):
                load_inventory(path)

    def test_invalid_dmarc_policy_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported DMARC"):
            DNSZone.from_dict({**self.secure.__dict__, "dmarc_policy": "invalid"})

    def test_posture_score_drops_with_findings(self) -> None:
        risky = DNSZone.from_dict({**self.secure.__dict__, "dnssec_enabled": False, "recursion_exposed": True})
        findings = assess_inventory([risky])
        self.assertLess(posture_score(findings, 1), 100)


if __name__ == "__main__":
    unittest.main()
