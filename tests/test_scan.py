import unittest

from procurement.scan import scan, verdict


def vendor(**over):
    base = {
        "name": "Acme",
        "accessibility": {"vpat": True, "wcag_level": "AA"},
        "security": {"mfa": True, "encryption_at_rest": True, "pen_test_date": "2026-03-01"},
        "data": {"pii": True, "hosting": "us", "dpa": True},
        "sbom": [{"package": "react", "version": "18", "license": "MIT"}],
    }
    base.update(over)
    return base


def status_of(results, req):
    return next(r["status"] for r in results if r["requirement"] == req)


class ScanTests(unittest.TestCase):
    def test_clean_vendor_is_go(self):
        self.assertEqual(verdict(scan(vendor(), as_of="2026-07-06")), "GO")

    def test_missing_vpat_is_no_go(self):
        v = vendor(accessibility={"vpat": False, "wcag_level": "AA"})
        results = scan(v, as_of="2026-07-06")
        self.assertEqual(status_of(results, "acr-vpat-present"), "fail")
        self.assertEqual(verdict(results), "NO-GO")

    def test_no_mfa_is_no_go(self):
        v = vendor(security={"mfa": False, "encryption_at_rest": True, "pen_test_date": "2026-03-01"})
        self.assertEqual(verdict(scan(v, as_of="2026-07-06")), "NO-GO")

    def test_stale_pentest_fails(self):
        v = vendor(security={"mfa": True, "encryption_at_rest": True, "pen_test_date": "2024-01-01"})
        self.assertEqual(status_of(scan(v, as_of="2026-07-06"), "recent-pentest"), "fail")

    def test_recent_pentest_passes(self):
        self.assertEqual(status_of(scan(vendor(), as_of="2026-07-06"), "recent-pentest"), "pass")

    def test_disallowed_license_fails(self):
        v = vendor(sbom=[{"package": "x", "license": "AGPL-3.0"}])
        results = scan(v, as_of="2026-07-06")
        self.assertEqual(status_of(results, "sbom-licenses"), "fail")
        self.assertEqual(verdict(results), "NO-GO")

    def test_unknown_license_warns_not_fails(self):
        v = vendor(sbom=[{"package": "x"}])
        self.assertEqual(status_of(scan(v, as_of="2026-07-06"), "sbom-licenses"), "warn")

    def test_pii_without_dpa_is_no_go(self):
        v = vendor(data={"pii": True, "hosting": "us"})  # no dpa
        results = scan(v, as_of="2026-07-06")
        self.assertEqual(status_of(results, "dpa"), "fail")
        self.assertEqual(verdict(results), "NO-GO")

    def test_non_pii_vendor_has_no_dpa_requirement(self):
        v = vendor(data={"pii": False})
        reqs = [r["requirement"] for r in scan(v, as_of="2026-07-06")]
        self.assertNotIn("dpa", reqs)

    def test_stale_vpat_warns(self):
        v = vendor(accessibility={"vpat": True, "wcag_level": "AA", "vpat_date": "2022-01-01"})
        self.assertEqual(status_of(scan(v, as_of="2026-07-06"), "vpat-freshness"), "warn")

    def test_fresh_vpat_has_no_freshness_finding(self):
        v = vendor(accessibility={"vpat": True, "wcag_level": "AA", "vpat_date": "2026-01-01"})
        reqs = [r["requirement"] for r in scan(v, as_of="2026-07-06")]
        self.assertNotIn("vpat-freshness", reqs)


if __name__ == "__main__":
    unittest.main()
