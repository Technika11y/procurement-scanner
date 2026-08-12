"""Evaluate a vendor intake record against a municipal procurement baseline and return a
GO / NO-GO with per-requirement detail.

Pure functions — dates are supplied (`as_of`), never read from the clock — so results are
deterministic and unit-testable. This structures the review; it does not replace human sign-off.
"""
from datetime import date

# Licenses disallowed for typical proprietary/redistribution procurement contexts.
DISALLOWED_LICENSES = {"AGPL-3.0", "GPL-3.0", "GPL-2.0"}


def _r(requirement, status, detail):
    # status: "pass" | "fail" | "warn"
    return {"requirement": requirement, "status": status, "detail": detail}


def _days_between(a, b):
    ay, am, ad = (int(x) for x in a.split("-"))
    by, bm, bd = (int(x) for x in b.split("-"))
    return (date(ay, am, ad) - date(by, bm, bd)).days


def scan(vendor, as_of=None, pentest_max_age_days=365):
    a = vendor.get("accessibility", {})
    s = vendor.get("security", {})
    data = vendor.get("data", {})
    sbom = vendor.get("sbom", [])
    results = []

    # Accessibility (Section 508 / WCAG)
    results.append(_r("acr-vpat-present", "pass" if a.get("vpat") else "fail",
        "VPAT/ACR provided" if a.get("vpat") else "no VPAT/ACR — Section 508 needs a conformance claim"))
    lvl = a.get("wcag_level")
    results.append(_r("wcag-aa", "pass" if lvl in ("AA", "AAA") else "fail",
        f"WCAG {lvl}" if lvl else "no WCAG level claimed"))
    # A VPAT older than ~2 years likely predates WCAG 2.2 — request a current ACR.
    vpat_date = a.get("vpat_date")
    if a.get("vpat") and vpat_date and as_of and _days_between(as_of, vpat_date) > 730:
        results.append(_r("vpat-freshness", "warn",
            f"VPAT dated {vpat_date} is over 2 years old — request a current ACR against WCAG 2.2"))

    # Security baseline
    results.append(_r("mfa", "pass" if s.get("mfa") else "fail",
        "MFA supported" if s.get("mfa") else "no MFA"))
    results.append(_r("encryption-at-rest", "pass" if s.get("encryption_at_rest") else "fail",
        "encryption at rest" if s.get("encryption_at_rest") else "no encryption at rest"))

    pentest = s.get("pen_test_date")
    if not pentest:
        results.append(_r("recent-pentest", "fail", "no pen-test date on file"))
    elif as_of:
        age = _days_between(as_of, pentest)
        ok = 0 <= age <= pentest_max_age_days
        results.append(_r("recent-pentest", "pass" if ok else "fail",
            f"pen-test {age}d ago" + ("" if ok else f" (limit {pentest_max_age_days}d)")))
    else:
        results.append(_r("recent-pentest", "warn", "pen-test date present but no as_of date to age it"))

    # SBOM license hygiene
    bad = [c for c in sbom if c.get("license") in DISALLOWED_LICENSES]
    unknown = [c for c in sbom if not c.get("license")]
    if bad:
        results.append(_r("sbom-licenses", "fail",
            "disallowed: " + ", ".join(f"{c.get('package','?')}({c.get('license')})" for c in bad)))
    elif unknown:
        results.append(_r("sbom-licenses", "warn",
            "unknown license: " + ", ".join(c.get("package", "?") for c in unknown)))
    else:
        results.append(_r("sbom-licenses", "pass", "no disallowed or unknown licenses"))

    # Data handling
    if data.get("pii"):
        host = data.get("hosting", "?")
        results.append(_r("pii-hosting", "pass" if host == "us" else "warn", f"PII hosted in {host}"))
        # Handing PII to a processor without a Data Processing Agreement is a hard stop.
        results.append(_r("dpa", "pass" if data.get("dpa") else "fail",
            "Data Processing Agreement on file" if data.get("dpa")
            else "PII is processed with no Data Processing Agreement (DPA) on file"))

    return results


def verdict(results):
    return "NO-GO" if any(r["status"] == "fail" for r in results) else "GO"
