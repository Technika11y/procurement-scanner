# Procurement Compliance Scanner

> Scans a vendor intake record — accessibility, security, SBOM licenses, data handling — against a
> municipal procurement baseline and returns a **GO / NO-GO** with per-requirement detail.
>
> Part of the **Technika11y** suite · *Root access for everyone.*

![status](https://img.shields.io/badge/status-pre--alpha-orange)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![python](https://img.shields.io/badge/python-3.10%2B-informational)

---

## Quick start

```bash
git clone https://github.com/technika11y/procurement-scanner && cd procurement-scanner
PYTHONPATH=src python3 -m procurement.cli examples/vendor.json --as-of 2026-07-06
```

## Status — read this first

**Pre-alpha (`v0.1.0a0`). Honest state of the code:**

| Capability | State |
|---|---|
| Accessibility: VPAT/ACR present, WCAG AA claimed | ✅ works, tested |
| Security: MFA, encryption at rest, pen-test recency (dated) | ✅ works, tested |
| SBOM: flag disallowed licenses (fail) / unknown licenses (warn) | ✅ works, tested |
| Data: PII hosting location check | ✅ works |
| GO / NO-GO verdict (any `fail` ⇒ NO-GO) | ✅ works, tested |
| Configurable baselines, EN 301 549, CVE/SBOM vuln lookup, sector rules | ⚠️ not built — [roadmap](#roadmap) |

The baseline is a **fixed representative** set of requirements, not a configurable policy engine,
and it is **decision support, not sign-off** — a human still owns the award.

## Why it exists

Municipal IT vets vendors by hand against a checklist that lives in someone's head. This turns that
checklist into a repeatable, dated GO/NO-GO: does the vendor have a VPAT, MFA, encryption, a recent
pen-test, and a clean SBOM — and if not, exactly which requirement failed.

## Usage

```bash
PYTHONPATH=src python -m procurement.cli examples/vendor.json --as-of 2026-07-06
```

```
PASS acr-vpat-present     VPAT/ACR provided
PASS wcag-aa              WCAG AA
PASS mfa                  MFA supported
...
VERDICT: GO  (Acme Permits Portal)
```

## Roadmap

- [ ] Configurable baselines (YAML policy) + EN 301 549
- [ ] SBOM → CVE/vulnerability lookup
- [ ] Sector overlays (CJIS, HIPAA, PCI)
- [ ] Ingest a real VPAT from the `vpat-generator`
- [ ] SARIF output + the shared Technika11y CI gate

## License

[Apache-2.0](LICENSE). See [`SECURITY.md`](SECURITY.md).

---

**Part of the [Technika11y](https://github.com/technika11y) suite** · [technika11y.github.io](https://technika11y.github.io/) · security, compliance, and accessibility as one discipline.
