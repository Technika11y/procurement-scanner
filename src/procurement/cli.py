"""procurement-scanner <vendor.json> [--as-of YYYY-MM-DD] — go/no-go against the baseline.

Exit 1 on NO-GO."""
import argparse
import json
import sys

from .scan import scan, verdict

_GLYPH = {"pass": "PASS", "fail": "FAIL", "warn": "WARN"}


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="procurement-scanner")
    parser.add_argument("vendor", help="vendor intake JSON")
    parser.add_argument("--as-of", dest="as_of", help="evaluation date YYYY-MM-DD (ages the pen-test)")
    args = parser.parse_args(argv)

    with open(args.vendor) as fh:
        vendor = json.load(fh)

    results = scan(vendor, as_of=args.as_of)
    for r in results:
        print(f"{_GLYPH.get(r['status'], '?'):4} {r['requirement']:20} {r['detail']}", file=sys.stderr)

    v = verdict(results)
    print(f"\nVERDICT: {v}  ({vendor.get('name', '?')})", file=sys.stderr)
    return 1 if v == "NO-GO" else 0


if __name__ == "__main__":
    raise SystemExit(main())
