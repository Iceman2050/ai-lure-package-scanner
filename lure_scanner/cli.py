"""CLI entry point for ai-lure-package-scanner."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import format_report, parse_deps, scan_deps

EXIT_HIGH = 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ai-lure-scan",
        description=(
            "Scan a package.json / package-lock.json for AI-lure malware patterns: "
            "AI-themed dependency names, freshly published versions, low download "
            "counts, and install hooks - the signature of the fake-AI-SDK malware wave."
        ),
    )
    p.add_argument("lockfile", help="path to package.json or package-lock.json")
    p.add_argument("--offline", action="store_true",
                   help="do not hit the npm registry; use --fixture JSON instead")
    p.add_argument("--fixture", default=None,
                   help="registry fixture JSON (required with --offline)")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    lockfile = Path(args.lockfile)
    if not lockfile.exists():
        print(f"error: file not found: {lockfile}", file=sys.stderr)
        return 2

    offline_data = None
    if args.offline:
        if not args.fixture:
            print("error: --offline requires --fixture <registry-fixture.json>",
                  file=sys.stderr)
            return 2
        offline_data = json.loads(Path(args.fixture).read_text(encoding="utf-8"))

    deps = parse_deps(lockfile)
    results = scan_deps(deps, offline=offline_data)

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print(format_report(results))

    return EXIT_HIGH if any(r.get("severity") == "HIGH" for r in results) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
