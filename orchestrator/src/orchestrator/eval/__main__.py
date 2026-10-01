"""``python -m orchestrator.eval`` -- run the harness and print the report.

``--json`` prints the machine-readable report instead, for recording a run
alongside a commit so a later regression has something to be a regression from.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from ..config import get_settings
from ..graphs.runtime import Runtime
from . import corpus
from .harness import evaluate, format_report


def main() -> int:
    parser = argparse.ArgumentParser(prog="orchestrator.eval", description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the raw report as JSON")
    parser.add_argument("--quiet", action="store_true", help="suppress progress logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet or args.json else logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )

    settings = corpus.settings_for(get_settings())
    runtime = Runtime.build(settings)
    try:
        report = evaluate(runtime)
    except Exception as exc:  # noqa: BLE001
        print(f"eval failed: {exc}", file=sys.stderr)
        return 2
    finally:
        runtime.close()

    print(json.dumps(report, indent=2) if args.json else format_report(report))
    # Non-zero when the exit test fails, so CI can gate on it.
    return 0 if "resolution helps" in format_report(report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
