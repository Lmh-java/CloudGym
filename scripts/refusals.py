"""The refusal catalogue for execution-conflict cases.

    uv run refusals build          # rebuild seeds/refusals.json from the installed SDK
    uv run refusals show [ID]      # print the catalogue (or one entry)

See harness/runtime/refusals.py for what is derived and what is manual.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness.runtime import refusals  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="write seeds/refusals.json from the installed botocore models")
    b.add_argument("--out", type=Path, default=refusals.CATALOGUE_PATH)
    s = sub.add_parser("show", help="print entries")
    s.add_argument("id", nargs="?")
    s.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if args.command == "build":
        path = refusals.write(args.out)
        doc = json.loads(path.read_text())
        print(f"{path.relative_to(REPO_ROOT)}: {len(doc['entries'])} entries, botocore {doc['botocore']}")
        return 0
    entries = refusals.load()
    chosen = [entries[args.id]] if args.id else list(entries.values())
    if args.json:
        print(json.dumps([e.as_dict() for e in chosen], indent=2))
        return 0
    for e in chosen:
        reads = "; ".join(f"{o.operation}({o.identifier_param}) {o.path} == {o.settled}" for o in e.observe) or f"no read, window {e.window_s}s"
        print(f"{e.id:30} {e.source:6} {e.resource}")
        print(f"{'':30} observe: {reads}")
        for ev in e.evidence:
            verdict = "refused" if ev.get("refused") else "NOT refused"
            print(f"{'':30} evidence: {ev.get('operation')} {verdict} during {ev.get('change')} ({ev.get('case')})")
        for shape, ops in e.refusals.items():
            print(f"{'':30} {shape}: {len(ops)} ops ({', '.join(ops[:6])}{', ...' if len(ops) > 6 else ''})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
