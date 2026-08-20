#!/usr/bin/env python3
"""Read and record coverage outcomes in operations.json, by operation id.

    # list only your module's operations — never load the whole file
    python3 tools/set_outcome.py --run <run-dir> --list <module>
    python3 tools/set_outcome.py --run <run-dir> --pending <module>

    # record an outcome
    python3 tools/set_outcome.py --run <run-dir> --id ml.get.map --outcome tested
    python3 tools/set_outcome.py --run <run-dir> --id ml.get.map \
        --outcome excluded --reason "UI-only, no server handler"

Exists because `Edit` cannot do this job: `"outcome": null` is byte-identical on
every entry, so there is no unique anchor to target, and at Kibana scale
operations.json is ~800 KB — far too large for a subagent to hold in context
while also tracing source. Agents stay read-only; this does the surgery.

stdlib only.
"""
import argparse
import datetime as dt
import json
import pathlib
import sys

VALID = ("tested", "blocked", "excluded", "not_applicable")


def load(run: pathlib.Path) -> tuple[pathlib.Path, list]:
    path = run / "operations.json"
    if not path.exists():
        sys.exit(f"error: {path} does not exist — run mapper first.")
    try:
        ops = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        sys.exit(f"error: {path} is not valid JSON: {exc}")
    if not isinstance(ops, list):
        sys.exit(f"error: {path} must be a list.")

    seen, dupes = set(), set()
    for op in ops:
        oid = op.get("id")
        (dupes if oid in seen else seen).add(oid)
    if dupes:
        sys.exit(
            f"error: duplicate operation ids in {path}: {', '.join(sorted(map(str, dupes)))}\n"
            "Ids must be unique — a collision means two distinct routes are sharing one\n"
            "coverage slot, so testing one silently marks both covered."
        )
    return path, ops


def show(ops: list, module: str, pending_only: bool) -> int:
    rows = [o for o in ops if o.get("module") == module]
    if not rows:
        modules = sorted({o.get("module") for o in ops if o.get("module")})
        sys.exit(
            f"error: no operations with module '{module}'.\n"
            f"Known modules: {', '.join(modules) if modules else '(none)'}"
        )
    if pending_only:
        rows = [o for o in rows if o.get("outcome") not in VALID]

    for o in rows:
        priv = o.get("declared_privilege") or "-"
        print(
            f"{o.get('id')}\t{o.get('method')}\t{o.get('path_or_selector')}\t"
            f"area={o.get('area')}\tauth={o.get('auth_required')}\t"
            f"mutates={o.get('mutates_state')}\tpriv={priv}\t"
            f"outcome={o.get('outcome')}\tsrc={o.get('source_ref', '-')}"
        )
        if o.get("notes"):
            print(f"\t# {o['notes']}")

    total = len([o for o in ops if o.get("module") == module])
    done = len([o for o in ops if o.get("module") == module and o.get("outcome") in VALID])
    print(f"\n# {len(rows)} shown | module '{module}': {done}/{total} covered", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, type=pathlib.Path)
    ap.add_argument("--list", metavar="MODULE")
    ap.add_argument("--pending", metavar="MODULE")
    ap.add_argument("--id")
    ap.add_argument("--outcome", choices=VALID)
    ap.add_argument("--reason", default="")
    ap.add_argument("--finding-ids", default="")
    args = ap.parse_args()

    path, ops = load(args.run)

    if args.list or args.pending:
        return show(ops, args.list or args.pending, bool(args.pending))

    if not args.id or not args.outcome:
        ap.error("need --list/--pending, or both --id and --outcome")

    if args.outcome != "tested" and not args.reason.strip():
        sys.exit(
            f"error: --outcome {args.outcome} requires --reason.\n"
            "'blocked', 'excluded' and 'not_applicable' are meaningless without one —\n"
            "they are how a coverage gap gets justified, not how it gets hidden."
        )

    target = next((o for o in ops if o.get("id") == args.id), None)
    if target is None:
        near = [o["id"] for o in ops if args.id.split(".")[0] in str(o.get("id"))][:5]
        sys.exit(
            f"error: no operation with id '{args.id}'.\n"
            + (f"Did you mean: {', '.join(near)}\n" if near else "")
            + "If this is a real entry point mapper missed, report it as a mapper gap —\n"
              "do not invent an id, and do not absorb it silently."
        )

    prev = target.get("outcome")
    target["outcome"] = args.outcome
    target["outcome_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    if args.reason.strip():
        target["outcome_reason"] = args.reason.strip()
    if args.finding_ids.strip():
        target["finding_ids"] = [f.strip() for f in args.finding_ids.split(",") if f.strip()]

    path.write_text(json.dumps(ops, indent=2) + "\n")

    module = target.get("module")
    owned = [o for o in ops if o.get("module") == module]
    done = len([o for o in owned if o.get("outcome") in VALID])
    changed = f"{prev} -> {args.outcome}" if prev else f"set {args.outcome}"
    print(f"{args.id}: {changed}")
    print(f"module '{module}': {done}/{len(owned)} covered"
          + ("  (ready to mark complete)" if done == len(owned) else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
