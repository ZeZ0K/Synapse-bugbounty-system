#!/usr/bin/env python3
"""Read and write the target-level anomaly ledger.

The ledger lives at runs/<target>/anomalies.json — one level ABOVE the run
directory, so it accumulates across runs instead of dying with one.

    # hunter: log something odd that is not a finding
    python3 tools/anomaly.py --run <run-dir> --add \
        --id ml.internal-client-on-read-branch \
        --source-agent hunter \
        --location "x-pack/.../analytics_manager.ts:99" \
        --what-was-odd "asInternalUser on one branch, asCurrentUser on its sibling" \
        --why-not-reportable "could not name a triggering request from the read alone"

    # prowler: see what is outstanding
    python3 tools/anomaly.py --run <run-dir> --list
    python3 tools/anomaly.py --run <run-dir> --list --status open

    # prowler: close one out
    python3 tools/anomaly.py --run <run-dir> --resolve --id <id> \
        --status resolved_benign --resolved-by prowler \
        --resolution "Guarded upstream at routes.ts:212, which rejects ... (file:line)"

    # prowler: rank what it did not reach
    python3 tools/anomaly.py --run <run-dir> --rank --id <id> --priority high

Agents hold no Write tool, so this is how they record. It also enforces unique
ids and the schema's conditional rules before anything lands.

stdlib only.
"""
import argparse
import contextlib
import datetime as dt
import fcntl
import json
import os
import pathlib
import sys
import tempfile

STATUSES = ("open", "pursued", "resolved_benign", "escalated")
NEEDS_RESOLUTION = ("pursued", "resolved_benign", "escalated")
OUTSTANDING = ("open", "pursued")
DEFAULT_LIMIT = 40


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def ledger_path(run: pathlib.Path) -> pathlib.Path:
    """Resolve runs/<target>/anomalies.json from the RUN directory.

    Validated, because the target-vs-run distinction is exactly what this
    feature's 'one level above' design makes easy to get wrong — and getting it
    wrong would silently fork a second ledger that nothing ever reads.
    """
    run = run.resolve()
    if not run.is_dir():
        sys.exit(f"error: --run {run} does not exist. Pass the RUN directory "
                 f"(runs/<target>/<run_id>), not the target directory.")
    if not (run / "state.json").exists():
        sys.exit(f"error: --run {run} has no state.json, so it is not a run directory. "
                 f"Pass runs/<target>/<run_id>; the ledger is resolved one level above it.")
    return run.parent / "anomalies.json"


@contextlib.contextmanager
def locked(path: pathlib.Path):
    """Exclusive lock around read-modify-write.

    The orchestrator permits two concurrent hunters, and they share this
    target-level ledger. Unlocked, a measured 80-write interleave lost 5-17
    entries silently. Unlike operations.json this file is never regenerated —
    it is the only copy of cross-run state.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_suffix(".lock")
    with open(lock, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def load(path: pathlib.Path) -> list:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        sys.exit(f"error: {path} is not valid JSON: {exc}")
    if not isinstance(data, list):
        sys.exit(f"error: {path} must be a list.")
    return data


def save(path: pathlib.Path, data: list) -> None:
    """Atomic: a crash mid-write would otherwise truncate the whole history."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".anomalies-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(data, indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def summarize(rows: list) -> int:
    """Counts by module and by recurrence cluster, so prowler can drill in
    rather than pulling the whole ledger into context."""
    by_module: dict = {}
    for r in rows:
        key = r.get("module") or "(none)"
        b = by_module.setdefault(key, {s: 0 for s in STATUSES})
        b[r.get("status", "open")] = b.get(r.get("status", "open"), 0) + 1

    print("module                          open  pursued  benign  escalated")
    for mod in sorted(by_module):
        c = by_module[mod]
        print(f"{mod:<30}  {c['open']:>4}  {c['pursued']:>7}  "
              f"{c['resolved_benign']:>6}  {c['escalated']:>9}")

    clusters = [r for r in rows if r.get("recurrence")]
    if clusters:
        print("\nrecurrence clusters (a shape seen in several places — highest-value leads):")
        for r in clusters:
            print(f"  {r['id']}  <-> {', '.join(r['recurrence'])}")

    runs = sorted({r.get("run_id") for r in rows if r.get("run_id")})
    print(f"\n# {len(rows)} entries across {len(runs)} run(s): {', '.join(runs) if runs else '-'}",
          file=sys.stderr)
    return 0


def show(rows: list, status: str | None, module: str | None,
         outstanding: bool, limit: int) -> int:
    sel = rows
    if outstanding:
        sel = [r for r in sel if r.get("status") in OUTSTANDING]
    elif status:
        sel = [r for r in sel if r.get("status") == status]
    if module:
        sel = [r for r in sel if r.get("module") == module]

    if not sel:
        print("# no anomalies match", file=sys.stderr)
        return 0

    # pursued first: an opus agent already spent depth on those and wrote down
    # what remains open, which makes them the most informed entries in the file.
    order = {"high": 0, "medium": 1, "low": 2}
    sel.sort(key=lambda r: (
        0 if r.get("status") == "pursued" else 1,
        order.get(r.get("priority"), 3),
        r.get("id", ""),
    ))

    total_sel = len(sel)
    truncated = total_sel > limit
    for r in sel[:limit]:
        pri = f" [{r['priority']}]" if r.get("priority") else ""
        att = f" attempts={r['prowler_attempts']}" if r.get("prowler_attempts") else ""
        print(f"{r.get('id')}  ({r.get('status')}{pri}{att})  <- {r.get('source_agent')}  "
              f"module={r.get('module', '-')}  run={r.get('run_id', '-')}  {r.get('location')}")
        print(f"    odd : {r.get('what_was_odd')}")
        print(f"    why : {r.get('why_not_reportable')}")
        if r.get("recurrence"):
            print(f"    also: {', '.join(r['recurrence'])}")
        if r.get("resolution"):
            print(f"    res : {r['resolution']}")

    counts = {s: len([r for r in rows if r.get("status") == s]) for s in STATUSES}
    note = ""
    if truncated:
        note = (f"\n# TRUNCATED: {total_sel - limit} more match. Do not treat this page as "
                f"the whole ledger — use --summary, then --module <name> to drill in.")
    print(
        f"\n# {min(total_sel, limit)} of {total_sel} shown | ledger total {len(rows)} | "
        + " ".join(f"{k}={v}" for k, v in counts.items()) + note,
        file=sys.stderr,
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, type=pathlib.Path,
                    help="the RUN directory; the ledger is resolved one level above it")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--add", action="store_true")
    mode.add_argument("--list", action="store_true")
    mode.add_argument("--summary", action="store_true",
                      help="counts by module + recurrence clusters; start here")
    mode.add_argument("--resolve", action="store_true")
    mode.add_argument("--rank", action="store_true")

    ap.add_argument("--outstanding", action="store_true",
                    help="list open AND pursued — what is actually still live")
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    ap.add_argument("--new-source",
                    help="required to re-escalate an anomaly a previous run already escalated")

    ap.add_argument("--id")
    ap.add_argument("--source-agent", choices=["hunter", "skeptic", "triager", "prowler", "chainer", "mapper"])
    ap.add_argument("--location")
    ap.add_argument("--what-was-odd")
    ap.add_argument("--why-not-reportable")
    ap.add_argument("--module")
    ap.add_argument("--operation-ids", default="")
    ap.add_argument("--recurrence", default="")
    ap.add_argument("--status", choices=STATUSES,
                    help="on --resolve, 'open' is not a valid target: use --rank instead")
    ap.add_argument("--resolution", default="")
    ap.add_argument("--resolved-by")
    ap.add_argument("--finding-id")
    ap.add_argument("--priority", choices=["high", "medium", "low"])
    args = ap.parse_args()

    path = ledger_path(args.run)
    run_id = args.run.resolve().name

    if args.list or args.summary:
        rows = load(path)
        if args.summary:
            return summarize(rows)
        return show(rows, args.status, args.module, args.outstanding, args.limit)

    # Everything below mutates: hold the lock across read-modify-write.
    with locked(path):
        return mutate(args, ap, path, run_id)


def mutate(args, ap, path: pathlib.Path, run_id: str) -> int:
    rows = load(path)

    if args.add:
        missing = [f for f in ("id", "source_agent", "location", "what_was_odd", "why_not_reportable")
                   if not getattr(args, f)]
        if missing:
            ap.error("--add needs " + ", ".join("--" + m.replace("_", "-") for m in missing))
        if any(r.get("id") == args.id for r in rows):
            sys.exit(
                f"error: anomaly id '{args.id}' already exists in {path}.\n"
                "Ids are unique across the whole ledger and across runs. If this is the same\n"
                "observation seen again elsewhere, add the existing id to the new entry's\n"
                "--recurrence instead of re-logging it — a shape seen in three modules is\n"
                "worth more than three unrelated curiosities, and only recurrence shows that."
            )
        rows.append({
            "id": args.id,
            "source_agent": args.source_agent,
            "location": args.location,
            "what_was_odd": args.what_was_odd,
            "why_not_reportable": args.why_not_reportable,
            "status": "open",
            "run_id": run_id,
            "logged_at": now(),
            **({"module": args.module} if args.module else {}),
            **({"operation_ids": [s.strip() for s in args.operation_ids.split(",") if s.strip()]}
               if args.operation_ids.strip() else {}),
            **({"recurrence": [s.strip() for s in args.recurrence.split(",") if s.strip()]}
               if args.recurrence.strip() else {}),
        })
        save(path, rows)
        print(f"logged {args.id} (open) -> {path}")
        print(f"ledger now {len(rows)} entries, {len([r for r in rows if r['status']=='open'])} open")
        return 0

    target = next((r for r in rows if r.get("id") == args.id), None)
    if target is None:
        sys.exit(f"error: no anomaly with id '{args.id}' in {path}")

    if args.rank:
        if not args.priority:
            ap.error("--rank needs --priority")
        target["priority"] = args.priority
        save(path, rows)
        print(f"{args.id}: priority {args.priority}")
        return 0

    # --resolve
    if not args.status:
        ap.error("--resolve needs --status")
    if args.status == "open":
        sys.exit(
            "error: --resolve cannot set status back to 'open'.\n"
            "Reverting would leave a stale resolution attached to a live anomaly, which\n"
            "the next run would read as a settled verdict. Use --rank to reprioritise, or\n"
            "--status pursued to record partial progress."
        )
    attempts = int(target.get("prowler_attempts", 0))
    if args.status == "escalated" and attempts >= 1 and not (args.new_source or "").strip():
        sys.exit(
            f"error: '{args.id}' was already escalated once (prowler_attempts={attempts}) and\n"
            "a previous run's skeptic did not keep it. Re-escalating on the same evidence is\n"
            "the unbounded loop every other stage caps.\n"
            "Pass --new-source naming the specific thing you have that the last attempt did\n"
            "not: a file it never opened, an assumption you actually tested, a source it\n"
            "never checked. If you do not have one, this is 'pursued' or 'resolved_benign'."
        )
    if args.status in NEEDS_RESOLUTION:
        if not args.resolution.strip():
            sys.exit(
                f"error: --status {args.status} requires --resolution.\n"
                "For resolved_benign this must name the actual mechanism that makes the\n"
                "behaviour safe, with file:line. A benign verdict with no mechanism is an\n"
                "unexamined anomaly wearing a resolved label."
            )
        if not args.resolved_by:
            sys.exit(f"error: --status {args.status} requires --resolved-by")
    if args.status == "escalated" and not args.finding_id:
        sys.exit(
            "error: --status escalated requires --finding-id.\n"
            "An escalated anomaly becomes a candidate that enters the chain at skeptic —\n"
            "it needs a finding to point at."
        )

    prev = target.get("status")
    target["status"] = args.status
    if args.resolution.strip():
        target["resolution"] = args.resolution.strip()
    if args.resolved_by:
        target["resolved_by"] = args.resolved_by
    target["resolution_run_id"] = run_id
    if args.finding_id:
        target["finding_id"] = args.finding_id
    if args.status == "escalated":
        target["prowler_attempts"] = attempts + 1
        if (args.new_source or "").strip():
            target["resolution"] = (
                target.get("resolution", "") + f" [new source: {args.new_source.strip()}]"
            )
    save(path, rows)

    print(f"{args.id}: {prev} -> {args.status}")
    remaining = len([r for r in rows if r.get("status") == "open"])
    print(f"ledger {len(rows)} entries, {remaining} still open")
    return 0


if __name__ == "__main__":
    sys.exit(main())
