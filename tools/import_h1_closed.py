#!/usr/bin/env python3
"""Bootstrap the calibration corpus from closed HackerOne reports.

    H1_USER=<handle> H1_TOKEN=<api-token> .venv/bin/python tools/import_h1_closed.py
    ... --program elastic --dry-run

Writes one stub per closed report into memory/closed-reports/, skipping any
file that already exists so hand-written lessons are never clobbered.

The stubs are deliberately incomplete: the API gives you the label
("Informative", "Duplicate"), never the *reason*. `closure_root_cause` and the
Lesson section are left as TODO markers for you to fill in, because the reason
is the only part that calibrates anything.

Credentials come from the environment and are never written to this tree.
"""
import argparse
import base64
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.hackerone.com/v1/hackers/me/reports"
OUT = pathlib.Path(__file__).resolve().parent.parent / "memory" / "closed-reports"

# Closed states worth learning from. 'resolved' included as positive calibration.
KEEP = {"informative", "duplicate", "not-applicable", "resolved", "spam"}


def slug(text: str, limit: int = 60) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:limit].rstrip("-") or "untitled"


def fetch(user: str, token: str, program: str | None) -> list[dict]:
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    reports: list[dict] = []
    page = 1
    while True:
        params = {"page[size]": "100", "page[number]": str(page)}
        if program:
            params["filter[program][]"] = program
        req = urllib.request.Request(
            f"{API}?{urllib.parse.urlencode(params)}",
            headers={"Authorization": f"Basic {auth}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.load(resp)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            sys.exit(f"HackerOne API {exc.code}: {detail}")
        except urllib.error.URLError as exc:
            sys.exit(f"HackerOne API unreachable: {exc.reason}")

        batch = body.get("data", [])
        if not batch:
            break
        reports.extend(batch)
        if not body.get("links", {}).get("next"):
            break
        page += 1
    return reports


def stub(report: dict) -> tuple[str, str] | None:
    attrs = report.get("attributes", {})
    state = (attrs.get("state") or "").lower()
    if state not in KEEP:
        return None

    rid = report.get("id", "unknown")
    title = attrs.get("title", "(untitled)")
    rel = report.get("relationships", {})
    program = (
        rel.get("program", {}).get("data", {}).get("attributes", {}).get("handle")
        or "unknown"
    )
    severity = (
        rel.get("severity", {}).get("data", {}).get("attributes", {}).get("rating")
        or "unknown"
    )
    resolution = {"not-applicable": "not_applicable"}.get(state, state)

    # Per-target subdirectory: every consumer reads
    # memory/closed-reports/<target>/, never the flat directory.
    name = f"{program}/{program}-h1-{rid}-{slug(title)}.md"
    body = f"""---
report_id: H1 #{rid}
program: {program}
finding_ref:
submitted: {(attrs.get('created_at') or '')[:10]}
closed: {(attrs.get('closed_at') or '')[:10]}
resolution: {resolution}
severity_claimed:
severity_assigned: {severity}
closure_root_cause: TODO — the actual reason, not the label. The API cannot tell you this.
---

## Claimed

{title}

TODO — what the finding actually asserted, in enough detail that a triager can
recognise the same shape in a different module.

## Program response

State: **{state}**. TODO — what they said, quoted where it matters.

## Lesson

TODO — write this as a rule a future triager can apply to a *different* finding.
A lesson that only describes this one report calibrates nothing.
"""
    return name, body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--program", help="filter to one program handle, e.g. elastic")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    user, token = os.environ.get("H1_USER"), os.environ.get("H1_TOKEN")
    if not user or not token:
        return int(
            bool(
                sys.stderr.write(
                    "H1_USER and H1_TOKEN must be set in the environment.\n"
                    "They are read from env only and never written to this tree.\n"
                )
            )
        ) or 2

    reports = fetch(user, token, args.program)
    print(f"fetched {len(reports)} reports")

    OUT.mkdir(parents=True, exist_ok=True)
    written = skipped = ignored = 0
    for report in reports:
        result = stub(report)
        if result is None:
            ignored += 1
            continue
        name, body = result
        target = OUT / name
        if target.exists():
            skipped += 1
            continue
        if args.dry_run:
            print(f"would write {target.relative_to(OUT)}")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
            print(f"wrote {target.relative_to(OUT)}")
        written += 1

    print(
        f"\n{written} stub(s), {skipped} already present (left untouched), "
        f"{ignored} still open."
    )
    if written:
        print("Every stub has TODOs. An unfilled stub calibrates nothing — the")
        print("closure *reason* is the whole value, and the API does not carry it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
