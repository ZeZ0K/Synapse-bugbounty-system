#!/usr/bin/env python3
"""Poll HackerOne for the current state of filed reports.

    H1_USER=<handle> H1_TOKEN=<token> python3 tools/h1_status.py --id 3887567
    H1_USER=... H1_TOKEN=... python3 tools/h1_status.py --all --reports runs/<t>/<r>/reports.json

Prints one JSON object per report: state, severity, last activity, and the
latest few activity entries. Read-only — it never comments, closes, or
otherwise touches a report.

Credentials come from the environment. They are never written to disk and never
appear on a command line, which is why this exists instead of inline curl.

stdlib only.
"""
import argparse
import base64
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

BASE = "https://api.hackerone.com/v1/hackers/reports"


def get(rid: str, auth: str) -> dict:
    req = urllib.request.Request(
        f"{BASE}/{rid}",
        headers={"Authorization": f"Basic {auth}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        return {"error": f"HTTP {exc.code}", "detail": exc.read().decode("utf-8", "replace")[:300]}
    except urllib.error.URLError as exc:
        return {"error": "unreachable", "detail": str(exc.reason)}


def summarize(rid: str, body: dict) -> dict:
    if "error" in body:
        return {"report_id": rid, **body}
    data = body.get("data", {})
    attrs = data.get("attributes", {})
    rel = data.get("relationships", {})

    activities = []
    for act in (rel.get("activities", {}) or {}).get("data", [])[-5:]:
        a = act.get("attributes", {})
        activities.append({
            "at": a.get("created_at"),
            "type": act.get("type"),
            "internal": a.get("internal"),
            "message": (a.get("message") or "")[:200],
        })

    return {
        "report_id": rid,
        "state": attrs.get("state"),
        "title": attrs.get("title"),
        "created_at": attrs.get("created_at"),
        "triaged_at": attrs.get("triaged_at"),
        "closed_at": attrs.get("closed_at"),
        "last_activity_at": attrs.get("last_activity_at"),
        "severity": (rel.get("severity", {}).get("data", {}).get("attributes", {}) or {}).get("rating"),
        "recent_activity": activities,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", action="append", default=[], help="report id (repeatable)")
    ap.add_argument("--all", action="store_true", help="every non-closed report in --reports")
    ap.add_argument("--reports", type=pathlib.Path, help="path to reports.json")
    args = ap.parse_args()

    user, token = os.environ.get("H1_USER"), os.environ.get("H1_TOKEN")
    if not user or not token:
        sys.stderr.write(
            "H1_USER and H1_TOKEN must be set in the environment.\n"
            "Read from env only; never written to this tree or passed on a command line.\n"
        )
        return 2
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()

    ids = list(args.id)
    if args.all:
        if not args.reports or not args.reports.exists():
            sys.stderr.write("--all needs --reports pointing at an existing reports.json\n")
            return 2
        try:
            reports = json.loads(args.reports.read_text())
        except json.JSONDecodeError as exc:
            sys.stderr.write(f"{args.reports} is not valid JSON: {exc}\n")
            return 2
        closed = {"resolved", "duplicate", "informative", "not_applicable", "closed"}
        ids += [
            str(r["report_id"]).lstrip("#H1 ")
            for r in reports
            if r.get("status") not in closed and str(r.get("report_id", "")).strip()
        ]

    if not ids:
        sys.stderr.write("nothing to check — pass --id or --all\n")
        return 2

    for rid in dict.fromkeys(ids):
        print(json.dumps(summarize(rid, get(rid, auth)), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
