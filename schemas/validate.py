#!/usr/bin/env python3
"""Validate run artifacts against the schemas in this directory.

    .venv/bin/python schemas/validate.py runs/elastic/<run_id>
    .venv/bin/python schemas/validate.py --file runs/.../state.json --schema state

Resolves cross-file $refs locally (escalate/verify reference
finding.schema.json#/$defs/evidence), so no network access is involved.
"""
import json
import pathlib
import sys

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

HERE = pathlib.Path(__file__).resolve().parent

# run-dir filename -> schema name
RUN_FILES = {
    "state.json": "state",
    "operations.json": "operations",
    "accounts.json": "accounts",
    "reports.json": "reports",
}
FINDING_FILES = {
    "finding.json": "finding",
    "escalate.json": "escalate",
    "verify.json": "verify",
    "triage.json": "triage",
}


def registry() -> Registry:
    reg = Registry()
    for path in HERE.glob("*.schema.json"):
        schema = json.loads(path.read_text())
        reg = reg.with_resource(schema["$id"], Resource.from_contents(schema))
    return reg


def validator(name: str) -> Draft202012Validator:
    schema = json.loads((HERE / f"{name}.schema.json").read_text())
    return Draft202012Validator(schema, registry=registry())


def check(path: pathlib.Path, name: str) -> int:
    try:
        instance = json.loads(path.read_text())
    except Exception as exc:
        print(f"FAIL {path} -> unparseable: {exc}")
        return 1
    errors = sorted(validator(name).iter_errors(instance), key=lambda e: list(e.path))
    if not errors:
        print(f"OK   {path}  [{name}]")
        return 0
    for err in errors:
        loc = "/".join(str(p) for p in err.path) or "<root>"
        print(f"FAIL {path} -> {loc}: {err.message}")
    return 1


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "--file":
        return check(pathlib.Path(argv[2]), argv[3])
    if len(argv) == 5 and argv[1] == "--file" and argv[3] == "--schema":
        return check(pathlib.Path(argv[2]), argv[4])
    if len(argv) != 2:
        print(__doc__)
        return 2

    run = pathlib.Path(argv[1])
    if not run.is_dir():
        print(f"not a directory: {run}")
        return 2

    rc = 0
    seen = False
    # Target-level, one above the run dir: accumulates across runs.
    anomalies = run / ".." / "anomalies.json"
    if anomalies.exists():
        seen = True
        rc |= check(anomalies.resolve(), "anomalies")
    for fname, sname in RUN_FILES.items():
        target = run / fname
        if target.exists():
            seen = True
            rc |= check(target, sname)
    for finding_dir in sorted((run / "findings").glob("*")):
        if not finding_dir.is_dir():
            continue
        for fname, sname in FINDING_FILES.items():
            target = finding_dir / fname
            if target.exists():
                seen = True
                rc |= check(target, sname)
    if not seen:
        print(f"no known artifacts found under {run}")
        return 2
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
