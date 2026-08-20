#!/usr/bin/env python3
"""PreToolUse gate: a module may not be marked complete with uncovered operations.

Denies any Write/Edit to runs/**/state.json that flips a module to "complete"
while an operations.json entry carrying that module still has no `outcome`.

PostToolUse cannot implement this — it fires after the write has already landed.
PreToolUse returning permissionDecision "deny" is the only blocking event.

Fails CLOSED: if this gate cannot determine the answer, it denies. A security
gate that fails open is decoration.

stdlib only — must not depend on the tooling venv.
"""
import json
import pathlib
import sys

VALID_OUTCOMES = {"tested", "blocked", "excluded", "not_applicable"}
MAX_LISTED = 8


def deny(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def allow() -> None:
    sys.exit(0)


def proposed_content(tool: str, ti: dict, path: pathlib.Path) -> str | None:
    """The content the file WOULD have. None means 'not determinable, allow'."""
    if tool == "Write":
        return ti.get("content", "")

    current = path.read_text() if path.exists() else ""

    if tool == "Edit":
        old, new = ti.get("old_string", ""), ti.get("new_string", "")
        if old not in current:
            return None  # the Edit itself will fail; nothing lands
        return current.replace(old, new) if ti.get("replace_all") else current.replace(old, new, 1)

    if tool == "MultiEdit":
        for edit in ti.get("edits", []):
            old, new = edit.get("old_string", ""), edit.get("new_string", "")
            if old not in current:
                return None
            current = current.replace(old, new) if edit.get("replace_all") else current.replace(old, new, 1)
        return current

    return None


def main() -> None:
    payload = json.load(sys.stdin)
    tool = payload.get("tool_name", "")
    if tool not in ("Write", "Edit", "MultiEdit"):
        allow()

    ti = payload.get("tool_input", {}) or {}
    raw_path = ti.get("file_path")
    if not raw_path:
        allow()

    path = pathlib.Path(raw_path)
    if not path.is_absolute():
        path = pathlib.Path(payload.get("cwd", ".")) / path

    # Only guard run state files.
    if path.name != "state.json" or "runs" not in path.parts:
        allow()

    content = proposed_content(tool, ti, path)
    if content is None:
        allow()

    try:
        new_state = json.loads(content)
    except json.JSONDecodeError as exc:
        deny(
            f"state.json would not be valid JSON ({exc}). Refusing the write — an "
            f"unparseable state file breaks run recovery, which is the whole point "
            f"of the file."
        )

    new_modules = (new_state or {}).get("modules", {}) or {}
    if not isinstance(new_modules, dict):
        deny("state.json 'modules' must be an object mapping module name -> status.")

    old_modules = {}
    if path.exists():
        try:
            old_modules = (json.loads(path.read_text()) or {}).get("modules", {}) or {}
        except Exception:
            old_modules = {}

    newly_complete = [
        m for m, status in new_modules.items()
        if status == "complete" and old_modules.get(m) != "complete"
    ]
    if not newly_complete:
        allow()

    ops_path = path.parent / "operations.json"
    if not ops_path.exists():
        deny(
            f"Cannot mark {', '.join(newly_complete)} complete: {ops_path} does not "
            f"exist, so there is no coverage record to verify against. Run mapper first."
        )

    try:
        operations = json.loads(ops_path.read_text())
        assert isinstance(operations, list)
    except Exception as exc:
        deny(f"Cannot verify coverage: {ops_path} is unreadable or not a list ({exc}).")

    problems = []
    for module in sorted(newly_complete):
        owned = [op for op in operations if isinstance(op, dict) and op.get("module") == module]
        if not owned:
            problems.append(
                f"module '{module}' has zero operations in operations.json — either the "
                f"module name does not match what mapper emitted, or the inventory is "
                f"missing. An empty module cannot be 'complete'."
            )
            continue
        uncovered = [
            op.get("id", "<no id>") for op in owned
            if op.get("outcome") not in VALID_OUTCOMES
        ]
        if uncovered:
            shown = ", ".join(uncovered[:MAX_LISTED])
            more = f" (+{len(uncovered) - MAX_LISTED} more)" if len(uncovered) > MAX_LISTED else ""
            problems.append(
                f"module '{module}': {len(uncovered)} of {len(owned)} operations have no "
                f"outcome — {shown}{more}"
            )

    if problems:
        deny(
            "Coverage gate: refusing to mark a module complete with uncovered "
            "operations.\n\n" + "\n".join(f"  - {p}" for p in problems) +
            f"\n\nEvery operation needs an explicit outcome ({'/'.join(sorted(VALID_OUTCOMES))}), "
            "and anything other than 'tested' needs an outcome_reason. Do not work around "
            "this by renaming the module or removing entries — an operation that is dropped "
            "is never tested and never noticed."
        )

    allow()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # fail closed
        deny(f"Coverage gate crashed ({type(exc).__name__}: {exc}). Denying rather than "
             f"allowing an unverified write.")
