#!/usr/bin/env python3
"""PreToolUse gate: triager cannot PASS a finding verifier did not CONFIRM.

Denies any Write/Edit to findings/<id>/triage.json whose verdict is PASS unless
the sibling verify.json says CONFIRMED.

This is why verdicts are files rather than prose: a prose verdict cannot be
checked by anything.

Fails CLOSED: if this gate cannot determine the answer, it denies.

stdlib only — must not depend on the tooling venv.
"""
import json
import pathlib
import sys


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
    if tool == "Write":
        return ti.get("content", "")

    current = path.read_text() if path.exists() else ""

    if tool == "Edit":
        old, new = ti.get("old_string", ""), ti.get("new_string", "")
        if old not in current:
            return None
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

    if path.name != "triage.json" or "findings" not in path.parts:
        allow()

    content = proposed_content(tool, ti, path)
    if content is None:
        allow()

    try:
        triage = json.loads(content)
    except json.JSONDecodeError as exc:
        deny(f"triage.json would not be valid JSON ({exc}). A verdict that cannot be "
             f"parsed cannot be enforced.")

    if (triage or {}).get("verdict") != "PASS":
        allow()  # BLOCK / DOWNGRADE / REJECT need no verification gate

    finding_id = (triage or {}).get("finding_id", path.parent.name)
    verify_path = path.parent / "verify.json"

    if not verify_path.exists():
        deny(
            f"Triage gate: cannot PASS finding '{finding_id}' — {verify_path.name} does "
            f"not exist. Nothing has independently reproduced this finding. Run verifier "
            f"first, or use BLOCK / DOWNGRADE / REJECT."
        )

    try:
        verify = json.loads(verify_path.read_text())
    except Exception as exc:
        deny(f"Triage gate: cannot PASS finding '{finding_id}' — {verify_path.name} is "
             f"unreadable ({exc}).")

    verdict = (verify or {}).get("verdict")
    if verdict != "CONFIRMED":
        deny(
            f"Triage gate: cannot PASS finding '{finding_id}' — verifier returned "
            f"'{verdict or '<missing>'}', not CONFIRMED.\n\n"
            f"A finding that could not be independently reproduced from its own written "
            f"PoC steps will not reproduce for the program's triager either. Valid verdicts "
            f"here are BLOCK, DOWNGRADE, or REJECT.\n\n"
            f"Do not edit verify.json to unblock this — that inverts the gate. If the "
            f"finding really does reproduce, re-run verifier and let it say so."
        )

    allow()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # fail closed
        deny(f"Triage gate crashed ({type(exc).__name__}: {exc}). Denying rather than "
             f"allowing an unverified PASS.")
