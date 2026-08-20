---
name: bounty-run
description: Runs the bug bounty research pipeline against a target — resume-or-create a run, policy gate, mapper, provisioner, then per module hunter -> skeptic -> escalator -> verifier -> triager with coverage enforcement, then prowler over the anomaly ledger before the run closes. Use when starting, resuming, or continuing a bounty run on any program under this repository.
---

Read `orchestrator.md` (at this repository's root) and follow it. It is the
authoritative loop; this file only routes you to it.

Two things before anything else:

1. **Resume before creating.** Check `runs/<target>/` for an existing
   `state.json`. If one exists, resume it and re-surface any unresolved
   `blocked` entries to the user before doing anything else.
2. **Run with `cwd` set to this repository's root** so the enforcement hooks
   load and `runs/` paths resolve.

If the user named a target, use it. If not, list the programs under
`targets/` and ask which — do not pick one.
