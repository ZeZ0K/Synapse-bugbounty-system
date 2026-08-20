# Bug bounty research system

AI-orchestrated pipeline for the repeatable parts of bounty research: mapping a
target, provisioning test access, hunting candidates, and adversarially
validating them before they reach you. You keep program selection, direction,
review, and submission.

**The goal is fewer, harder-to-kill findings.** A run producing two findings
that survive the program's triage beats one producing nine that come back
Informative. Killing a weak finding early is a success and gets reported as one.

## Running it

```bash
cd Synapse-bugbounty-system
claude
```

Then `/bounty-run`, or just point it at [orchestrator.md](orchestrator.md).

**Always run from this directory.** The enforcement hooks are project-scoped and
`runs/` paths are relative to it.

## Layout

| Path | What |
|---|---|
| [orchestrator.md](orchestrator.md) | The run loop. Resume-before-create, policy gate, per-module chain. |
| `~/.claude/agents/` | The ten agent definitions (user-scoped — see [agents/README](agents/README.md) for why). |
| [schemas/](schemas/) | JSON Schema for every artifact + `validate.py`. |
| [.claude/hooks/](.claude/hooks/) | The two enforcement gates + their tests. |
| [memory/general-lessons.md](memory/general-lessons.md) | Cross-program triage patterns. Read on every run, every target. |
| [memory/closed-reports/&lt;target&gt;/](memory/closed-reports/) | Per-target calibration corpus. Read by escalator, triager and prowler. Empty on a new target. |
| [qa/](qa/) | Review rubric and shipped residual objections. |
| [targets/](targets/) | Per-target `policy.md` (scope + automation snapshot) and `profile.md` (saved discovery recipe), plus that target's own source clones and program docs. |
| [tools/](tools/) | `set_outcome.py`, `anomaly.py`, `h1_status.py`, `import_h1_closed.py`. |
| `runs/<target>/<run_id>/` | Everything a run produces. This is the recovery mechanism. |
| `runs/<target>/anomalies.json` | The anomaly ledger. Target-level, so it accumulates across runs. |

## Starting a new target

Four steps. Do them in order — step 2 depends on step 1 having happened.

1. **`mkdir -p targets/<target>` and write `policy.md`** from the program's
   *actual published policy*. Not a guess, not a recollection: the same re-read
   discipline `orchestrator.md` §1a requires on every run. Record scope,
   payable classes, out-of-scope items and anything about automated tooling.
2. **Let the first `mapper` run populate `profile.md`.** With no profile
   present, mapper runs its discovery phase — identify the framework's
   registration idiom, find where authorization is declared, cross-check
   several independent extraction methods, hand-verify a sample — and writes
   the recipe. This is a one-time cost per target; every later run reads it.
3. **`memory/closed-reports/<target>/` starts empty.** That is expected, not
   broken. `memory/general-lessons.md` applies from run one regardless. If you
   have prior HackerOne history against this program, seed the corpus before
   the first real run:
   ```bash
   H1_USER=<handle> H1_TOKEN=<token> .venv/bin/python tools/import_h1_closed.py --program <target> --dry-run
   ```
   It writes into `memory/closed-reports/<program>/`. Pass `--program` unless
   you want every program on the account landing in this run; drop `--dry-run`
   once the listing looks right.
4. **Confirm which of the six disqualifier sources actually exist** for this
   target and record it in `profile.md`. Most SaaS targets have no public repo,
   so source 1 does not apply — write that down once as `not_applicable` with
   the reason, and every later `skeptic`, `escalator`, `chainer` and `triager`
   call stops re-discovering it. A shorter list is not a weaker check; a source
   that exists and was skipped is.

## The chain

```
policy gate → mapper → provisioner        (once per target)
per module:  hunter → skeptic → [SURVIVES] → escalator → verifier → triager
             chainer whenever a new finding lands
```

A `BLOCK`/`DOWNGRADE` from triager goes back to escalator **exactly once**, then
parks for you. The cap is deliberate: an unbounded loop burns the most expensive
models in the chain on something that already failed the gate twice.

## Enforcement

Two rules are backed by hooks rather than prompt instructions, because prose is
not a boundary. Both are `PreToolUse` (`PostToolUse` fires after the write lands)
and both **fail closed** — a gate that fails open is decoration.

1. **Coverage** — a module cannot be marked `complete` while any operation
   carrying it lacks an `outcome`. Every operation ends as `tested`, `blocked`,
   `excluded` or `not_applicable`, and the last three need a reason.
2. **Verification** — `triager` cannot write `PASS` unless `verify.json` says
   `CONFIRMED`. This is why verdicts are files: prose cannot be checked.

Test them: `bash .claude/hooks/test_gates.sh`

## Non-negotiables

- **No fabricated evidence.** Every artifact traces to a real tool execution in
  the run. Untraceable evidence is dropped, not caveated.
- **No silently skipped coverage.** An operation that is never inventoried is
  never tested and never noticed — the gate can only check entries that exist.
- **Never outside published scope or automation policy**, re-read per program,
  per run.
- **The agent does not create accounts, enter passwords, or solve CAPTCHAs.**
  Provisioner stops and names what it needs from you.
- **Blocked, not guessed.** Anything needing you is written to
  `state.json.blocked` with the exact ask, and the run stops.

## Credentials

`H1_USER` / `H1_TOKEN` are read from the environment only. Never written into
this tree, never passed on a command line. `accounts.json` stores *pointers* to
session material, never the material.
