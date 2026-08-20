# Agent definitions live in `~/.claude/agents/`

Not here. Claude Code resolves subagents from `.claude/agents/` (user scope or
project root), so markdown in a plain `agents/` directory is never loaded.

Canonical definitions, all user-scoped so they resolve regardless of which
target directory a run executes from:

| Agent | Model | Role |
|---|---|---|
| `mapper` | haiku | Attack-surface inventory → `operations.json` |
| `provisioner` | sonnet | Test accounts + ownership ledger → `accounts.json` |
| `hunter` | sonnet | Traces data flow, produces candidate findings |
| `skeptic` | opus | Tries to kill each candidate (incl. 6-source check) |
| `escalator` | opus | Proves real impact from a realistic attacker position |
| `verifier` | opus | Independent reproduction + evidence audit |
| `triager` | opus | Hostile final gate; PASS/BLOCK/DOWNGRADE/REJECT |
| `chainer` | opus | Finds real compositions between findings |
| `prowler` | opus | Follows what the linear pass noticed but walked past |
| `monitor` | haiku | Post-submission tracking, headless |

The run loop that drives them is `orchestrator.md` at this repository's root.

`agents/` in the system root holds the real files; the entries in `~/.claude/agents/`
are symlinks to them, so they are version-controlled with the system.

`Elastic/agents/_deprecated/` holds the Pass 1 forks of hunter/skeptic/orchestrator. They are
history, not configuration.
