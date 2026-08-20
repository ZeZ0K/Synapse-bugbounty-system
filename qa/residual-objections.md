# Residual objections

Known weaknesses shipped deliberately, from the build-time review rounds. Each
is recorded rather than fixed because the fix costs more than the defect, or
because the right time to fix it is when it actually bites.

Reviewed against `qa/agent-rubric.md` over two adversarial rounds.

---

### mapper runs on haiku, and its job grew

Source mode now carries four scoped extraction commands, path-constant
resolution, a three-shape ES dispatch chain, per-shape floors and canary checks.
That is the most demanding extraction in the pipeline, running on the weakest
model in the routing table.

Kept because mapper's output is checkable: the canaries and floors fail loudly,
and hunter reports operations it finds that mapper missed. **If "Never invent an
entry" is ever violated in practice, promote mapper to sonnet first** — that is
the signal to watch, not the operation count.

### No `id` uniqueness constraint in `operations.schema.json`

JSON Schema cannot express unique-by-key cleanly. Enforced in two other places
instead: mapper's derivable-id rule makes collisions mean a wrong path
extraction, and `tools/set_outcome.py` refuses to run at all when it loads a file
with duplicate ids. That is where a collision would actually do damage, since it
would let one test silently mark two routes covered.

### mapper and provisioner have `Write` but no `Edit`

Appending to `state.json.blocked` therefore means rewriting the whole file, and
`state.schema.json` is `additionalProperties: false`, so a dropped key fails
validation. Low frequency, and validation catches it immediately. Granting
`Edit` to close it would hand a mutation tool to agents that read a shared clone
— a worse trade.

### hunter cannot resolve every ES privilege

mapper predicts `declared_privilege: "unresolved"` for roughly one ES handler in
five (no `client.execute` to follow). hunter is told this is high-value work
rather than a reason to skip the operation, but nothing enforces that it does it.
An unresolved privilege boundary is exactly where authz bugs live, so this is
worth watching in the first few real passes.

### The coverage gate enforces explicitness, not honesty

`gate_module_complete.py` requires every operation to carry an outcome and a
reason. It cannot tell a genuine `not_applicable` from a lazy one. That is the
correct boundary for a mechanical check — it makes the claim explicit, attributed
and reviewable, which is what makes a bad one findable later. Do not try to make
the hook smarter; make the reasons reviewable.

### Duplicate risk is unsolved and unsolvable here

No public-source check can see another researcher's pending private report. A
High-triaged finding in this engagement was closed Duplicate with every public
source clean. `triager` records `duplicate_risk` and it affects submission order,
but nothing eliminates it.

### The build-time review loop is not wired into the system

Agent definitions were reviewed adversarially against the rubric during this
build, but nothing re-runs that review when an agent is edited later. Re-run it
by hand after any substantive agent change — the round-2 findings were all
defects introduced *by* round-1 fixes, which is exactly what an unreviewed edit
produces.

### `claude -p` does not auto-approve Bash, and a blocked agent looks like a working one

The first end-to-end escalator run was refused every `curl` — `--permission-mode
acceptEdits` covers edits, not Bash, and headless has nobody to approve. Fixed by
allowlisting `curl` and read-only `docker` in `.claude/settings.json`.

Worth keeping because of how it surfaced: the agent had a prior rig log showing
the exploit succeeding and still wrote `executed: false`, tagged every blocked
path "BLOCKED, NOT DECLINED", and warned that its own untested prediction "must
not be recorded anywhere as a tested negative." That is the anti-fabrication
requirement holding under exactly the pressure it exists for.

The lesson for operating the system: **check `impact_demonstrated.executed`
before believing an escalation.** A permission-blocked run and a successful one
produce similarly confident prose; only that boolean separates them.

### The anomaly ledger grows forever

`runs/<target>/anomalies.json` accumulates across runs and nothing collects it.
`resolved_benign` entries stay for good. Inflow is bounded by hunter's
comparator rule (only things with nothing to compare against get logged) and
outflow is 5 pursuits per run, so it will grow.

Mitigated rather than solved: `--summary` and `--module` let prowler drill in
instead of pulling everything, `--limit` defaults to 40 and says when it
truncated, and `--outstanding` surfaces the live entries first. **If a real
ledger passes ~500 entries, add archival of old `resolved_benign` rows** — that
is the number to watch, not the file size.

### Prowler's "don't overturn a kill on disagreement alone" is self-adjudicated

Skeptic has a required `six_source_check`; triager has a required
`conceded_privilege_check`. Prowler's equivalent rule has no required artifact —
it is prose. The bounded part is enforced (`prowler_attempts`, and a second
escalation demands `--new-source`), but the *quality* of the new source is not.
If prowler starts producing candidates skeptic kills for the same reason twice,
that is the signal to make it a required field.

---

## Target-generalization pass (targets/, profile.md, general-lessons.md)

Seven blocking objections were raised and all seven were fixed. What shipped
unfixed:

### `six_source_check.github_issues` is a historical key name

Source 1 is "the target's own public issue tracker", which for most SaaS
targets is `not_applicable`. The schema key still says `github_issues`. Renaming
a `required` property would invalidate the one stored artifact that carries a
skeptic block (`runs/elastic/2026-08-11-e2e/findings/f16/finding.json`), so the
description was generalized and the key left alone. Cosmetic; rename it the next
time a schema migration is happening anyway.

### The six-source list is written out three times

`skeptic.md`, `chainer.md` and `targets/elastic/profile.md` each carry the full
list; chainer's differs only in searching for the combination rather than the
halves. This fails rubric criterion 24 (no duplicated instruction). Consolidating
would mean an agent reading another agent's prompt, which is worse. The risk is
drift: **if you edit the source list, edit all three.**

### `prowler` has no `calibration_checked` field

`escalate.schema.json` and `triage.schema.json` both have one, so criterion 17 is
machine-checkable for escalator and triager. Prowler reports which lessons it
consulted in prose, so for prowler the criterion is honour-system. Same shape as
the self-adjudication objection above, and the same trigger to fix it: if prowler
starts choosing pursuits that a lesson would have ruled out, make it a field.

### Frontmatter `gh` is narrowed below what the agents might want

`Bash(gh:*)` was replaced with `Bash(gh api search/issues:*)` and
`Bash(gh api repos:*)` in both `settings.json` and the three agents' frontmatter,
because a blanket `gh` allows `gh issue create` and `gh pr create` — an agent
that files a public GitHub issue about an unreported vulnerability has caused a
disclosure incident, not a permissions error. The cost is that a legitimately
useful read-only call outside those two prefixes (`gh release list`, say) now
prompts. **Prefer adding another narrow prefix over widening to `gh:*`.**
