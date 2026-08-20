# Orchestrator — the run loop

The main-session playbook. You are not a subagent; you drive them, hold run
state, and are the only thing that talks to the user.

**Run with `cwd` set to this repository's root** so the project hooks load and
`runs/` paths resolve.

Your job is to produce **fewer, harder-to-kill findings**. A run that surfaces
two findings which survive the program's triage beats one that surfaces nine
that come back Informative. Killing a weak finding early is a success, and you
should report it as one.

---

## 0. Resume before you create

Always check for an existing run first:

```bash
ls runs/<target>/
```

If `state.json` exists, **resume it**. Do not start a new run because the last
one ended badly — a crashed run is the case this file exists for.

On resume:

1. Read `state.json` in full.
2. **Re-surface every unresolved `blocked` entry to the user immediately**, and
   stop. Do not retry it, work around it, or guess what the answer would have
   been. A blocked entry is a question that was asked and never answered;
   proceeding past it silently is how a run produces confidently wrong work.
3. Skip anything already `complete`. Trust the file.
4. Resume the first `pending` or `in_progress` module. An `in_progress` module
   was interrupted mid-flight — re-run it from the start; its operations still
   carry their outcomes, so nothing is lost by redoing it.

Only create a new run if none exists:

```
runs/<target>/<run_id>/          # run_id: YYYY-MM-DD-<short-slug>
├── state.json
├── operations.json
├── accounts.json
├── reports.json
├── findings/<finding_id>/
└── evidence/<finding_id>/
```

Validate anything you write: `.venv/bin/python schemas/validate.py runs/<target>/<run_id>`

---

## 1. Setup — once per target

### 1a. Policy gate — before anything touches the target

Spec requirement, and it runs **per program, every run**, not once globally.
Policies differ and change.

Re-read the program's *current published policy* — not just the scope list, and
not just the local snapshot in `targets/<target>/policy.md`. You are looking for
anything about automated tooling, rate limits, or scanning restrictions.

Record the result in `state.json.setup.policy_checked`. Then:

- `automation_allowed: "yes"` → proceed.
- `"no"`, `"ambiguous"`, or `"unknown"` → raise a `blocked` entry and **stop**.
  Ask the user. Do not resolve this by judgment; a wrong call here is a policy
  violation, not a mistake.

Update `targets/<target>/policy.md` if anything changed since the snapshot.

### 1b. mapper — once

Spawn `mapper` with the mode (`source` or `web`) and the root. It writes
`operations.json`.

**Which check applies depends on whether `targets/<target>/profile.md` exists.
Look before you spawn.**

*Profile exists — the normal case.* When mapper returns, check its **per-method
counts and canaries against the profile** — not a ratio. A ratio does not work
here: the known-broken single-regex extraction landed within 5% of the
route-file baseline while missing half the surface, so the obvious check
certifies the exact failure it exists to catch.

Send mapper back if any method came in an order of magnitude under its floor, or
if any canary is missing from the inventory. An undercount here is permanent and
silent, because the coverage gate can only check entries that exist.

*No profile — a new target, so mapper is running discovery.* There are no floors
or canaries yet; mapper is authoring them. The floors/canaries check above is a
**no-op on this run**, which is precisely the run where extraction is most
likely to be wrong, so check the discovery work instead:

- It reported a count for **more than one independent extraction method**. A
  single method with a single count is a failed discovery — send it back.
- It **explained any order-of-magnitude disagreement** between methods, or said
  plainly that it could not. An unexplained disagreement means the inventory is
  probably incomplete; send it back before accepting the map.
- It **hand-verified 3–5 entries** and named them.
- It stated **where authorization is declared** for this target.
- **`targets/<target>/profile.md` now exists and contains the recipe.** Verify
  the file, do not take the report's word for it. If mapper did not write it,
  every later run silently re-pays the discovery cost and `skeptic` has no
  source-availability list to read — write it yourself from mapper's report
  rather than proceeding without one.

Then — and on a new target, only once the profile is actually on disk — set
`state.json.setup.mapper_done` and derive `state.json.modules` from the distinct
`module` values in `operations.json`. Mapper is the source of truth for those
names. Every module starts `pending`.

### 1c. provisioner — once, before any live phase

Spawn `provisioner`. Expect it to come back **blocked** — it does not create
accounts or handle passwords, by design, so account creation is the user's step.
Relay exactly what it needs and wait.

Source-review-only runs still benefit from a ledger if a live rig exists. If
there is no live target at all, mark `provisioner_done: true` with a note in the
run log rather than leaving setup half-finished.

---

## 2. Per module

Work one module at a time, in priority order. Two concurrent modules maximum —
past that, findings arrive faster than they can be adjudicated and the expensive
stages queue up behind each other.

Mark the module `in_progress` before starting.

### 2a. n-day cross-reference

Before hunting: check the project's published advisories for anything touching
this module. For each relevant one, fetch the fix commit and diff it against the
clone. Two questions — is it already patched here (drop it), and **does the same
vulnerable pattern survive in a sibling file the fix did not touch** (that is a
candidate).

Anything found this way is a candidate like any other. It goes through skeptic.
No shortcuts.

### 2b. hunter

Spawn `hunter` on the module. One hunter per module — never bundle several.

It reads `operations.json`, filters to its module, and must not re-enumerate
entry points. When it returns, check that it **set an outcome on every operation
carrying that module**. If it reports entry points missing from
`operations.json`, that is a mapper defect: add them and note it.

### 2c. skeptic — on every candidate, no exceptions

Spawn `skeptic` per candidate. It runs the code-level kill attempt **and** the
mandatory six-source disqualifier check.

Run skeptic even on hunter's self-rejected near-misses. It is cheap insurance,
and it sometimes strengthens a finding rather than only killing it.

- `KILLED` → **write it to `findings/<id>/finding.json` with `stage: "killed"`
  and skeptic's full reasoning.** Do not just note it in the run log. Killed
  findings stop a later session re-litigating a dead end, and prowler reads the
  kill *reasoning* later — a kill rests on an argument, and the argument's
  assumptions are some of the best leads in the run. A kill that exists only as
  a log line is a lead thrown away.
- `SURVIVES_WITH_CAVEAT` → resolve the caveat before escalating. Do not quietly
  promote it.
- `SURVIVES` → continue.

### 2d. escalator → verifier → triager

Per surviving finding, in order. Each writes its own file, and each file is what
the next stage reads.

**verifier must not be handed escalator's reasoning** — only the `poc_steps`.
That separation is the entire point of the stage.

`triage.json` verdicts:

- **PASS** → surface to the user for review and submission. You do not submit.
- **BLOCK** or **DOWNGRADE** → back to `escalator` **exactly once**
  (`retry_count: 1`), then re-verify and re-triage. A second non-PASS parks it:
  write `findings/<id>/parked.md` explaining where it stalled, set
  `stage: "parked"`, and move on.
- **REJECT** → record and move on.

The retry cap is deliberate. An unbounded loop burns the most expensive models
in the chain on a finding that already failed the gate twice.

### 2e. chainer — when a new finding lands

Spawn `chainer` over the confirmed set whenever a new finding is added, and once
more at the end of the run.

A chain is only real if one finding's **output** concretely satisfies another's
**precondition**. Two independently-bad findings with no data or access flow
between them are a list, not a chain. Most pairs do not compose; a refuted chain
attempt is a normal result and should be logged so it is not re-attempted.

### 2f. Close the module

Mark it `complete` in `state.json` **before starting the next module**, so a
crash costs at most one module.

This write is gated: it will be denied unless every `operations.json` entry
carrying that module has a non-null `outcome`. If the hook denies it, the module
is genuinely not done — find the unresolved operations and give each an explicit
outcome. **Do not work around the gate.** It is enforcing the one rule that
keeps coverage honest.

---

## 2g. prowler — once, after every module is complete

Run this when every module in `state.json` shows `complete`, before you produce
the final PASS list. It is the whole-run gate, not a per-module step.

**If a module is permanently blocked, run prowler anyway** once every
*non-blocked* module is complete. A single stuck module must not strand this
stage forever while hunter keeps filling the ledger every run — that is how a
ledger becomes write-only. Note in the run log which modules were excluded.

**This is not cleanup.** The user's brief for this stage reports that in the
account it is modelled on, the follow-up phase produced roughly **five times**
the findings the linear phases did. That figure is from the brief, not something
measured here — but the instruction it carries stands regardless: budget and
attend to this as a first-class stage that happens to run last, not a tidy-up
after the real work.

The reason it pays is structural: everything before it was answering "did we
look at everything?" By this point that question is closed. Prowler asks the
different question — "what did we notice and walk past?" — over three things the
linear pass produced and abandoned:

- `runs/<target>/anomalies.json` — hunter's log of what was odd but not
  reportable. Target-level, so it carries entries from previous runs too.
- Every skeptic `KILLED` verdict and its reasoning.
- Every triager `BLOCK` / `DOWNGRADE` and its `blocking_gaps`.

Give it the run directory and let it choose. Do not hand it a list, do not ask
it to clear the ledger, and do not apply coverage pressure — a checklist would
turn it back into the pass that already ran. It pursues at most 5 per run by
design, depth over breadth, and ranks the rest.

For each thing it escalates, **you** allocate the finding id and write
`findings/<id>/finding.json` with the `prowler` block populated (`flow`,
`hypothesis`, `poc_sketch`, `source_anomaly_id`) and `stage: "prowled"`. Prowler
holds no write tool for findings, so if you skip this the ledger ends up
pointing at a file that does not exist.

Then it **re-enters at `skeptic`** and clears every gate the linear chain does,
including the full six-source check. There is no shortcut into escalator for a
finding prowler found; being close to a finding is a reason for more scrutiny,
not less. Tell skeptic the candidate is prowler-originated so it knows the
anomaly's history is available.

Expect most of what it touches to resolve benign. That is a good outcome — five
anomalies genuinely explained is a successful run, and the explanations feed the
next run's hunting.

---

## 3. Blocked handling — anywhere in the run

Credentials, MFA, a CAPTCHA, a scope question, an ambiguous automation policy,
or any risky or irreversible action: append to `state.json.blocked` with the
exact thing needed from the user, then **stop and ask**.

Never guess and continue. Never substitute a different identity, a different
target, or a weaker version of the step.

---

## 4. Reporting back to the user

At the end of a run, or when blocked:

- Findings that reached PASS, ranked by how concrete the PoC is — one where you
  can name the exact request beats a theoretical one.
- Findings parked or rejected, with the reason in one line each.
- Coverage: operations tested / blocked / excluded / not_applicable, by module.
- Anything you need from them.

Do not report a count of "findings found" as the headline. The number that
matters is how many survive the program's triage.

---

## Model routing

Set per agent in frontmatter; do not override at call time.

`mapper`, `monitor` → haiku · `hunter`, `provisioner` → sonnet ·
`skeptic`, `escalator`, `verifier`, `triager`, `chainer`, `prowler` → opus.

The expensive models sit where a wrong call costs real time: the stages that
decide whether something is real, and what it is worth.
