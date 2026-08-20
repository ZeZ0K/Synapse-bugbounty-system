# Agent definition rubric

Used by the build-time review loop. Every new or changed agent under
`~/.claude/agents/` is scored against this before it ships. A reviewer returns a
score per criterion plus **blocking objections**; the author revises and
resubmits, up to **3 rounds**, after which it ships with residual objections
recorded in `qa/residual-objections.md`.

A criterion marked **BLOCKING** cannot be waived by the round cap.

---

## A. Mechanical correctness — BLOCKING

1. Frontmatter parses: `name`, `description`, `tools`, `model`.
2. `name` matches the filename and is what `orchestrator.md` actually calls.
3. `description` states *when to use it*, not just what it does. Claude Code
   routes on this string.
4. Every tool in `tools:` exists and is installed. `ast-grep` was listed in
   three agents for weeks and is not installed — verify, don't assume.
5. `model:` matches the routing table in `agents/README.md`.
6. Read-only agents cannot mutate: no `Write`/`Edit`, and Bash restricted to an
   explicit read-only allowlist. `hunter`, `skeptic` and `chainer` read a shared
   clone that other passes depend on.

## B. Anti-fabrication — BLOCKING

7. Every artifact the agent cites must name the real tool invocation that
   produced it. Paraphrase is not attribution.
8. The agent is told explicitly: **never** generate proof, reconstruct terminal
   output, or describe a result it did not observe.
9. Untraceable evidence is **dropped**, not retained with a caveat. "Keep it
   just in case" is the failure this exists to prevent.
10. Any claim the agent cannot reproduce from its own stated steps is removed
    from the finding.

## C. Coverage integrity — BLOCKING

11. Every operation the agent touches gets an explicit `outcome`
    (`tested` / `blocked` / `excluded` / `not_applicable`). None are dropped.
12. `blocked`, `excluded` and `not_applicable` each carry a reason.
13. The agent never marks a module complete itself — that write is gated, and
    attempting it without full coverage will be denied.

## D. Stop-and-ask discipline — BLOCKING

14. Credentials, MFA, CAPTCHA, scope ambiguity, or any risky action → append to
    `state.json.blocked` with the exact ask, then **stop**. Never guess past it.
15. The agent never widens scope, ignores a program's automation policy, or
    proceeds on an unresolved scope question to save a finding.
16. Prohibited actions are named where relevant: the agent does not create
    accounts, enter passwords, solve CAPTCHAs, or perform destructive operations
    on data it does not own.

## E. Calibration

17. `escalator`, `triager` and `prowler` read **both** `memory/general-lessons.md`
    (always) and `memory/closed-reports/<target>/` (may be empty on a new
    target) before deciding, and record which of each they consulted. An empty
    target corpus must not read as a reason to skip the check.
18. The agent encodes actual observed failure modes rather than generic security
    advice. The four in `memory/general-lessons.md`, each still traceable to the
    closed report that produced it:
    - admin-trusted-entity preconditions are near-worthless (lesson 1)
    - code-level cleanliness ≠ payability (lesson 2)
    - public prior-art checks cannot see private duplicates (lesson 3)
    - the conservative CVSS vector is the accurate one (lesson 4)
19. **Target-specific content lives in `targets/<target>/`, not in the agent.**
    An agent naming one target's framework, repo, routes, file paths or vocabulary
    is a defect: it silently mis-instructs every other target. The agent carries
    the procedure and the general principle; the target's answer to it belongs in
    `profile.md` or `policy.md`. A generalization that replaces a specific
    instruction with vaguer prose is the opposite defect and fails this too —
    "look for common vulnerability patterns" grips nothing.

## F. Judgment quality

20. The agent is told what would make it *wrong*, not only what to do. An agent
    that cannot fail a check will not perform it.
21. Severity guidance names CVSS 3.1 specifics: C/I/A are None/Low/High only;
    Scope:Changed requires a genuinely different security authority.
22. The agent cannot rescue a finding by substituting a different bug, widening
    the attacker's assumed privilege, or inventing a new angle.
23. Output format is machine-checkable where a later stage or hook depends on it
    — verdicts are written to the specified JSON file, not left as prose.

## G. Economy

24. No instruction duplicated from another agent's job. Each stage does one
    thing; overlap wastes the strongest models on repeat work.
25. Length is justified. Sub-agents pay for every token of their prompt on
    every invocation.

---

## Scoring

Per criterion: **pass / weak / fail**. Any BLOCKING `fail` blocks the ship.
Three or more `weak` in one section counts as a section failure and must be
addressed.

The reviewer's job is to find reasons the agent will produce a bad finding, not
to confirm it reads well. A review that returns no objections on round 1 should
itself be treated as suspect.
