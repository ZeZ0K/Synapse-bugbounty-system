# Calibration corpus

Ground truth on how a specific program actually triages, drawn from its closed
reports. `escalator`, `triager` and `prowler` read the corpus for the target
they are working before making a call.

**One directory per target**: `closed-reports/<target>/`. A brand-new target
starts empty — that is expected, not broken. It means there is no
target-specific calibration yet, so the cross-program rules in
[`../general-lessons.md`](../general-lessons.md) carry the whole weight. Those
apply on every run regardless of what is in here.

**The Informative and Duplicate closures are the valuable half.** Paid findings
tell you the system worked; the closed ones are the only real evidence of where
the reasoning was too generous about attacker privilege — which is precisely
the failure mode `triager` exists to catch.

When a case in here generalizes past its own program, promote the rule into
`general-lessons.md` and leave the case here as its evidence. The four Elastic
files are the evidence behind all four current general lessons.

## Format

One file per closed report, in that target's directory. Frontmatter:

```yaml
report_id: H1 #3684474        # or LOCAL-<n> if never filed
program: elastic
finding_ref: elastic#1        # tracker number, if any
submitted: 2026-07-19
closed: 2026-07-19
resolution: informative | duplicate | resolved | not_applicable | never_filed
severity_claimed: high
severity_assigned: none
closure_root_cause: <one line — the actual reason, not the label>
```

Body: what was claimed, what the program said, and **the transferable lesson**.
Write the lesson as a rule a future triager can apply to a different finding.

## Bulk import

Filed reports can be imported from the HackerOne API rather than transcribed:

```bash
H1_USER=<handle> H1_TOKEN=<token> .venv/bin/python tools/import_h1_closed.py --program <target>
```

Imported files land in `closed-reports/<program>/`, the same directory the
agents read. Without `--program`, every program on the account is imported,
each into its own subdirectory.

Reads the token from the environment. It is never written into this tree.
