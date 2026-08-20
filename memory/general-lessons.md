# General lessons — cross-program, always applicable

These are patterns about how bounty programs triage, not facts about any one
target. **Read these on every run, including the first run against a brand-new
target whose `closed-reports/<target>/` is still empty.** An empty target corpus
means you have no target-specific calibration yet; it does not mean these stop
applying.

The evidence for each is in `closed-reports/<target>/`. Those files are the
stories; these are the rules the stories produced. When one of these applies,
cite it by name and, if the target corpus has a matching case, cite that too.

---

## 1. Pre-established trust is worth approximately nothing

*Evidence: `closed-reports/elastic/elastic-01-reindex-ssrf-informative.md` — SSRF via redirect, fully live-validated, closed Informative "operates as documented" because the exploit needed an admin-allowlisted host.*

**A finding whose exploit path requires the target to already be an
admin-configured trusted entity is worth approximately nothing to almost any
program.** Allowlisted hosts, preconfigured connectors, admin-registered
integrations, an operator-established trust relationship — if an administrator
had to deliberately grant the position the attack starts from, the program will
almost always call the outcome intended.

**Gate on this, do not weigh it.** Before spending effort on impact, state the
attacker's starting position in one sentence and ask whether an administrator
had to set it up. If the answer is yes, that is a disqualifier to argue against
explicitly, not a discount to apply at the end.

The tell is a PoC whose setup steps are longer than its exploit steps.

## 2. Code-level cleanliness says nothing about payability

*Evidence: `closed-reports/elastic/elastic-04-enrich-exfil-accepted-by-design.md` — a 2019 upstream issue had explicitly accepted that exact exposure by name and pre-approved the API the PoC used. Never filed.*

**A technically flawless, fully reproduced, live-validated finding can still be
a maintainer-accepted, years-old known issue.** Being right about the code and
being right about the report are different claims, and the first does not
support the second.

This is the entire reason the external disqualifier check exists, for any
target. Run it even when the code analysis is airtight — *especially* then,
because a clean trace is exactly what makes a researcher skip it.

## 3. Duplicate risk is weightable, never solvable

*Evidence: `closed-reports/elastic/elastic-06-fleet-secrets-leak-duplicate.md` — triaged High, then closed Duplicate with every public source clean.*

**No public-source check can see another researcher's pending private report.**
A well-known bug-class shape in a heavily-hunted area of a popular target
carries duplicate risk that no amount of searching will resolve.

Treat this as a probability attached to the finding, not a question with an
answer. It is a reason to prefer the less-obvious area and to submit promptly
when you do find something in a crowded one. It is never a reason to claim a
finding is novel because your search came back empty.

## 4. The conservative CVSS vector is usually the correct one

*Evidence: `closed-reports/elastic/elastic-15-synthetics-cross-space-delete-triaged-high.md` — scored 8.1 Scope:Unchanged over an available 9.6 Scope:Changed argument; the program independently landed on 8.1.*

**Reach for `Scope:Changed` only when impact crosses into a genuinely different
security authority** — a different trust domain, a different account boundary,
a different system that does its own authorization. "The consequences are
broader" is not a scope change; broad consequences inside one authority are
just a higher impact metric.

The same restraint applies to C/I/A. Claim `High` where a metric is genuinely
high, `Low` where the disclosure is partial or the modification bounded, and
`None` where nothing in that dimension moves. Programs score conservatively and
a defensible vector that matches theirs builds credibility across reports; an
inflated one invites a downgrade that costs more than the points it sought.

A finding argued at the severity it actually merits survives triage. One argued
a band too high gets corrected, and the correction is remembered.
