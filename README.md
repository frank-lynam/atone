# atone

Keeps a system's authorization (ATO) true to the system.

atone is an **expert pack for [hobkin](https://github.com/frank-lynam/hobkin)**: install it, and a hobkin becomes a
compliance engineer's apprentice. It's also a deterministic toolkit anyone can run without an agent. It collects
evidence from the real system, checks NIST SP 800-53 controls against it, verifies every claim a drafted narrative
cites, fills in the customer's own workbooks, and draws the architecture as it really is (draw.io): the
connections its configuration intends, the ones seen, the ones rules allow and the ones the SSP documents, with
where they disagree called out. People decide; atone drafts and proves. It never declares
anything compliant. The design is in [DESIGN.md](DESIGN.md).

Standard library only (plus [lorewell](https://github.com/frank-lynam/lorewell) for lores), one file of code, no
listening ports, and **no internet needed**: NIST's 800-53 catalog and baselines (OSCAL) and guidance (SP 800-37,
800-18, 800-137 as text) ship in the package as plain text, each with its source and SHA-256 (`atone sources`).
No sudo either: it reads what the account can, and says so where it can't. Any system, any customer: nothing about
one product is in it.

**Security first.** Before the compliance documents comes **atonement**: the hobkin studies the system the way a
capable, automated attacker would, builds an attack graph from the evidence (each step cited, or flagged as
assumed), and `atone attack` works out, for each attacker profile and mission effect, the cheapest way in, the
controls in the way, and the fewest lock-downs that cut every path. The bar defaults high (AI attackers assumed):
every path crosses two controls and every step on it is detected. MITRE ATT&CK, CAPEC and CWE, and the mappings from
ATT&CK to 800-53 and AWS, ship in the package. The design: DESIGN.md 4a.

## With a hobkin

```sh
pip install atone hobkin
hobkin URL MODEL KEY --chore atone --set system=tst --set store=s3://bucket/atone --chat
```

The hobkin sets the system up, makes **the plan** (every piece of the effort, and who can do it: the hobkin, access
it needs, or a person), asks for what only people can give (the working documents, the inherited-controls matrix,
example narratives, access), builds the lores it needs, and keeps to a cadence: collecting daily, checking weekly,
and the continuous-monitoring package monthly. Its watch is `atone due SYSTEM`, which prints nothing when nothing's
due, so a quiet day costs no model calls. Its skills (atone-become-expert, -system-spec, -mappings, -narratives,
-drift, -conmon) are copied to that agent only.

## By hand

```sh
atone init tst [--store s3://bucket/prefix] [--remote URL]   # the codex: ~/atone/systems/tst
atone init tst --from URL                      # or clone it on another machine
atone controls lore                            # the shipped catalog as a lore, word for word (lorewell install it)
atone controls fetch --from DIR                # a newer copy of NIST's files, brought in by hand (optional)
atone discover tst [--ssh user@host]...        # what runs: for drafting system.json
atone collect tst [--ssh user@host]...         # evidence, from the built-in read-only collectors
atone import tst                               # scans in imports/: OpenSCAP natively, others through a mapping
atone import tst --eaveswatch s3://bucket/ew   # logging evidence (AU) from an eaveswatch store
atone evidence tst search keep_logs            # ranked full-text search over the current evidence
atone doc SSP.docx --out ssp.txt               # a Word or Excel document as text: headings, lists, tables
atone attack tst [--paths 5]                   # atonement: attack paths, the controls in the way, what to lock down
atone attack tst --close STEP                  # what if that step (or lock-down) were blocked?
atone attack tst --controls                    # how much each control carries, and what its failing would open
atone attack tst --steps                       # each step's claim beside what it cites (--derived: atone's own)
atone attack technique T1552.005               # the attacker library: a technique, its mitigations, 800-53, AWS
atone attack search instance metadata          # ...or search it (atone attack lore: as a lore)
atone check tst                                # every control: met, partly, not met, unknown, inherited
atone verify tst                               # drafted narratives: each claim's citation checked
atone fill tst --out package/                  # copies of the workbooks, filled in, with what changed and why
atone connections tst                          # the intentional connections each config file defines
atone draw tst --out package/                  # the architecture: configured, seen, allowed, documented (draw.io)
                                               #   with the account's security groups reviewed (and in the report)
atone oscal tst --out package/oscal/           # the SSP, assessment results and POA&M as OSCAL 1.1.2
atone plan tst                                 # the plan (PLAN.md)
atone report tst --out package/ [--conmon]     # report.html
atone commit tst "why" [--control AC-2]        # commit your own edits to the codex, guarded
atone review tst AC-2 --by NAME                # a person reviews a statement
atone decide tst risk-acceptance "why" --by NAME --control RA-5   # a person decides
atone package tst --tag conmon-2026-11         # generate everything into packages/TAG, commit and tag
atone history tst --control AC-2               # what changed, who decided, when
```

The first run on a real system, step by step (offline, no sudo): [docs/RUNBOOK.md](docs/RUNBOOK.md).

## The codex

Each system is a git repository, **the codex** (`~/atone/systems/NAME/`, `$ATONE_HOME`): the single source of truth,
and its history is the system's security history. atone commits what it changes, with trailers saying what and why
(`atone history NAME [--control AC-2] [--since "1 month ago"]`); a pre-commit guard refuses anything secret. Drafts go
on branches, merging is approval, and each package is a tag.

| Path | What it is | Whose |
|---|---|---|
| `system.json` | the system spec: hosts, components, the config files that define their connections, what to collect | drafted by the agent, reviewed by the ISSE |
| `interfaces.json` | the flows the SSP describes | drafted from the SSP, reviewed |
| `tailoring.json` | the baseline, controls added and removed, parameter values, inherited and shared controls | a person's |
| `site.json` | commands atone doesn't have, and extra redaction patterns; evidence from them is marked as such | a person's, never the agent's |
| `mappings/controls/` | the evidence that bears on each control, checks as data (`starter.json` to begin from) | drafted by the agent, owned by the ISSE |
| `mappings/scanners/`, `mappings/workbooks/` | how to read each scanner export and fill each working document | drafted by the agent, confirmed by the ISSE |
| `attack/` | the attack graph: mission effects and other conditions, attacker profiles, `steps/` (each cited, or flagged as assumed) | drafted by the hobkin, effects refined by the team |
| `risks/` | lock-downs: the exact change, and a check that keeps proving it's in place | proposed by the hobkin, made by people (or accepted) |
| `engagement.json` | the rules of engagement: the replicas it may test, how deep, the bar for atonement | agreed with the hobkin (`atone decide ... engagement`) |
| `evidence/HOST/KIND/` | redacted evidence at stable paths, committed only when it changes | atone's |
| `controls/` | each control's status, findings and implementation statement (drafted, verified, reviewed) | atone's and the reviewers' |
| `poam/` | the POA&M items, opened as findings appear | atone's; closed by decisions |
| `decisions/` | risk acceptances, deviations, false positives, the approved POA&M schedule | people's (`atone decide`) |
| `workbooks/` | the customer's working documents | the customer's |
| `packages/TAG/` | what was delivered: workbooks, diagrams, OSCAL, the report | atone's (`atone package`) |
| `drafts/` | narratives (claims with citations), the proposed schedule, `examples/` | the agent's |
| `imports/`, `runs/`, `PLAN.md` | scanner exports to import, local caches and indexes, the plan (not committed) | local |

## The rules it keeps

- **Evidence is never written by a model.** Every record says where it came from, when, and its content's SHA-256;
  it's redacted (keys, tokens, passwords) before it's stored; credential files are never read.
- **No command runs from a spec or a mapping.** Specs name collectors from a fixed menu; checks are patterns,
  comparisons and counts run by plain code.
- **No citation, no claim.** `atone verify` keeps a claim only if its evidence is current, matches its hash and says
  what the claim quotes.
- **The customer's workbooks are theirs.** A copy, only cell values changed (styles, drop-downs, formulas and every
  other part kept); status values from their drop-downs; what's filled in is kept, and disagreements are flagged.

## Tests

`python3 tests/test_atone.py` (fixtures only: no AWS, no network, no model).
