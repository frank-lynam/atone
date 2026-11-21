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
atone init tst [--store s3://bucket/prefix]     # ~/atone/systems/tst: spec, tailoring, site file, mappings...
atone controls lore                            # the shipped catalog as a lore, word for word (lorewell install it)
atone controls fetch --from DIR                # a newer copy of NIST's files, brought in by hand (optional)
atone discover tst [--ssh user@host]...        # what runs: for drafting system.json
atone collect tst [--ssh user@host]...         # evidence, from the built-in read-only collectors
atone import tst                               # scans in imports/: OpenSCAP natively, others through a mapping
atone import tst --eaveswatch s3://bucket/ew   # logging evidence (AU) from an eaveswatch store
atone evidence tst search keep_logs            # ranked full-text search over the current evidence
atone check tst                                # every control: met, partly, not met, unknown, inherited
atone verify tst                               # drafted narratives: each claim's citation checked
atone fill tst --out package/                  # copies of the workbooks, filled in, with what changed and why
atone connections tst                          # the intentional connections each config file defines
atone draw tst --out package/                  # the architecture: configured, seen, allowed, documented (draw.io)
atone oscal tst --out package/oscal/           # the SSP, assessment results and POA&M as OSCAL 1.1.2
atone plan tst                                 # the plan (PLAN.md)
atone report tst --out package/ [--conmon]     # report.html
```

The first run on a real system, step by step (offline, no sudo): [docs/RUNBOOK.md](docs/RUNBOOK.md).

## A system's folder

`~/atone/systems/NAME/` (`$ATONE_HOME`):

| File | What it is | Whose |
|---|---|---|
| `system.json` | the system spec: hosts, components, the config files that define their connections, what to collect | drafted by the agent, reviewed by the ISSE |
| `tailoring.json` | the baseline, controls added and removed, parameter values, inherited and shared controls | a person's |
| `site.json` | commands atone doesn't have, and extra redaction patterns; evidence from them is marked as such | a person's, never the agent's |
| `mappings/*.json` | control mappings: the evidence that bears on each control, checks as data, what a person must supply (`starter.json` to begin from) | drafted by the agent, owned by the ISSE |
| `imports/` | scanner exports, and `TOOL.mapping.json` for any that isn't OpenSCAP | a person's (the exports), the agent's (the mappings) |
| `workbooks/` | the working documents, and `NAME.mapping.json` for each | the customer's (the files) |
| `documented.json` | the flows the SSP describes | drafted from the SSP, reviewed |
| `drafts/` | narratives (claims with citations), `verified/` (what `atone verify` kept), `poam-schedule.json`, `examples/` | the agent's, approved by people |
| `runs/` | evidence indexes, check results, drawings, fills | atone's |
| `PLAN.md` | the plan, worked out from all of the above | atone's |

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
