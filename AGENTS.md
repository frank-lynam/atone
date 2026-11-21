# Working on atone

DESIGN.md is the design; read the section you're working on. The rules that hold everywhere:

- **One file of code, standard library only:** `atone/__init__.py`, Python 3.9+ (`atone/__main__.py` only runs it).
  lorewell is the one dependency (lores); hobkin is the agent atone is a pack for, never imported. `grep -n '^# ----'
  atone/__init__.py` lists its sections; new code goes in the section it belongs to, and the map stays in step.
- **No internet where it runs.** Everything it needs ships in the package as plain text: `atone/data/` (NIST's
  OSCAL catalog and baselines, guidance as text), each file's source and SHA-256 in `atone/data/lock.json`. Nothing
  ever writes there (a newer copy goes to ~/atone/sources); a test checks every hash.
- **The toolkit never calls a model.** Collection, imports, checks, citation checks, workbooks, diagrams and OSCAL
  are deterministic code; the agent drafts, by running the toolkit and reading what it says.
- **Evidence is never written by a model,** and every record says where it came from, when, and its content's
  SHA-256. Nothing is stored before the redaction floor (`REDACT`) has run; collectors never read credential files
  (`DENY_PATHS`, `DENY_NAMES`). Neither is configurable away.
- **No command runs from a spec or mapping.** Specs name collectors from the built-in menu (`COLLECTORS`); checks are
  data (patterns, comparisons, counts) run by plain code. A command atone doesn't have lives in a person's site file,
  and evidence from one says so.
- **Being right over being complete.** Nothing unverified is worded as fact; `verify` drops a claim whose citation
  doesn't hold; reports state their coverage.
- **Customer- and system-agnostic.** Nothing about one product (PeopleSoft or any other), customer, scanner layout or
  template is in the code: they arrive as reviewed data at run time.
- **Workbooks are the customer's:** write into a copy, change only cell values, keep everything else byte for byte
  where it can be. Status values come from the workbook, never from atone.
- **No auto-updates or migrations.**
- **Tests:** `python3 tests/test_atone.py` (fixtures only: no AWS, no network, no model). Add a check for what you
  change; run what you changed, CI runs the rest.
- GitHub: `frank-lynam/atone` (remote `origin` uses the `github-atone` SSH alias). Commit and push finished work.
  PyPI name `atone`: don't publish without asking.
