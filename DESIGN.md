# atone: design

*A draft for discussion, written for the ISSE first. Nothing here is built yet.*

atone keeps a system's authorization true to the system. It is an **expert pack for hobkin**: install it, and a
hobkin becomes a compliance engineer's apprentice, with a deterministic toolkit, prepared knowledge, and the skills
to use them. Together they gather evidence from the real system, draft control narratives from that evidence (every
claim cited), fill in the customer's own workbooks, draw the architecture as it really is, and say where the
paperwork and the system have drifted apart. People decide; atone drafts and proves. It never declares anything
compliant.

It works on any system and for any customer. Nothing about PeopleSoft, or any other product, is in it.

## 1. Principles

- **Code is the source of truth; the agent is the apprentice.** Evidence collection, imports, checks, the workbook
  round trip, diagrams and OSCAL are plain, deterministic code: the atone toolkit. It never calls a model, an ISSE
  can run it without any agent, and an assessor can re-run anything it did. The hobkin does the judgement work
  (drafting specs, mappings and narratives, investigating drift) by running the toolkit and reading what it says.
- **Evidence is never written by a model.** Every piece of evidence is something the toolkit collected or imported:
  a command's output, a file, a scanner export, an API response. Each records where it came from, when, and a hash
  of its content, and can be collected again on demand.
- **No citation, no claim, and code checks the citations.** Every statement in a drafted narrative cites evidence,
  with the words it relies on quoted. The toolkit verifies each citation (the evidence exists, is current, and says
  what the quote says) before a narrative goes in a workbook. Anything without evidence is marked *needs a person*.
- **Being right matters more than being complete.** Assessors mostly take what the package says on trust, so a wrong
  statement does more harm than a missing one. When in doubt, atone says less and says why: every report states its
  coverage (what's verified, what's drafted from a person's word, what's open), and nothing unverified is ever
  worded as fact.
- **Knowledge comes from sources you can trace.** The control text is compiled exactly from NIST's own files, never
  paraphrased by a model. Guidance in prose is built into lores from documents listed in a manifest, and reviewed.
  The customer's own documents are built into a private lore on their machines, and never leave.
- **Knowledge about a system is data, reviewed by a person.** What a system is, how to read a scanner's export, a
  workbook's layout, and which evidence proves which control are files. The agent drafts them; the ISSE reviews and
  edits them; the toolkit runs them.
- **Customer-agnostic by construction.** Nothing customer-specific is ever in the pack: a customer's systems,
  scanners, templates and documents all arrive as data on their side.
- **People sign.** The ISSO owns the package. atone's outputs are drafts with their evidence attached, and a diff of
  what changed since the last review.
- **Nothing leaves a host unredacted.** A redaction floor (keys, tokens, passwords, credentials in URLs), always on,
  applied before evidence is stored. Collectors never read credential files.
- **Austere.** Standard library only, no listening ports, the AWS CLI where AWS is involved. hobkin, lorewell and
  eaveswatch are the same.

## 2. Architecture

```
                    ┌──────────────────────── the atone pack (pip install atone) ───────────────────────┐
                    │                                                                                    │
   people ───────►  │  skills        how to: become the expert for a system, draft a system spec, draft  │
  (ISSE, ISSO)      │                mappings, write cited narratives, investigate drift, prepare ConMon │
                    │  knowledge     a source manifest; the exact compiler for NIST's OSCAL              │
                    │  mappings      a starter library of control mappings (generic Linux, AWS)          │
                    │  a chore       the cadence: collect daily, run weekly, ConMon monthly              │
                    │  the toolkit   atone collect | import | check | verify | fill | draw | diff | oscal │
                    └────────────────────────────────────────────────────────────────────────────────────┘
                              ▲ installed into                       ▲ runs it, like any command
                              │                                      │
                    ┌─────────┴──────────────────────────────────────┴──────────────────────────────────┐
                    │  hobkin: the agent. Persistent memory, the field lore, brownies on a cheaper model, │
                    │  safe mode, approval gates, stash between machines, hearthboard for "needs a person"│
                    └────────────────────────────────────────────────────────────────────────────────────┘
                              │ builds and reads lores with                 │ reads logs and flows from
                              ▼                                             ▼
                          lorewell                                      eaveswatch (where it runs)
```

The only interface between hobkin and atone is the command line and files. hobkin runs `atone check` the way it
runs anything else, so every step the agent takes is in its timeline, and atone depends on no hobkin internals.

### 2.1 Expert packs: a hobkin mechanism

For atone to install into hobkin, hobkin gains one small, generic feature: it finds **chores, skills and lores in
installed Python packages** (through a standard entry point, `hobkin.packs`), not only in hobkin-chores. A pack
declares what it brings: chores, skill folders, a lore manifest, tools.

atone is the first expert pack. The mechanism is for anyone's:

- a customer can build their own, privately (their deploy tooling, their runbooks, their product's lore) and
  install it into hobkin the same way, without it ever coming near our repos;
- the next pack could be anything: a Kubernetes operator, a database administrator, a release manager.

## 3. Knowledge: three kinds, handled three ways

| | What | How it becomes a lore | Trust |
|---|---|---|---|
| **Authoritative** | NIST SP 800-53 Rev 5 and its baselines (OSCAL JSON); the SCAP Security Guide's rule-to-control references | atone's own **exact compiler**: no model; word for word | what an assessor cites |
| **Guidance** | SP 800-37 (RMF), 800-53A (assessment), 800-171, FedRAMP guides, DISA STIGs for whatever the system runs | `lorewell build` (model-distilled) then `lorewell review` by the ISSE | reference: help, never cited as the control |
| **The customer's** | their policies and procedures, interconnection agreements, past SSPs and their ISSO's comments, tailoring decisions, style | `lorewell build` on their machine, into a private lore | theirs: stays in their environment |

The pack ships a **source manifest**: each public document's location, version and checksum, and which kind it is.
A skill, *become the expert for this system*, reads the system spec and the manifest, works out what's needed (a
Kubernetes system gets the Kubernetes STIG, not the Oracle one), and builds those lores. When NIST publishes an
update, the lore is rebuilt and the diff shown. The compiled authoritative lores may also ship in the pack for
convenience, but the manifest is what proves where every word came from.

What the agent learns about the system and the people along the way (the customer's voice, its quirks, who owns
what) goes in hobkin's field lore. The control mappings do not: they're files in git, reviewed line by line (§4.4).

## 4. The toolkit

### 4.1 Controls: any 800-53 baseline

The catalog and a baseline come from NIST's OSCAL files; the customer's **tailoring** from a small file of theirs:
controls added or removed, parameter values (a session timeout of 15 minutes, logs kept 90 days), and which
controls are **inherited** (from AWS GovCloud, an enterprise service) or **shared**. Inherited controls are drafted
as inherited, pointing at the provider's responsibility matrix, never as if the customer implemented them. There
almost always are some, so if no responsibility matrix is provided, asking for it is one of the first things on the
plan (§5).

### 4.2 The system spec: what the system is

`atone discover` looks at each host: processes, listening ports and connections (through /proc), packages,
services, users and groups, and which configuration files exist. It lists config files; it doesn't read them out.
The agent turns that into a **system spec** (with its skill for it):

- the components (a web tier, an app server, a batch scheduler, a database) and the hosts that run them;
- for each component, the config files that define its connections, and how to read them (a pattern, an XML path,
  a key);
- the evidence worth collecting from it.

The ISSE reviews the spec. Every system gets its own; PeopleSoft's will just be the first example.

### 4.3 Evidence: collected and imported

**Collected,** through a fixed menu of collectors, each read-only and each built in:

| Collector | What it gathers |
|---|---|
| `file` | files named in the spec (never ones that look like credentials) |
| `accounts` | users, groups, sudoers, last logins |
| `packages` | installed packages and versions |
| `services` | services, their state, and the account each runs as |
| `listeners`, `flows` | ports listened on, and connections seen over time |
| `firewall` | host firewall rules |
| `aws` | security groups and the network interfaces that use them, instances, subnets, route tables, network ACLs, load balancers (listeners, target groups, targets), RDS, CloudTrail and Config status, KMS, IAM summary, in each of the spec's regions (`describe`/`get`/`list` calls only) |
| `certs` | certificates on listeners: issuer, expiry, protocols |

A spec can only *name* collectors from this menu; it can't add a command. A customer who needs a command atone
doesn't have puts it in their **site file**, written by a person, never by the agent, and every run says which
evidence came from site commands.

**Imported,** from scanner results dropped into a folder:

- **OpenSCAP** (XCCDF / ARF), read natively: SCAP Security Guide rules carry their 800-53 references, so each result
  maps straight to controls.
- **Everything else** (Rapid7, Trellix, the next one): CSV or XML exports, read through a **scanner mapping file**
  (which column is the host, the finding, the severity, the CVE, the first-seen date). The agent drafts it from one
  sample export; the ISSE confirms it.
- **eaveswatch**, where it runs: its log collection, review, alerting and retention are evidence for the AU family,
  and its flows feed the architecture.

Each piece of evidence is a record (its id, collector or importer, host, time, source, the SHA-256 of its content,
and the content, redacted) in a store, a folder or S3, laid out like eaveswatch's:

```
PREFIX/system=NAME/kind=accounts/dt=2026-11-21/host=HOST/STAMP_RAND.json.gz
```

`atone search` finds evidence by text (a lorewell index of each run), so a drafter pulls what bears on one control
rather than loading thousands of records.

### 4.4 Control mappings: the ISSE's asset

For each control (or enhancement), a mapping says:

- which evidence bears on it (by kind, component and content);
- the **checks**: what to look for, and what counts as satisfied, partly satisfied, or not (a parameter compared, a
  rule's pass or fail, a list that must be empty);
- what a person must supply (a policy, a procedure), which atone tracks but can't collect.

Checks are data run by plain code (patterns, comparisons and counts, never code from a file). The agent drafts
mappings from the control's text and the system spec; the ISSE owns them, in git. Most of a mapping is generic
(Linux accounts, AWS logging), so it carries from system to system; the pack's **starter library** holds those, and
only the system-specific parts live with the system. **Each engagement makes the next one faster: the mappings are
the asset.**

### 4.5 Narratives: drafted by the agent, verified by code

For each control, the agent drafts the implementation statement (with its skill, and brownies on the cheaper model
for the hundreds of them) from the check results, the evidence, and the customer's lore for voice and style (it
asks for examples of statements the ISSO accepted, and any sent back, at the start: §5). It writes it as claims, each citing evidence ids and quoting the words it relies on. `atone verify` checks every
citation: the evidence exists, it's from the current run, and it says what the quote says. A claim that fails is
dropped and the control goes on the *needs a person* list with what's missing. Inherited controls are drafted as
inherited.

### 4.6 The customer's workbooks

Most of an authorization package is Excel: the SSP control matrix, the POA&M, inventories, the responsibility
matrix. `atone fill` fills them in without wrecking them:

- the working documents are given to the hobkin at run time, blank or partly done; a **template mapping file** per
  workbook says what each sheet and column is (control id, status, statement, responsible role, POA&M fields); the
  agent drafts it from the workbook itself, the ISSE confirms it;
- **status values come from the workbook,** never from atone: every ISSM is a little different, so atone reads the
  allowed values from the workbook (its data validation lists, or a legend sheet) and uses only those; what's already
  filled in is kept unless the evidence contradicts it, and then it's flagged, not overwritten;
- atone writes into a **copy**, changing only cell values: styles, merged cells, data validation, formulas and
  hidden sheets stay as they are (an .xlsx is zipped XML: edit the cells, never rebuild the file);
- each filled cell's evidence goes in an added column or a companion sheet, and every run writes a **diff report**:
  what changed, why, and what proves it.

### 4.7 Architecture: configured, seen, allowed, documented

`atone draw` builds one graph of the system from four layers:

1. **Configured:** the intentional connections. The config files the system spec names are read for what each
   program connects to and listens on, by generic readers that know no product (URLs and a scheme's usual port, JDBC
   and Oracle TNS strings, host and port settings near each other, listen directives), plus patterns in the system
   spec (regexes, drafted by the agent, reviewed) for formats they miss. Each path keeps its file, line and evidence.
   `atone connections` lists what was found.
2. **Seen:** connections observed (the `flows` collector, every snapshot in the freshness window; eaveswatch;
   VPC Flow Logs where they're on).
3. **Allowed:** the AWS security groups, in (ranges, IPv6 ranges, prefix lists, other groups) and out (egress;
   a blanket allow-all lets traffic out but explains nothing), for instances, load balancers and RDS databases.
   Whether a rule open to the world is actually reachable comes from the routes (a subnet routed to an internet
   gateway) and public addresses. An internet-facing load balancer's listeners and its target groups are
   configuration: they're the intended way in. (Network ACLs are collected, not yet evaluated; host firewall rules
   likewise.)
4. **Documented:** the boundary and data flows the SSP describes (interfaces.json in the codex, reviewed).

| Class | Means |
|---|---|
| unexpected | seen, but no config, rule or document explains it (first to look at) |
| blocked | configured, but no rule allows it: it would fail |
| undocumented | configured or seen, but not in the SSP |
| unused | allowed by a rule, but nothing configures or uses it: attack surface, with the rule to tighten |
| idle | configured but not seen in the window: intended, just quiet |
| documented only | in the SSP, but neither configured nor seen |
| normal | configured (or documented, or allowed), and seen |

**The security groups themselves are reviewed,** account-wide: rules open to the world (all traffic, admin and
database ports named, any port beyond the system's `public_ports`), each with whether it's reachable from the
internet now; groups attached to nothing; rules naming a group that doesn't exist; a default group that allows
anything. The review is a check type (`security_groups`) the mappings use (SC-7, CM-7), and a table in the report.

The authorization boundary is computed, not drawn by hand, so interconnections can't hide outside it. The diagrams
are first for the engineering team: accurate and useful for understanding the system, not just for the package.
Output is **draw.io** files (editable, and readable by most tools) plus SVG, laid out by tier, regenerated every run
with a diff. They feed SC-7, AC-4, CA-3, CM-7, CM-8 and the SSP's architecture sections.

### 4.8 Drift and the POA&M

- **Drift:** new evidence that contradicts a narrative or the documented architecture is flagged before an assessor
  finds it: what the paperwork says, what the system shows, and the evidence. The agent investigates and drafts the
  fix (to the system, or to the paperwork) for a person to choose.
- **The POA&M:** failed checks and scanner findings become rows; closed findings are marked closed with the evidence
  that closed them. Nothing is deleted. The hobkin **proposes a realistic schedule** for each item, with margin for
  the ISSE and the DevOps team to review and do the work (their capacity, dependencies between items, what needs a
  change window). There's rarely a hard deadline; when there is one, the schedule is something the hobkin and the
  team iterate on, and the hobkin says plainly what can't fit.
- **Changes:** a change a hobkin made (its timeline, its approvals) gets a security impact analysis drafted, for
  CM-3 and CM-4.

### 4.9 Outputs

- the customer's workbooks, filled (copies);
- `diagrams/*.drawio`;
- `report.html`: what changed since the last run, the drift, the *needs a person* list, and every claim's evidence
  a click away;
- `oscal/`: the SSP, assessment results and POA&M as OSCAL, for whoever takes machine-readable packages.

## 4b. The atone codex: the system's security history, as a git history

*Built in 0.1.0: evidence at stable paths, the control model (`controls/`, `poam/`, `decisions/`), trailers, the
pre-commit guard, `review`, `decide`, `package` (tagged) and `history`. The components live in `system.json`, the
intended flows in `interfaces.json`; raw scanner exports are archived by hash in the store, not the codex.*

Everything atone knows about a system lives in one git repository per system: **the codex**. The authorization
boundary is the repository, so access is the repository's permissions. It's the single source of truth: every
artifact (the workbooks, the POA&M, OSCAL, the diagrams, the report) is generated from it, never edited by hand.
Its history is the system's security history: every change to the system, to what we understand and assert about
it, and to what was decided and delivered is a commit.

### Three layers

| Layer | What it is | Changes when |
|---|---|---|
| **Evidence** | what the system is: collected and imported, normalized, redacted, never edited | the system changes |
| **The model** | what we understand and assert: curated, reviewed | someone decides something |
| **Artifacts** | the packages people and assessors receive | regenerated from the two; kept at each delivery |

Drift is exact: the model says X, the latest evidence says Y.

### The repository

| Path | Holds | A commit there means |
|---|---|---|
| `system.json`, `components/`, `interfaces/`, `boundary.json`, `roles.json` | what the system is: purpose, owners, FIPS 199 categorization and data types, components, intended flows (with the data each carries), interconnections, user roles | the understanding of the system changed |
| `controls/ac-2.json`... | each control: responsibility (system, inherited, shared), status, its implementation as claims with citations, review | a statement or status changed, and who reviewed it |
| `decisions/` | tailoring, risk acceptances, deviations, false positives, approved dates, each with who and why | someone decided something |
| `poam/` | one file per item, from opened to closed | a weakness was found, scheduled, fixed |
| `mappings/` | the ISSE's control, scanner and workbook mappings | how the system is assessed changed |
| `evidence/HOST/KIND/SOURCE.json` | the latest observed state at stable paths, normalized and redacted | **the system itself changed** |
| `packages/TAG/` | exactly what was delivered | a package went out |
| `CODEX.md` | what's here and how to read it | |

**Evidence snapshots:** each collect overwrites `evidence/` and commits only what changed, so its history is the real
system's: a package updated, an account added, a security group opened, a certificate renewed, each a dated diff.
Unchanged content costs nothing (git stores it once). Raw scanner exports and other big files stay in the store (S3
or a folder); the codex records their hashes and holds what's normalized from them.

**Provenance in every fact and every commit.** A fact is *observed* (evidence id), *configured* (file and line),
*asserted* (a named person, a date) or *drafted* (the agent; a draft until reviewed). Commits carry it as trailers,
so `git log` is the audit trail:

```
AC-2: implementation statement drafted from evidence

Control: ac-2
Status: unknown -> partly
Evidence: accounts.app01.20261121T1746Z.4952e9f8
Drafted-by: hobkin bodkin
Reviewed-by: Jane Doe (ISSE)
```

People commit as themselves, the agent as itself; commits can be signed (git's SSH or GPG signing) where the
customer wants non-repudiation.

### Change control is the git workflow

- **`main`** is the system as currently understood and approved.
- **The agent works on branches:** drafted narratives, a proposed POA&M schedule, a security impact analysis for a
  change. Merging is approval; the merge names who approved (CM-3, CM-4).
- **Tags** mark milestones (`ato-2026-12`, `conmon-2026-11`, `assessment-2027`); `packages/TAG/` holds what was
  delivered, and checking a tag out regenerates the package as it stood.

### What the history answers

- When was SSH opened to the world, and what changed just before? (`atone history`, or `git log` on the evidence)
- Who wrote and who approved AC-2's statement, on what evidence? (`git blame`, the trailers)
- What did the assessor see at the ATO, and what's changed since? (a diff against the tag)
- Which POA&M items were open on March 1?

### Safeguards

- **Nothing secret gets committed:** the redaction floor before anything is written, and a second scan at commit
  time that refuses the commit; a documented purge procedure for the worst case (git history is forever).
- **Summaries only,** per system or per kind of evidence, where full snapshots are too sensitive: hashes and what
  changed, without the content.

### Settled

- Evidence in git: full normalized snapshots by default (summaries where a system needs them).
- The remote: the team's internal git server (configurable; there's no internet).
- Commit signing: optional.

## 5. The engagement: a plan first

The first thing the hobkin does on a new system is make **the plan**: one big to-do list of every piece of the
effort, made before anything else and kept current to the end. Each item says what it is, who can do it, what it's
waiting on, and its state. Then the hobkin starts on everything it can do, and explains to the people what they
need to do for the rest.

The plan is built from the baseline (every control, through its mapping), the working documents (what's filled in,
what's blank), and what the hobkin can reach. Its items are of three kinds:

| Kind | Examples | What the hobkin does |
|---|---|---|
| **the hobkin's** | collect evidence from hosts it can reach; draft the system spec, mappings and narratives; draw the architecture; import the scans it's given | does them, in an order that unblocks the most |
| **needs access** | a host it can't reach; AWS read access for a VPC; a scanner's latest export | asks for exactly what it needs and why: the account, the permission (the least that works), or the file, with the command a person would run to grant it |
| **needs a person** | a policy that exists only on paper; an interview with a system owner; a decision (accept a risk, tailor a control out); the inherited-controls matrix; example narratives | says what's needed, from whom, and what it unblocks; or drafts it for them to correct |

It's hobkin's own checklist (CHECKLIST.md), so it survives compaction, moves with the hobkin when it's stashed, and
anyone can read where things stand. Items that need a person can also become hearthboard tickets, assigned to whoever
they need. The plan's first items are always the questions only people can answer: the working documents, the
inherited controls, example narratives, and access.

The plan is also where the schedule lives: the hobkin estimates each item, with margin for review, and proposes
dates; the team adjusts them.

## 6. Who does what

| | Does |
|---|---|
| **the toolkit** (plain code) | collects and imports evidence, runs checks, verifies citations, fills workbooks, computes the graph and draws it, diffs everything |
| **the hobkin** (the agent, with the pack's skills) | builds the lores it needs; drafts the system spec, the mapping files and the narratives; investigates drift; never collects |
| **the ISSE** | owns the system spec and the control mappings; reviews the lores and the drafts; decides what *needs a person* means here |
| **the ISSO** | owns the package and signs it |

## 7. How it's used

As a hobkin with the pack:

```sh
pip install atone                                   # the pack (it brings lorewell; hobkin finds it)
hobkin URL MODEL KEY --chore atone --set system=tst --set store=s3://bucket/atone --chat
```

The hobkin makes the plan (§5), asks for the working documents, access and the inherited-controls matrix, builds the
lores the system needs, drafts the system spec and the workbook mappings for review, then keeps to its cadence: collect daily, run weekly, prepare continuous monitoring monthly, with drift and *needs a
person* items brought to its people (in chat, or as hearthboard tickets).

Or by hand, without any agent:

```sh
atone discover --system tst
atone collect --system tst
atone check --system tst && atone verify --system tst
atone fill --system tst --ssp SSP.xlsx --poam POAM.xlsx --out package/
atone draw --system tst --out package/diagrams/
```

## 8. What needs building, by repo

- **hobkin:** expert packs: chores, skills and lore manifests found in installed packages (`hobkin.packs`). Small and
  generic.
- **lorewell:** nothing new, as far as I can see: `build`, `review` and `compile` already do it; atone's exact
  compiler writes lorewell's format.
- **atone:** the toolkit, the exact OSCAL compiler and the manifest, the skills, the starter mappings, the chore.

## 9. The first slice

One system, end to end, for the controls the family already has evidence for:

- **AU** (audit and accountability): eaveswatch's collection, review, alerting and retention.
- **CM** (configuration management): OpenSCAP results, packages, hobkin's change records.
- **SC-7, AC-4, CA-3, CM-8:** the architecture graph and its diagrams.

It includes the plan (§5), the exact OSCAL lore and tailoring, discovery and the system spec, the collectors those controls need,
the OpenSCAP importer and one scanner mapping, the checks, cited and verified narratives, the workbook round trip,
the diagrams, the report, the chore and its skills, and hobkin's expert-pack mechanism. If the ISSE looks at it
and says *I'd accept this*, the rest is more mappings.

## 10. Settled with the ISSE

1. **Evidence:** assessors mostly take what the package says on trust, so it has to be right: see the principle on
   being right before complete, and `atone verify`.
2. **Working documents:** given to the hobkin at run time, blank or partly done.
3. **Statuses:** defined in the working documents (every ISSM is a little different); atone uses only those.
4. **Inherited controls:** there will be some; the responsibility matrix is provided, and the hobkin asks for it if
   it isn't.
5. **POA&M schedules:** the hobkin proposes realistic dates with margin for the ISSE and DevOps to review; a hard
   deadline, when there is one, is iterated on with the hobkin.
6. **Narrative examples:** asked for at run time.
7. **Diagrams:** the ISSM is tool-agnostic and may not look at them much; they're for the engineering team, and must
   be accurate and useful.
8. **The customer's documents:** decided as they come up, at run time. The model is at the right security level for
   them.
9. **Where it runs and what it reaches:** the hobkin asks for access to what it needs to inspect, or puts it on the
   plan as something a person does.
