# Running atone on a real system

For the first run on a real system: no internet on the boxes, no sudo, a person at the keyboard. About an hour for
the setup; the rest goes at the speed of the questions only people can answer.

## Bring

- **The working documents:** blank (or partly done) copies of the SSP control matrix, the POA&M, and any inventory
  workbook, as `.xlsx`.
- **One export from each scanner:** the latest OpenSCAP results (`oscap xccdf eval --results results.xml ...` or
  ARF), a Rapid7 export (CSV), a Trellix export (CSV or XML).
- **Access:** an account that can ssh to each host with a key (no password prompts) and read config and logs. No
  sudo needed: what it can't read is reported as unknown, never guessed.
- **AWS, if the system runs there:** read-only credentials where atone runs (the SecurityAudit managed policy
  covers it).
- **The inherited controls:** the provider's customer responsibility matrix (AWS GovCloud's, an enterprise
  service's), or the list of controls inherited.
- **If eaveswatch runs there:** its store (`s3://...` or the folder) and its system name.

## Install (no internet)

From the internal PyPI mirror, or wheels carried over:

```sh
pip install atone hobkin lorewell        # or: pip install atone-*.whl hobkin-*.whl lorewell-*.whl
atone sources                            # NIST's files are in the package: their hashes, where they came from
```

## With a hobkin (the way it's meant to run)

```sh
hobkin URL MODEL KEY --brownie CHEAPER_MODEL --chore atone --set system=SYSTEM --set store=s3://bucket/atone --chat
```

It sets the system up and makes **the plan**, then asks for what it needs. Answer it, and give it the files above
(put them where it says). Watch for:

- the plan (`~/atone/systems/SYSTEM/PLAN.md`): what's waiting on people and on access;
- its questions about the inherited controls, the baseline, and example narratives;
- anything it says it couldn't read.

## By hand (to see each step)

```sh
atone init SYSTEM --store s3://bucket/atone           # or a folder
atone discover SYSTEM --ssh user@host1 --ssh user@host2
#   draft systems/SYSTEM/system.json from discovery.json (hosts, components, config files), and review it
atone collect SYSTEM --ssh user@host1 --ssh user@host2
cp results.xml rapid7.csv trellix.csv ~/atone/systems/SYSTEM/imports/
atone import SYSTEM --sample ~/atone/systems/SYSTEM/imports/rapid7.csv
#   write imports/rapid7.mapping.json from its columns (and the same for trellix)
atone import SYSTEM
atone import SYSTEM --eaveswatch s3://bucket/eaveswatch --ew-system NAME     # if eaveswatch runs
#   tailoring.json: the baseline, parameter values, the inherited controls
atone check SYSTEM
cp SSP.xlsx POAM.xlsx ~/atone/systems/SYSTEM/workbooks/
atone workbook inspect ~/atone/systems/SYSTEM/workbooks/SSP.xlsx
#   write workbooks/ssp.mapping.json (sheet, header row, columns, status_values in the workbook's own words)
atone fill SYSTEM --out package/
atone draw SYSTEM --out package/
atone oscal SYSTEM --out package/oscal/
atone report SYSTEM --out package/
atone plan SYSTEM
```

## What to look at

- **`package/report.html`:** coverage, what needs a person, drift, the architecture, each control's evidence.
- **`package/NAME.changes.json`:** every cell atone set in each workbook, and every flag (where the paperwork and the
  evidence disagree). Open the filled `.xlsx` copies in Excel: they should look like the originals, filled in.
- **`package/network.drawio`:** open it in draw.io. Dashed lines are open rules nothing uses; red ones are connections
  the SSP doesn't mention.
- **`atone check SYSTEM CONTROL`:** for any control that looks wrong, its checks and the exact lines they read.

## What to send back

So the first real data can make atone better:

- the error, whole, for anything that failed (`atone ...` prints it);
- the controls whose status looks wrong, with what the evidence actually is (`atone check SYSTEM CONTROL`);
- the workbook mapping files and scanner mapping files that were needed (they're the customer's layouts: send them
  only if that's allowed, or describe what was awkward);
- whatever was "unknown" because it couldn't be read (that tells us what access, or what collector, is missing).

Evidence is redacted before it's stored (keys, tokens, passwords), but it's still the customer's system: check before
anything leaves.
