# atone's bundled data

Shipped in the package as plain text, so atone works with no internet access. Every file's source, when it was
fetched and its SHA-256 are in lock.json. NIST's files are US government work, in the public domain; the attacker library's sources and terms are below.

- `nist/`: NIST SP 800-53 Rev 5 (catalog, with SP 800-53A's assessment objectives) and its LOW, MODERATE, HIGH and
  PRIVACY baseline profiles, as NIST publishes them in OSCAL. The controls lore is compiled from these, word for
  word: `atone controls lore`.
- `guidance/`: NIST SP 800-37 Rev 2 (the Risk Management Framework), SP 800-18 Rev 1 (writing a system security
  plan) and SP 800-137 (continuous monitoring), as text converted from NIST's PDFs. Help for the agent, built into a
  lore with lorewell and reviewed; never cited as a control.

- `attack/`: the attacker library, for atonement (DESIGN.md 4a): MITRE ATT&CK Enterprise (techniques, tactics,
  mitigations, detection strategies), CAPEC (attack patterns), CWE (weaknesses), and the Center for Threat-Informed
  Defense's mappings from ATT&CK to NIST SP 800-53 Rev 5 controls, to AWS services, and from CISA's Known Exploited
  Vulnerabilities to ATT&CK. Compact JSON derived by `tools/attack_data.py` (in the source distribution; the same
  downloads always give the same bytes), the text unchanged. Their copyright designations and licences, as their
  terms require: `attack/LICENSES.md`. In lock.json, each records its sources' URLs and hashes as well as its own.

A newer copy of NIST's files, downloaded elsewhere: `atone controls fetch --from DIR` (recorded with its hashes in
~/atone/sources/lock.json, and used instead of these).
