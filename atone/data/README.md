# atone's bundled data

Shipped in the package as plain text, so atone works with no internet access. Every file's source, when it was
fetched and its SHA-256 are in lock.json. All of it is US government work (NIST), in the public domain.

- `nist/`: NIST SP 800-53 Rev 5 (catalog, with SP 800-53A's assessment objectives) and its LOW, MODERATE, HIGH and
  PRIVACY baseline profiles, as NIST publishes them in OSCAL. The controls lore is compiled from these, word for
  word: `atone controls lore`.
- `guidance/`: NIST SP 800-37 Rev 2 (the Risk Management Framework), SP 800-18 Rev 1 (writing a system security
  plan) and SP 800-137 (continuous monitoring), as text converted from NIST's PDFs. Help for the agent, built into a
  lore with lorewell and reviewed; never cited as a control.

A newer copy of NIST's files, downloaded elsewhere: `atone controls fetch --from DIR` (recorded with its hashes in
~/atone/sources/lock.json, and used instead of these).
