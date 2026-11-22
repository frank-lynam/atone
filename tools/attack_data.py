#!/usr/bin/env python3
"""Build atone's attacker library (atone/data/attack/) from the sources as their owners publish them.

    python3 tools/attack_data.py DOWNLOADS_DIR

DOWNLOADS_DIR holds what `--fetch` lists (or run with --fetch DIR to download them there first, with internet).
The output is compact, plain-text JSON: what atone and the hobkin need from each source, its text unchanged.
It's deterministic (the same inputs give the same bytes), so anyone can rebuild it and compare hashes. Each output
file's sources (URL, SHA-256 of what was downloaded) and its own SHA-256 go in atone/data/lock.json.

Not shipped in the package: a maintainer's tool, standard library only like the rest.
"""
import hashlib
import json
import re
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "atone" / "data" / "attack"
MX = "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings"
SOURCES = {
    "enterprise-attack.json": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/"
                              "enterprise-attack.json",
    "capec.xml": "https://capec.mitre.org/data/xml/capec_latest.xml",
    "cwe.zip": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    "nist.json": f"{MX}/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.json",
    "aws.json": f"{MX}/aws/attack-19.1/aws-11.06.2026/enterprise/aws-11.06.2026_attack-19.1-enterprise.json",
    "kev.json": f"{MX}/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text(el) -> str:
    """An XML element's text, whitespace tidied (CAPEC and CWE wrap prose in XHTML)."""
    if el is None:
        return ""
    return re.sub(r"\s+", " ", " ".join(el.itertext())).strip()


def ext_id(obj: dict, source: str = "mitre-attack") -> str | None:
    for r in obj.get("external_references") or []:
        if r.get("source_name") == source:
            return r.get("external_id")
    return None


def attack(src: Path) -> dict:
    """ATT&CK Enterprise: tactics, techniques (with their tactics, platforms, mitigations and detection strategies),
    and mitigations. Revoked and deprecated objects are left out."""
    objs = json.loads(src.read_text())["objects"]
    live = [o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_ref = {o["id"]: o for o in live}
    version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), None)
    tactics = {ext_id(o): {"name": o["name"], "short": o.get("x_mitre_shortname"), "description": o.get("description", "")}
               for o in live if o["type"] == "x-mitre-tactic"}
    techniques, mitigations = {}, {}
    for o in live:
        if o["type"] == "attack-pattern" and ext_id(o):
            techniques[ext_id(o)] = {
                "name": o["name"], "tactics": sorted(p["phase_name"] for p in o.get("kill_chain_phases") or []
                                                     if p.get("kill_chain_name") == "mitre-attack"),
                "platforms": sorted(o.get("x_mitre_platforms") or []), "description": o.get("description", ""),
                "mitigations": [], "detection": []}
        elif o["type"] == "course-of-action" and ext_id(o):
            mitigations[ext_id(o)] = {"name": o["name"], "description": o.get("description", "")}
    for r in live:
        if r["type"] != "relationship":
            continue
        s, t = by_ref.get(r.get("source_ref")), by_ref.get(r.get("target_ref"))
        if not s or not t or t["type"] != "attack-pattern" or not ext_id(t) or ext_id(t) not in techniques:
            continue
        if r["relationship_type"] == "mitigates" and s["type"] == "course-of-action" and ext_id(s):
            techniques[ext_id(t)]["mitigations"].append(ext_id(s))
        elif r["relationship_type"] == "detects" and s["type"] == "x-mitre-detection-strategy":
            techniques[ext_id(t)]["detection"].append(s["name"])
    for t in techniques.values():
        t["mitigations"], t["detection"] = sorted(set(t["mitigations"])), sorted(set(t["detection"]))
    return {"source": "MITRE ATT&CK Enterprise", "version": version, "tactics": dict(sorted(tactics.items())),
            "techniques": dict(sorted(techniques.items())), "mitigations": dict(sorted(mitigations.items()))}


def capec(src: Path) -> dict:
    """CAPEC attack patterns: description, likelihood, severity, prerequisites, mitigations, and the CWE weaknesses
    and ATT&CK techniques each relates to. Deprecated ones are left out."""
    root = ET.parse(src).getroot()
    ns = root.tag.split("}")[0] + "}"
    out = {}
    for a in root.find(ns + "Attack_Patterns"):
        if a.get("Status") == "Deprecated":
            continue
        out[f"CAPEC-{a.get('ID')}"] = {
            "name": a.get("Name"), "abstraction": a.get("Abstraction"), "status": a.get("Status"),
            "description": text(a.find(ns + "Description")),
            "likelihood": text(a.find(ns + "Likelihood_Of_Attack")), "severity": text(a.find(ns + "Typical_Severity")),
            "prerequisites": [text(p) for p in a.findall(f"{ns}Prerequisites/{ns}Prerequisite")],
            "mitigations": [text(m) for m in a.findall(f"{ns}Mitigations/{ns}Mitigation")],
            "cwe": [f"CWE-{w.get('CWE_ID')}" for w in a.findall(f"{ns}Related_Weaknesses/{ns}Related_Weakness")],
            "attack": [f"T{m.find(ns + 'Entry_ID').text.strip()}" for m in a.findall(f"{ns}Taxonomy_Mappings/{ns}Taxonomy_Mapping")
                       if m.get("Taxonomy_Name") == "ATTACK" and m.find(ns + "Entry_ID") is not None],
        }
    return {"source": "MITRE CAPEC", "version": root.get("Version"), "date": root.get("Date"),
            "patterns": dict(sorted(out.items(), key=lambda kv: int(kv[0].split("-")[1])))}


def cwe(src: Path) -> dict:
    """CWE weaknesses: description, what exploiting one does, how to mitigate it, related attack patterns.
    Deprecated ones are left out."""
    with zipfile.ZipFile(src) as z:
        name = next(n for n in z.namelist() if n.endswith(".xml"))
        root = ET.fromstring(z.read(name))
    ns = root.tag.split("}")[0] + "}"
    out = {}
    for w in root.find(ns + "Weaknesses"):
        if w.get("Status") == "Deprecated":
            continue
        out[f"CWE-{w.get('ID')}"] = {
            "name": w.get("Name"), "abstraction": w.get("Abstraction"), "status": w.get("Status"),
            "description": text(w.find(ns + "Description")),
            "consequences": [{"scope": [text(s) for s in c.findall(ns + "Scope")], "impact": [text(i) for i in c.findall(ns + "Impact")]}
                             for c in w.findall(f"{ns}Common_Consequences/{ns}Consequence")],
            "mitigations": [text(m.find(ns + "Description")) for m in w.findall(f"{ns}Potential_Mitigations/{ns}Mitigation")
                            if m.find(ns + "Description") is not None],
            "capec": [f"CAPEC-{p.get('CAPEC_ID')}" for p in w.findall(f"{ns}Related_Attack_Patterns/{ns}Related_Attack_Pattern")],
        }
    return {"source": "MITRE CWE", "version": root.get("Version"), "date": root.get("Date"),
            "weaknesses": dict(sorted(out.items(), key=lambda kv: int(kv[0].split("-")[1])))}


def mappings(nist: Path, aws: Path, kev: Path) -> dict:
    """The Center for Threat-Informed Defense's mappings: ATT&CK techniques to the 800-53 controls that mitigate them,
    to the AWS services that protect against or detect them, and CISA's known exploited vulnerabilities to the
    techniques they're used in."""
    n, a, k = (json.loads(p.read_text()) for p in (nist, aws, kev))
    to_controls, unmappable = {}, set()
    for m in n["mapping_objects"]:
        if m.get("status") == "non_mappable":
            unmappable.add(m["attack_object_id"])
        elif m.get("capability_id") and m.get("attack_object_id") and m.get("mapping_type") == "mitigates":
            # their ids are zero-padded (ac-02); the catalog's, and atone's, aren't (ac-2)
            to_controls.setdefault(m["attack_object_id"], set()).add(
                re.sub(r"-0*(\d)", r"-\1", m["capability_id"].lower()))
    to_aws = {}
    for m in a["mapping_objects"]:
        if m.get("capability_id") and m.get("attack_object_id"):
            to_aws.setdefault(m["attack_object_id"], []).append(
                {"service": m.get("capability_description"), "category": m.get("score_category"),
                 "value": m.get("score_value"), "note": m.get("comments") or ""})
    vulns = {}
    for m in k["mapping_objects"]:
        if m.get("capability_id") and m.get("attack_object_id"):
            v = vulns.setdefault(m["capability_id"], {"name": m.get("capability_description"), "techniques": []})
            v["techniques"].append({"id": m["attack_object_id"], "how": m.get("mapping_type")})
    meta = lambda d: {x: d["metadata"].get(x) for x in ("mapping_version", "attack_version", "technology_domain",
                                                         "mapping_framework", "mapping_framework_version")}
    return {"source": "Center for Threat-Informed Defense, Mappings Explorer",
            "nist_800_53": {"about": meta(n), "techniques": {t: sorted(c) for t, c in sorted(to_controls.items())},
                            "unmappable": sorted(unmappable - set(to_controls))},
            "aws": {"about": meta(a), "techniques": dict(sorted((t, sorted(v, key=lambda x: (x["service"] or "", x["category"] or "")))
                                                              for t, v in to_aws.items()))},
            "kev": {"about": meta(k), "vulnerabilities": dict(sorted(vulns.items()))}}


def write(name: str, data: dict) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    p = OUT / name
    p.write_text(json.dumps(data, indent=0, ensure_ascii=False, sort_keys=False) + "\n")
    return p


def main(argv: list[str]) -> None:
    if argv[:1] == ["--fetch"]:
        d = Path(argv[1])
        d.mkdir(parents=True, exist_ok=True)
        for name, url in SOURCES.items():
            print(f"fetching {url}")
            urllib.request.urlretrieve(url, d / name)
        argv = [str(d)]
    if len(argv) != 1:
        sys.exit(__doc__)
    d = Path(argv[0])
    built = {"attack/attack.json": (attack(d / "enterprise-attack.json"), ["enterprise-attack.json"]),
             "attack/capec.json": (capec(d / "capec.xml"), ["capec.xml"]),
             "attack/cwe.json": (cwe(d / "cwe.zip"), ["cwe.zip"]),
             "attack/mappings.json": (mappings(d / "nist.json", d / "aws.json", d / "kev.json"),
                                      ["nist.json", "aws.json", "kev.json"])}
    lock_path = ROOT / "atone" / "data" / "lock.json"
    lock = json.loads(lock_path.read_text())
    for rel, (data, srcs) in built.items():
        p = write(rel.split("/", 1)[1], data)
        lock[rel] = {"derived_by": "tools/attack_data.py", "fetched": time.strftime("%Y-%m-%d"),
                     "sources": [{"url": SOURCES[s], "sha256": sha(d / s)} for s in srcs],
                     "bytes": p.stat().st_size, "sha256": sha(p)}
        print(f"{rel}: {p.stat().st_size // 1024} KB")
    lock_path.write_text(json.dumps(lock, indent=2) + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])
