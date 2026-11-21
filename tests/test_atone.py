"""atone's tests: fixtures only (no AWS, no network, no model). python3 tests/test_atone.py"""
import gzip
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
os.environ["ATONE_HOME"] = tempfile.mkdtemp(prefix="atone-test-")
import atone  # noqa: E402

FIX = HERE / "fixtures"


def run(*argv) -> tuple[int, str]:
    out = io.StringIO()
    with redirect_stdout(out):
        code = atone.main(list(argv))
    return code, out.getvalue()


class Floor(unittest.TestCase):
    """The redaction floor and the credential deny-list: always on."""

    def test_secrets_are_redacted(self):
        text = ("password=hunter2 key AKIAABCDEFGHIJKLMNOP url https://u:pw@h/x Authorization: Bearer abcdefgh123 "
                "<password>s3cret</password>")
        out = atone.redact(text)
        for secret in ("hunter2", "AKIAABCDEFGHIJKLMNOP", "u:pw@", "abcdefgh123", "s3cret"):
            self.assertNotIn(secret, out)

    def test_credentials_are_never_read(self):
        for path in ("~/.ssh/id_ed25519", "/etc/shadow", "/opt/app/server.key", "/opt/app/db-credentials.xml",
                     "~/.aws/credentials"):
            self.assertIsNotNone(atone.denied(path), path)
        self.assertIsNone(atone.denied("/etc/sudoers"))       # policy, not a credential: evidence
        self.assertIsNone(atone.denied("/etc/ssh/sshd_config"))


class Evidence(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_a_record_is_redacted_then_hashed_and_checks_against_itself(self):
        rec = atone.make_record("tst", "file", "h1", "/etc/app.conf", "db_password=abc123\nport=8443\n")
        self.assertNotIn("abc123", rec["content"])
        self.assertTrue(atone.check_record(rec))
        rec["content"] += "tampered"
        self.assertFalse(atone.check_record(rec))

    def test_the_store_lays_records_out_by_system_kind_day_and_host(self):
        store = atone.Store(str(self.tmp / "store"))
        rec = atone.make_record("tst", "accounts", "h1", "passwd entries", [{"user": "root"}])
        key = atone.record_key(rec)
        self.assertRegex(key, r"^system=tst/kind=accounts/dt=\d{4}-\d\d-\d\d/host=h1/\d{8}T\d{6}Z_[0-9a-f]{6}\.json\.gz$")
        store.put(key, gzip.compress(json.dumps(rec).encode()))
        self.assertEqual(json.loads(gzip.decompress(store.get(key)))["sha256"], rec["sha256"])

    def test_collectors_run_here_and_one_failing_is_evidence_of_that(self):
        parts = atone.collect_here(["accounts", "listeners"], {})
        self.assertTrue(any(p["source"] == "passwd entries" for p in parts))
        self.assertTrue(any(p["kind"] == "listeners" for p in parts))
        with self.assertRaises(atone.AtoneError):
            atone.collect_here(["rm -rf"], {})                 # only the menu

    def test_the_file_collector_takes_named_files_but_never_credentials(self):
        conf, key = self.tmp / "app.conf", self.tmp / "server.key"
        conf.write_text("listen 8443\n")
        key.write_text("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n")
        spec = {"components": [{"name": "app", "files": [{"path": str(conf)}, {"path": str(key)}]}]}
        got = dict(atone.c_file(spec))
        self.assertEqual(got[str(conf)], "listen 8443\n")
        self.assertIn("never collected", got[str(key)])


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = (atone.HOME / "sources")
        src.mkdir(parents=True, exist_ok=True)
        shutil.copy(FIX / "catalog.json", src / "catalog.json")
        shutil.copy(FIX / "moderate.json", src / "moderate.json")
        cls.cat = atone.load_catalog()

    def test_the_catalog_has_controls_and_enhancements(self):
        self.assertEqual(self.cat["ac-2"]["label"], "AC-2")
        self.assertEqual(self.cat["ac-2.1"]["label"], "AC-2(1)")
        self.assertEqual(self.cat["ac-2.1"]["parent"], "ac-2")
        self.assertTrue(self.cat["ac-2.10"]["withdrawn"])

    def test_statements_fill_in_parameters_and_selections(self):
        text = atone.control_text(self.cat["ac-11"])
        self.assertIn("[Selection (one or more): initiating a device lock after [Assignment: time period]", text)
        self.assertNotIn("{{", text)
        self.assertIn("after 15 minutes of inactivity", atone.control_text(self.cat["ac-11"], {"ac-11_odp.02": "15 minutes"}))

    def test_tailoring_adds_removes_and_marks_inherited(self):
        d = atone.init_system("tailored", None)
        t = atone.read_json(d / "tailoring.json")
        t.update({"add": ["cm-6"], "remove": ["au-11"], "inherited": {"pe-3": {"from": "AWS GovCloud"}},
                  "params": {"ac-11_odp.02": "15 minutes"}})
        atone.write_json(d / "tailoring.json", t)
        ctls = {c["id"]: c for c in atone.system_controls(d)}
        self.assertEqual(set(ctls), {"ac-2", "ac-2.1", "ac-11", "pe-3", "cm-6"})
        self.assertEqual(ctls["pe-3"]["responsibility"], "inherited")
        self.assertEqual(ctls["ac-11"]["values"], {"ac-11_odp.02": "15 minutes"})
        t["add"] = ["zz-99"]
        atone.write_json(d / "tailoring.json", t)
        with self.assertRaises(atone.AtoneError):
            atone.system_controls(d)

    def test_the_lore_is_the_catalog_word_for_word(self):
        import lorewell
        out = Path(tempfile.mkdtemp()) / "nist.lore.db"
        r = atone.compile_controls_lore(out)
        self.assertEqual(r["symbols"], len(self.cat))
        lore = lorewell.Lore(out)
        shown = lorewell.cmd_symbol(lore, type("A", (), {"name": "AC-2(1)"}))
        self.assertIn("Automated System Account Management", shown)
        nist = atone.control_text(self.cat["ac-2"])
        body = lore.q("SELECT body FROM sections WHERE id = 'ac-2'")[0][0]
        self.assertIn(nist, body)                              # exactly NIST's words


class Imports(unittest.TestCase):
    def test_control_references(self):
        self.assertEqual(atone.control_ids("AC-17(a),CM-7(a)"), ["ac-17", "cm-7"])   # parts: the control
        self.assertEqual(atone.control_ids("AC-2(1)"), ["ac-2.1"])                 # enhancements
        self.assertEqual(atone.control_ids("IA-5(1)(a)"), ["ia-5.1"])

    def test_openscap_results_with_their_controls(self):
        [rec] = atone.import_oscap(FIX / "oscap-results.xml")
        self.assertEqual(rec["host"], "app01.example.internal")
        rules = {r["title"]: r for r in rec["content"]["results"]}
        self.assertEqual(rules["Set Interactive Session Timeout"]["result"], "fail")
        self.assertEqual(rules["Set Interactive Session Timeout"]["controls"], ["ac-12", "sc-10"])
        self.assertNotIn("Uninstall telnet", rules)             # not selected: not a result

    def test_a_csv_export_through_its_mapping(self):
        mapping = json.loads((FIX / "vulns.mapping.json").read_text())
        recs = {r["host"]: r for r in atone.import_file(FIX / "vulns-export.csv", [mapping])}
        app = recs["app01.example.internal"]["content"]["findings"]
        self.assertEqual([f["severity"] for f in app], ["critical", "moderate"])    # the customer's words
        self.assertEqual(recs["db01.example.internal"]["content"]["findings"][0]["cve"], ["CVE-2026-2222", "CVE-2026-2223"])

    def test_an_xml_export_through_its_mapping(self):
        mapping = json.loads((FIX / "endpoints.mapping.json").read_text())
        recs = {r["host"]: r["content"]["findings"][0] for r in atone.import_file(FIX / "endpoints-export.xml", [mapping])}
        self.assertEqual(recs["db01.example.internal"]["finding"], "unmanaged")
        self.assertEqual(recs["app01.example.internal"]["agent_version"], "5.8.1")

    def test_a_file_nothing_can_read_says_how_to_make_a_mapping(self):
        with self.assertRaises(atone.AtoneError) as e:
            atone.import_file(FIX / "vulns-export.csv", [])
        self.assertIn("--sample", str(e.exception))

    def test_imports_add_to_the_current_evidence_alongside_collected(self):
        d = atone.init_system("imp", None)
        for f in ("oscap-results.xml", "vulns-export.csv", "vulns.mapping.json"):
            shutil.copy(FIX / f, d / "imports" / f)
        atone.collect("imp", ["accounts"], log=lambda *a: None)
        atone.import_results("imp", log=lambda *a: None)
        kinds = {(e["kind"], e["source"].split(" (")[0]) for e in atone.current_index(d)}
        self.assertIn(("accounts", "passwd entries"), kinds)              # still current after the import
        self.assertIn(("scan", "openscap stig"), kinds)
        self.assertIn(("scan", "vulnscanner"), kinds)
        self.assertTrue(all("file_sha256" in e for e in atone.current_index(d) if e["kind"] == "scan"))
        atone.collect("imp", ["accounts"], log=lambda *a: None)          # collected again: the newest one counts
        self.assertEqual(len([e for e in atone.current_index(d) if e["source"] == "passwd entries"]), 1)


def evidence_system(name, records):
    """A system whose current evidence is exactly `records`: [(kind, host, source, content)]."""
    d = atone.init_system(name, None)
    (atone.HOME / "sources").mkdir(parents=True, exist_ok=True)
    shutil.copy(FIX / "catalog.json", (atone.HOME / "sources") / "catalog.json")
    shutil.copy(FIX / "moderate.json", (atone.HOME / "sources") / "moderate.json")
    atone.save_records(d, [atone.make_record(name, k, h, src, c) for k, h, src, c in records])
    return d


AUDITD = "log_file = /var/log/audit/audit.log\nnum_logs = 10\nmax_log_file_action = keep_logs\nspace_left = 25%\n"


class Checks(unittest.TestCase):
    def rec(self, content, kind="file", host="h1", source="/etc/audit/auditd.conf"):
        return atone.make_record("t", kind, host, source, content)

    def test_present_absent_and_their_quotes(self):
        r = atone.run_check({"type": "present", "pattern": r"^max_log_file_action\s*=\s*keep_logs"}, [self.rec(AUDITD)], "au-11", {})
        self.assertEqual(r["status"], "pass")
        self.assertEqual(r["quotes"][0]["quote"], "max_log_file_action = keep_logs")
        r = atone.run_check({"type": "absent", "pattern": "NOPASSWD"}, [self.rec("%wheel ALL=(ALL) NOPASSWD: ALL")], "ac-6", {})
        self.assertEqual(r["status"], "fail")

    def test_a_value_against_the_tailoring(self):
        chk = {"type": "value", "pattern": r"^num_logs\s*=\s*(\d+)", "op": ">=", "value": "{param:au-11_odp}"}
        self.assertEqual(atone.run_check(chk, [self.rec(AUDITD)], "au-11", {"au-11_odp": "5 rotations"})["status"], "pass")
        self.assertEqual(atone.run_check(chk, [self.rec(AUDITD)], "au-11", {"au-11_odp": "30"})["status"], "fail")
        self.assertEqual(atone.run_check(chk, [self.rec(AUDITD)], "au-11", {})["status"], "unknown")   # not tailored yet

    def test_counts_scans_and_findings(self):
        users = self.rec(json.dumps([{"user": "root", "uid": 0}, {"user": "toor", "uid": 0}]), kind="accounts")
        self.assertEqual(atone.run_check({"type": "count", "field_patterns": {"uid": "^0$"}, "op": "==", "value": 1},
                                         [users], "ac-2", {})["status"], "fail")
        [scan] = atone.import_oscap(FIX / "oscap-results.xml")
        srec = self.rec(scan["content"], kind="scan", source=scan["source"])
        self.assertEqual(atone.run_check({"type": "scan"}, [srec], "ac-12", {})["status"], "fail")   # the timeout rule
        self.assertEqual(atone.run_check({"type": "scan"}, [srec], "au-11", {})["status"], "pass")
        self.assertEqual(atone.run_check({"type": "scan"}, [srec], "ac-17", {})["status"], "unknown")
        mapping = json.loads((FIX / "vulns.mapping.json").read_text())
        vrecs = [self.rec(r["content"], kind="scan", host=r["host"], source=r["source"])
                 for r in atone.import_file(FIX / "vulns-export.csv", [mapping])]
        r = atone.run_check({"type": "findings", "severity": ["critical", "high"], "op": "==", "value": 0}, vrecs, "ra-5", {})
        self.assertEqual((r["status"], r["detail"]), ("fail", "2 findings (critical, high)"))

    def test_evidence_that_couldnt_be_read_is_unknown_not_a_pass_or_a_fail(self):
        r = atone.run_check({"type": "absent", "pattern": "NOPASSWD"},
                            [self.rec("not readable here: /etc/sudoers: Permission denied")], "ac-6", {})
        self.assertEqual(r["status"], "unknown")

    def test_a_mapping_with_mistakes_says_what_they_are(self):
        probs = atone.mapping_problems({"control": "x", "evidence": [{"name": "e", "kind": "rm"}],
                                        "checks": [{"id": "a", "type": "eval", "evidence": "e"},
                                                   {"id": "b", "type": "present", "evidence": "nope", "pattern": "("}]})
        self.assertEqual(len(probs), 4, probs)

    def test_a_system_checked_end_to_end(self):
        d = evidence_system("chk", [("file", "h1", "/etc/audit/auditd.conf", AUDITD),
                                    ("services", "h1", "systemctl list-units --type=service --all",
                                     "auditd.service loaded active running Security Auditing Service\n")])
        t = atone.read_json(d / "tailoring.json")
        t["inherited"] = {"pe-3": {"from": "AWS GovCloud"}}
        atone.write_json(d / "tailoring.json", t)
        res = atone.check_system("chk", log=lambda *a: None)["controls"]
        self.assertEqual(res["au-11"]["status"], "partly")       # checks pass, but a person must supply the policy
        self.assertEqual(res["au-11"]["checks"][0]["status"], "pass")
        self.assertEqual(res["pe-3"]["status"], "inherited")
        self.assertEqual(res["ac-11"]["status"], "unknown")       # no mapping yet: said so
        self.assertIn("no mapping", res["ac-11"]["why"])


class Verify(unittest.TestCase):
    def test_only_claims_the_evidence_bears_out_are_kept(self):
        d = evidence_system("ver", [("file", "h1", "/etc/audit/auditd.conf", AUDITD)])
        eid = atone.current_index(d)[0]["id"]
        draft = {"control": "au-11", "claims": [
            {"text": "The audit daemon keeps rotated logs rather than overwriting them.",
             "cites": [{"evidence": eid, "quote": "max_log_file_action = keep_logs"}]},
            {"text": "Audit logs are kept for one year.", "cites": [{"evidence": eid, "quote": "num_logs = 365"}]},
            {"text": "Logs are reviewed weekly.", "cites": []},
            {"text": "The ISSO reviews retention annually.", "person": "the ISSE, 2026-11-21"}]}
        v = atone.verify_narrative(d, draft)
        self.assertEqual([c["text"][:20] for c in v["claims"]], ["The audit daemon kee", "The ISSO reviews ret"])
        self.assertEqual(v["coverage"], {"evidence": 1, "person": 1, "dropped": 2})
        self.assertIn("doesn't say", v["dropped"][0]["why"])
        self.assertIn("cites nothing", v["dropped"][1]["why"])

    def test_a_claim_on_superseded_evidence_is_dropped(self):
        d = evidence_system("sup", [("file", "h1", "/etc/audit/auditd.conf", AUDITD)])
        old = atone.current_index(d)[0]["id"]
        import time
        time.sleep(1.1)
        atone.save_records(d, [atone.make_record("sup", "file", "h1", "/etc/audit/auditd.conf",
                                                 AUDITD.replace("keep_logs", "rotate"))])
        v = atone.verify_narrative(d, {"claims": [{"text": "x", "cites": [{"evidence": old, "quote": "keep_logs"}]}]})
        self.assertIn("superseded", v["dropped"][0]["why"])


SSP_MAP = {"match": "ssp-*.xlsx", "kind": "ssp", "sheet": "Controls", "header_row": 3,
           "columns": {"control": "Control ID", "status": "Status", "statement": "Implementation Statement",
                       "evidence": "Evidence"},
           "status_values": {"met": "Implemented", "partly": "Partially Implemented", "not met": "Planned",
                             "inherited": "Inherited"}}
POAM_MAP = {"match": "poam*.xlsx", "kind": "poam", "sheet": "POA&M Items", "header_row": 1,
            "columns": {"id": "POA&M ID", "weakness": "Weakness Name", "description": "Weakness Description",
                        "control": "Security Control", "severity": "Severity", "detected": "Detection Date",
                        "due": "Scheduled Completion Date", "status": "Status", "source": "Source", "asset": "Asset"},
            "status_values": {"open": "Open", "closed": "Closed"}}


class Workbooks(unittest.TestCase):
    """The customer's workbooks: read as they are (shared strings, drop-downs from a range), filled in a copy."""

    def test_reading_a_workbook_as_excel_and_libreoffice_save_them(self):
        wb = atone.Workbook(FIX / "ssp-matrix.xlsx")
        self.assertEqual(list(wb.sheets), ["Instructions", "Controls", "Lists"])
        self.assertEqual(wb.value("Controls", "A5"), "AC-2(1)")                # a shared string
        self.assertEqual(wb.allowed("Controls", "C10"), ["Implemented", "Partially Implemented", "Planned", "Inherited",
                                                         "Not Applicable"])   # from Lists!$A$1:$A$5
        self.assertEqual(atone.Workbook(FIX / "poam.xlsx").allowed("POA&M Items", "H2"), ["Open", "Closed", "Risk Accepted"])
        self.assertEqual(wb.merged("Controls"), ["A1:F1"])

    def test_control_ids_as_workbooks_write_them(self):
        for text, want in (("AC-2(1)", "ac-2.1"), ("AC-02 (01)", "ac-2.1"), ("ac-2.1", "ac-2.1"), ("AU-11", "au-11"),
                           ("Control ID", None)):
            self.assertEqual(atone.normalize_control(text), want)

    def test_cells_set_in_place_and_formulas_never_overwritten(self):
        xml = ('<worksheet><dimension ref="A1:B2"/><sheetData><row r="1"><c r="A1" s="3" t="s"><v>0</v></c>'
               '<c r="B1"><f>SUM(A2:A9)</f><v>4</v></c></row><row r="3"><c r="C3" s="5"/></row></sheetData></worksheet>')
        out, skipped = atone.edit_sheet_xml(xml, {"A1": "new <one> & co", "B1": "x", "B3": "beside", "D3": "after", "A2": "row"})
        self.assertEqual(skipped, ["B1"])
        self.assertIn('<c r="A1" s="3" t="inlineStr"><is><t xml:space="preserve">new &lt;one&gt; &amp; co</t></is></c>', out)
        self.assertIn("<f>SUM(A2:A9)</f>", out)
        self.assertLess(out.index('r="A2"'), out.index('r="C3"'))                 # the new row, in order
        self.assertLess(out.index('r="B3"'), out.index('r="C3"'))                 # a new cell, in column order
        self.assertLess(out.index('r="C3"'), out.index('r="D3"'))
        self.assertIn('<dimension ref="A1:D3"', out)

    def system(self, name):
        d = evidence_system(name, [("file", "app01.example.internal", "/etc/audit/auditd.conf", AUDITD)])
        for f in ("oscap-results.xml", "vulns-export.csv", "vulns.mapping.json"):
            shutil.copy(FIX / f, d / "imports" / f)
        atone.import_results(name, log=lambda *a: None)
        t = atone.read_json(d / "tailoring.json")
        t["inherited"] = {"pe-3": {"from": "AWS GovCloud"}}
        atone.write_json(d / "tailoring.json", t)
        atone.check_system(name, log=lambda *a: None)
        for f, m in (("ssp-matrix.xlsx", SSP_MAP), ("poam.xlsx", POAM_MAP)):
            shutil.copy(FIX / f, d / "workbooks" / f)
            atone.write_json(d / "workbooks" / (f.split(".")[0] + ".mapping.json"), m)
        return d

    def test_filling_the_ssp_keeps_whats_there_and_flags_disagreements(self):
        d = self.system("fillssp")
        eid = next(e["id"] for e in atone.current_index(d) if e["kind"] == "file")
        atone.write_json(d / "drafts" / "verified" / "ac-11.json", atone.verify_narrative(d, {"control": "ac-11", "claims": [
            {"text": "Rotated audit logs are kept.", "cites": [{"evidence": eid, "quote": "max_log_file_action = keep_logs"}]}]}))
        out = Path(tempfile.mkdtemp())
        [ssp] = [r for r in atone.fill_workbooks("fillssp", out, log=lambda *a: None) if r["workbook"] == "ssp-matrix.xlsx"]
        wb = atone.Workbook(out / "ssp-matrix.xlsx")
        self.assertEqual(wb.value("Controls", "E6"), "Rotated audit logs are kept.")          # the verified narrative
        self.assertEqual(wb.value("Controls", "C8"), "Inherited")
        self.assertEqual(wb.value("Controls", "E8"), "Inherited from AWS GovCloud.")
        self.assertEqual(wb.value("Controls", "C7"), "Implemented")                            # kept...
        self.assertTrue(any(f["cell"] == "Controls!C7" and f["atone"] == "Partially Implemented" for f in ssp["flags"]))
        self.assertTrue(wb.value("Controls", "F7").startswith("atone: "))
        import zipfile
        a, b = zipfile.ZipFile(FIX / "ssp-matrix.xlsx"), zipfile.ZipFile(out / "ssp-matrix.xlsx")
        self.assertEqual([i.filename for i in a.infolist() if a.read(i) != b.read(i.filename)], ["xl/worksheets/sheet2.xml"])
        self.assertTrue((out / "ssp-matrix.changes.json").exists())

    def test_filling_the_poam_adds_whats_new_once(self):
        d = self.system("fillpoam")
        out = Path(tempfile.mkdtemp())
        atone.fill_workbooks("fillpoam", out, log=lambda *a: None)
        rows = atone.Workbook(out / "poam.xlsx").rows("POA&M Items")
        names = [r.get("B") for r in rows.values()]
        self.assertEqual(names.count("TLS 1.0 enabled"), 1)                     # already there: not added again
        self.assertIn("OpenSSL: CVE-2026-1111 buffer overread", names)
        self.assertIn("Set Interactive Session Timeout", names)                 # a failed OpenSCAP rule
        new = next(r for r in rows.values() if r.get("B") == "Oracle JDK out of date")
        self.assertEqual((new["A"], new["H"], new.get("G")), ("ATONE-0003", "Open", None))    # no made-up date

    def test_a_status_the_workbooks_drop_down_doesnt_have_is_refused(self):
        d = self.system("badstatus")
        atone.write_json(d / "workbooks" / "ssp-matrix.mapping.json",
                         {**SSP_MAP, "status_values": {**SSP_MAP["status_values"], "met": "Compliant"}})
        with self.assertRaises(atone.AtoneError) as e:
            atone.fill_workbooks("badstatus", Path(tempfile.mkdtemp()), [str(d / "workbooks" / "ssp-matrix.xlsx")],
                                 log=lambda *a: None)
        self.assertIn("Compliant", str(e.exception))


class Architecture(unittest.TestCase):
    """Actual (connections seen), allowed (security groups) and documented (the SSP's flows), and what differs."""

    @classmethod
    def setUpClass(cls):
        fx = json.loads((FIX / "architecture.json").read_text())
        cls.d = atone.init_system("arch", None)
        atone.write_json(cls.d / "system.json", fx["spec"])
        atone.write_json(cls.d / "documented.json", fx["documented"])
        atone.save_records(cls.d, [atone.make_record("arch", k, h, src, c) for k, h, src, c in fx["records"]])
        cls.out = Path(tempfile.mkdtemp())
        cls.g = atone.draw_system("arch", cls.out, log=lambda *a: None)
        cls.edges = {(e["from"], e["to"], e["port"]): e["class"] for e in cls.g["edges"]}

    def test_each_path_is_classed_by_what_the_three_layers_say(self):
        self.assertEqual(self.edges[("internet", "web01", "tcp/443")], "normal")
        self.assertEqual(self.edges[("web01", "app01", "tcp/9000")], "normal")           # all three agree
        self.assertEqual(self.edges[("internet", "web01", "tcp/22")], "unused")           # open, never used
        self.assertEqual(self.edges[("app01", "db01", "tcp/1521")], "undocumented")       # allowed, used, not in the SSP
        self.assertEqual(self.edges[("app01", "52.94.0.10", "tcp/443")], "undocumented")
        self.assertEqual(self.edges[("db01", "backup.example.internal", "tcp/443")], "documented only")
        self.assertEqual(self.edges[("34.200.1.7", "web01", "tcp/443")], "normal")         # covered by 0.0.0.0/0

    def test_the_boundary_and_what_crosses_it(self):
        inside = {n["id"] for n in self.g["nodes"] if n["inside"]}
        self.assertEqual(inside, {"web01", "app01", "db01"})
        self.assertIn("app01 -> 52.94.0.10 tcp/443", self.g["crossing"])

    def test_drawio_and_svg_are_well_formed_and_say_what_they_show(self):
        import xml.etree.ElementTree as ET
        model = ET.parse(self.out / "network.drawio").getroot()
        cells = model.findall(".//mxCell")
        self.assertTrue(any(c.get("id") == "boundary" for c in cells))
        self.assertEqual(sum(1 for c in cells if c.get("edge") == "1" and c.get("source")), len(self.g["edges"]))
        self.assertTrue(any("dashed=1" in (c.get("style") or "") for c in cells if c.get("source")))
        ET.parse(self.out / "network.svg")

    def test_a_connection_seen_once_in_the_window_still_counts(self):
        import time as _t
        d = atone.init_system("overtime", None)
        fx = json.loads((FIX / "architecture.json").read_text())
        atone.write_json(d / "system.json", fx["spec"])
        recs = [atone.make_record("overtime", k, h, src, c) for k, h, src, c in fx["records"] if k != "flows"]
        recs.append(atone.make_record("overtime", "flows", "app01", "/proc/net (connected)",
                                      [{"proto": "tcp", "state": "established", "local": "10.0.2.20:43000",
                                        "remote": "10.0.3.30:1521", "process": "nightly batch"}]))
        atone.save_records(d, recs)
        _t.sleep(1.1)                                       # the next collect: the batch connection has closed
        atone.save_records(d, [atone.make_record("overtime", "flows", "app01", "/proc/net (connected)", [])])
        g = atone.build_graph("overtime")
        e = next(e for e in g["edges"] if (e["from"], e["to"], e["port"]) == ("app01", "db01", "tcp/1521"))
        self.assertIn("actual", e["layers"])                # not "unused": it was seen, once
        self.assertEqual(e["seen"], 1)

    def test_what_changed_since_the_last_drawing(self):
        atone.write_json(self.d / "documented.json", json.loads((FIX / "architecture.json").read_text())["documented"]
                         + [{"from": "app", "to": "db", "port": "tcp/1521"}])
        out = Path(tempfile.mkdtemp())
        atone.draw_system("arch", out, log=lambda *a: None)
        ch = atone.read_json(out / "graph.changes.json")
        self.assertIn("app01 -> db01 tcp/1521: undocumented -> normal", ch["changed"])


class A_Bundled(unittest.TestCase):
    """NIST's files ship in the package as plain text: nothing needs the internet."""

    def test_the_catalog_and_baselines_are_in_the_package_and_match_their_hashes(self):
        import hashlib
        lock = json.loads((atone.DATA / "lock.json").read_text())
        for rel, info in lock.items():
            self.assertEqual(hashlib.sha256((atone.DATA / rel).read_bytes()).hexdigest(), info["sha256"], rel)
        cat = atone.load_catalog(atone.DATA / "nist" / "catalog.json")
        self.assertGreater(len(cat), 1000)
        prof = json.loads((atone.DATA / "nist" / "moderate.json").read_text())["profile"]
        ids = [i for imp in prof["imports"] for inc in imp["include-controls"] for i in inc["with-ids"]]
        self.assertEqual(len(ids), 287)                                    # Rev 5 moderate
        self.assertTrue(all(i in cat for i in ids))
        for g in ("sp800-37r2", "sp800-18r1", "sp800-137"):
            self.assertIn("NIST", (atone.DATA / "guidance" / f"{g}.txt").read_text()[:3000])

    def test_a_newer_copy_from_a_folder_without_the_internet(self):
        src = Path(tempfile.mkdtemp())
        shutil.copy(FIX / "catalog.json", src / "NIST_SP-800-53_rev5_catalog.json")    # NIST's own file names
        shutil.copy(FIX / "moderate.json", src / "moderate.json")                       # or atone's
        lock = atone.fetch_sources(str(src), log=lambda *a: None)
        self.assertEqual(set(lock), {"catalog", "moderate"})
        self.assertTrue(lock["catalog"]["url"].endswith("NIST_SP-800-53_rev5_catalog.json"))
        self.assertEqual(atone.sources_dir(), atone.HOME / "sources")


class MoreEvidence(unittest.TestCase):
    def test_a_certificate_decoded_with_the_standard_library(self):
        import ssl
        pem = (FIX / "cert.pem").read_text()
        info = atone.decode_cert(ssl.PEM_cert_to_DER_cert(pem))
        self.assertEqual(info["subject"], "commonName=app01.example.internal")
        self.assertIn("app01.example.internal", info["names"])
        self.assertTrue(info["self_signed"])

    def test_old_tls_and_expiring_certificates_are_caught(self):
        tls = [{"port": 443, "protocol": "TLSv1.3", "days_left": 200}, {"port": 8443, "protocol": "TLSv1.1", "days_left": 12}]
        rec = atone.make_record("t", "certs", "h1", "TLS on listeners", tls)
        m = {x["control"]: x for x in atone.STARTER_MAPPINGS}
        self.assertEqual(atone.run_check(m["sc-8"]["checks"][0], [rec], "sc-8", {})["status"], "fail")
        self.assertEqual(atone.run_check(m["sc-17"]["checks"][0], [rec], "sc-17", {})["status"], "fail")
        ok = atone.make_record("t", "certs", "h1", "TLS on listeners", tls[:1])
        self.assertEqual(atone.run_check(m["sc-8"]["checks"][0], [ok], "sc-8", {})["status"], "pass")
        self.assertEqual(atone.run_check(m["sc-17"]["checks"][0], [ok], "sc-17", {})["status"], "pass")

    def test_evidence_search_is_ranked_and_follows_the_current_evidence(self):
        d = evidence_system("srch", [("file", "h1", "/etc/audit/auditd.conf", AUDITD),
                                     ("file", "h1", "/etc/chrony.conf", "server time.example.internal iburst\n")])
        hits = atone.search_evidence(d, "keep_logs")
        self.assertEqual([h["source"] for h in hits], ["/etc/audit/auditd.conf"])
        self.assertIn("[keep_logs]", hits[0]["snippet"])
        import time as _t
        _t.sleep(1.1)
        atone.save_records(d, [atone.make_record("srch", "file", "h1", "/etc/audit/auditd.conf", "max_log_file_action = rotate\n")])
        self.assertEqual(atone.search_evidence(d, "keep_logs"), [])           # superseded: out of the index

    def test_eaveswatch_shows_logging_retention_and_review(self):
        ew = Path(tempfile.mkdtemp())
        base = ew / "systems" / "system=web"
        (base / "interpreter").mkdir(parents=True)
        (base / "interpreter" / "v1.json").write_text(json.dumps({"sources": [{"name": "app", "path": "/var/log/app/*.log"}]}))
        (base / "interpreter" / "v2.json").write_text(json.dumps({"sources": [{"name": "app", "path": "/var/log/app/*.log"}],
                                                                  "alerts": [{"name": "errors", "match": "ERROR"}]}))
        (base / "nodes").mkdir()
        (base / "nodes" / "app01.json").write_text(json.dumps({"host": "app01", "at": "2026-11-21T10:00:00Z", "role": "finial"}))
        (base / "ledger").mkdir()
        (base / "ledger" / "e1.json").write_text(json.dumps({"at": "2026-11-20", "title": "disk filling", "severity": "warn"}))
        for day in ("2026-08-01", "2026-11-20"):
            (ew / "env=prod" / "kind=packets" / f"dt={day}" / "hour=10" / "host=app01").mkdir(parents=True)
        d = evidence_system("ewsys", [])
        atone.import_results("ewsys", eaveswatch=str(ew), ew_system="web", log=lambda *a: None)
        idx = {e["source"]: e for e in atone.current_index(d)}
        self.assertIn("eaveswatch interpreter v2", idx)                          # the newest version
        archive = json.loads(atone.load_record(d, idx["eaveswatch archive (prod)"])["content"])
        self.assertEqual(archive["days_kept"], 112)
        self.assertEqual(archive["kinds"]["packets"]["hosts_latest"], ["app01"])
        m = {x["control"]: x for x in atone.STARTER_MAPPINGS}
        recs = [atone.load_record(d, idx["eaveswatch archive (prod)"])]
        chk = next(c for c in m["au-11"]["checks"] if c["id"] == "archive-reaches-back")
        self.assertEqual(atone.run_check(chk, recs, "au-11", {"au-11_odp": "90 days"})["status"], "pass")
        self.assertEqual(atone.run_check(chk, recs, "au-11", {"au-11_odp": "365 days"})["status"], "fail")
        spec = [atone.load_record(d, idx["eaveswatch interpreter v2"])]
        self.assertEqual(atone.run_check(m["au-6"]["checks"][1], spec, "au-6", {})["status"], "pass")


class PlanAndReport(unittest.TestCase):
    def test_the_plan_says_who_does_what_and_ticks_what_is_done(self):
        d = evidence_system("plan", [("file", "app01", "/etc/audit/auditd.conf", AUDITD)])
        spec = atone.read_json(d / "system.json")
        spec["hosts"] = [{"name": "app01"}, {"name": "db01"}]
        atone.write_json(d / "system.json", spec)
        atone.check_system("plan", log=lambda *a: None)
        p = {i["id"]: i for i in atone.plan("plan")["items"]}
        self.assertEqual((p["documents"]["who"], p["documents"]["done"]), ("person", False))
        self.assertEqual((p["inherited"]["who"], p["inherited"]["done"]), ("person", False))     # always asked
        self.assertEqual((p["access:db01"]["who"], p["access:db01"]["done"]), ("access", False))
        self.assertIn("map:ac-11", p)                                                             # no mapping yet
        self.assertTrue(any(i.startswith("person:au-11") for i in p))                             # needs_person
        t = atone.read_json(d / "tailoring.json")
        t["inherited"] = {"pe-3": {"from": "AWS GovCloud"}}
        atone.write_json(d / "tailoring.json", t)
        self.assertTrue({i["id"]: i for i in atone.plan("plan")["items"]}["inherited"]["done"])
        self.assertIn("## Needs a person", (d / "PLAN.md").read_text())

    def test_due_is_quiet_until_something_is(self):
        d = evidence_system("due", [("file", "h1", "/etc/audit/auditd.conf", AUDITD)])
        lines = atone.due("due")
        self.assertTrue(any(l.startswith("check:") for l in lines))
        atone.check_system("due", log=lambda *a: None)
        atone.report("due", Path(tempfile.mkdtemp()), conmon=True, log=lambda *a: None)
        self.assertEqual(atone.due("due"), [])                    # collected, checked, the month's package done

    def test_the_report_escapes_what_it_shows(self):
        d = evidence_system("rep", [("file", "h1", "/etc/audit/auditd.conf", AUDITD + "<script>alert(1)</script>\n")])
        m = atone.read_json(d / "mappings" / "starter.json")
        m.append({"control": "ac-11", "evidence": [{"name": "f", "kind": "file"}],
                  "checks": [{"id": "x", "type": "present", "evidence": "f", "pattern": "script"}]})
        atone.write_json(d / "mappings" / "starter.json", m)
        atone.check_system("rep", log=lambda *a: None)
        html = atone.report("rep", Path(tempfile.mkdtemp()), log=lambda *a: None).read_text()
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;alert", html)


class Pack(unittest.TestCase):
    def test_the_hobkin_pack_is_a_chore_with_its_skills(self):
        os.environ["XDG_CACHE_HOME"] = tempfile.mkdtemp()
        root = Path(atone.hobkin_pack())
        chore = root / "chores" / "atone"
        spec = json.loads((chore / "chore.json").read_text())
        self.assertEqual(spec["name"], "atone")
        self.assertEqual(spec["config"]["wake"]["command"], "atone due {{system}}")
        self.assertIn("No citation, no claim", (chore / "CHORE.md").read_text())
        skills = sorted(p.name for p in (chore / "skills").iterdir())
        self.assertEqual(skills, sorted(atone.SKILLS))
        head = (chore / "skills" / "atone-narratives" / "SKILL.md").read_text().split("---")[1]
        self.assertIn("name: atone-narratives", head)
        self.assertRegex(head, r'description: ".+"')               # quoted: descriptions have colons


class CommandLine(unittest.TestCase):
    def test_init_collect_and_look_at_the_evidence(self):
        code, out = run("init", "cli")
        self.assertEqual(code, 0)
        code, out = run("collect", "cli", "--kind", "accounts")
        self.assertEqual(code, 0)
        self.assertIn("records in run", out)
        code, out = run("evidence", "cli")
        first = out.split()[0]
        self.assertTrue(first.startswith("accounts."))
        code, out = run("evidence", "cli", "show", first)
        self.assertIn("verified", out.splitlines()[0])
        code, out = run("evidence", "cli", "search", "root")
        self.assertIn("passwd entries", out)

    def test_discover_lists_config_files_but_never_reads_them(self):
        run("init", "disc")
        code, out = run("discover", "disc")
        self.assertEqual(code, 0)
        found = atone.read_json(atone.system_dir("disc") / "discovery.json")["hosts"][0]
        self.assertTrue(found["processes"])
        self.assertTrue(all(isinstance(c, str) for c in found["configs"]))   # paths only
        self.assertFalse(any(atone.denied(c) for c in found["configs"]))


if __name__ == "__main__":
    unittest.main(verbosity=1)
