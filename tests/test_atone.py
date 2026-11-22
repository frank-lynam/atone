"""atone's tests: fixtures only (no AWS, no network, no model). python3 tests/test_atone.py"""
import gzip
import io
import json
import os
import shutil
import subprocess
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

    def test_evidence_in_the_codex_at_stable_paths_committed_only_when_it_changes(self):
        d = atone.init_system("codexev", None)
        mk = lambda text: atone.make_record("codexev", "file", "h1", "/etc/app.conf", text)
        changed = atone.save_records(d, [mk("port=8443\n")])
        self.assertRegex(changed[0]["path"], r"^evidence/h1/file/etc_app\.conf(-[0-9a-f]{6})?\.txt$")
        self.assertEqual((d / changed[0]["path"]).read_text(), "port=8443\n")           # as it is: readable in a diff
        commits = lambda: atone.git(d, "rev-list", "--count", "HEAD").stdout.strip()
        n = commits()
        self.assertEqual(atone.save_records(d, [mk("port=8443\n")]), [])                 # the same again: nothing
        self.assertEqual(commits(), n)
        atone.save_records(d, [mk("port=9443\n")])                                       # the system changed
        self.assertEqual(int(commits()), int(n) + 1)
        diff = atone.git(d, "show", "HEAD", "--", changed[0]["path"]).stdout
        self.assertIn("-port=8443", diff)
        self.assertIn("+port=9443", diff)
        rec = atone.load_record(d, atone.current_index(d)[0])
        self.assertTrue(atone.check_record(rec) and not rec.get("tampered"))

    def test_the_codex_refuses_a_secret_whoever_commits_it(self):
        d = atone.init_system("guarded", None)
        (d / "decisions" / "oops.json").write_text('{"note": "the db password=hunter2 for now"}\n')
        with self.assertRaises(atone.AtoneError) as e:
            atone.codex_commit(d, "a note")
        self.assertIn("redaction floor", str(e.exception))
        atone.git(d, "add", "-A")                                                          # a person, with plain git
        r = subprocess.run(["git", "-C", str(d), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)                                               # the hook refuses it
        self.assertIn("redaction floor", r.stderr)

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
        for f in ("oscap-results.xml", "vulns-export.csv"):
            shutil.copy(FIX / f, d / "imports" / f)
        shutil.copy(FIX / "vulns.mapping.json", d / "mappings" / "scanners" / "vulns.mapping.json")
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
        self.assertEqual(v["coverage"], {"evidence": 1, "document": 0, "person": 1, "dropped": 2})
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
        for f in ("oscap-results.xml", "vulns-export.csv"):
            shutil.copy(FIX / f, d / "imports" / f)
        shutil.copy(FIX / "vulns.mapping.json", d / "mappings" / "scanners" / "vulns.mapping.json")
        atone.import_results(name, log=lambda *a: None)
        t = atone.read_json(d / "tailoring.json")
        t["inherited"] = {"pe-3": {"from": "AWS GovCloud"}}
        atone.write_json(d / "tailoring.json", t)
        atone.check_system(name, log=lambda *a: None)
        for f, m in (("ssp-matrix.xlsx", SSP_MAP), ("poam.xlsx", POAM_MAP)):
            shutil.copy(FIX / f, d / "workbooks" / f)
            atone.write_json(d / "mappings" / "workbooks" / (f.split(".")[0] + ".mapping.json"), m)
        return d

    def test_filling_the_ssp_keeps_whats_there_and_flags_disagreements(self):
        d = self.system("fillssp")
        eid = next(e["id"] for e in atone.current_index(d) if e["kind"] == "file")
        atone.save_statement(d, atone.verify_narrative(d, {"control": "ac-11", "claims": [
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
        atone.write_json(d / "mappings" / "workbooks" / "ssp-matrix.mapping.json",
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
        atone.write_json(cls.d / "interfaces.json", fx["documented"])
        atone.save_records(cls.d, [atone.make_record("arch", k, h, src, c) for k, h, src, c in fx["records"]])
        cls.out = Path(tempfile.mkdtemp())
        cls.g = atone.draw_system("arch", cls.out, log=lambda *a: None)
        cls.edges = {(e["from"], e["to"], e["port"]): e["class"] for e in cls.g["edges"]}

    def test_each_path_is_classed_by_what_the_three_layers_say(self):
        self.assertEqual(self.edges[("internet", "web01", "tcp/443")], "normal")
        self.assertEqual(self.edges[("web01", "app01", "tcp/9000")], "normal")           # all three agree
        self.assertEqual(self.edges[("internet", "web01", "tcp/22")], "unused")           # open, never used
        self.assertEqual(self.edges[("app01", "db01", "tcp/1521")], "undocumented")       # allowed, used, not in the SSP
        self.assertEqual(self.edges[("app01", "52.94.0.10", "tcp/443")], "unexpected")      # nothing explains it

    def test_intentional_connections_come_from_the_config_files(self):
        e = {(x["from"], x["to"], x["port"]): x for x in self.g["edges"]}
        self.assertIn("configured", e[("web01", "app01", "tcp/9000")]["layers"])           # nginx's proxy_pass
        self.assertEqual(e[("app01", "db01", "tcp/1521")]["config"]["file"], "/opt/app/application.properties")
        self.assertEqual(self.edges[("app01", "smtp.example.internal", "tcp/25")], "idle")      # intended, documented, quiet
        self.assertEqual(self.edges[("app01", "backup.example.internal", "tcp/443")], "undocumented")
        self.assertEqual(self.edges[("app01", "db01", "tcp/5432")], "blocked")                # configured; no rule allows it
        web = next(n for n in self.g["nodes"] if n["id"] == "web01")
        self.assertEqual(web["configured_listens"], [443])
        self.assertEqual(self.edges[("db01", "backup.example.internal", "tcp/443")], "documented only")
        self.assertEqual(self.edges[("34.200.1.7", "web01", "tcp/443")], "normal")         # covered by 0.0.0.0/0

    def test_aws_load_balancers_databases_and_reachability(self):
        e = {(x["from"], x["to"], x["port"]): x for x in self.g["edges"]}
        self.assertEqual(self.edges[("internet", "public-alb", "tcp/443")], "idle")          # its listener: the way in
        self.assertIn("configured", e[("public-alb", "web01", "tcp/8443")]["layers"])           # its target group
        self.assertEqual(self.edges[("public-alb", "web01", "tcp/8443")], "idle")
        self.assertEqual(e[("app01", "reports-db", "tcp/5432")]["config"]["file"], "/opt/app/application.properties")
        self.assertTrue(e[("app01", "reports-db", "tcp/5432")]["allowed_by_rule"])           # by name: its endpoint
        self.assertFalse(e[("internet", "db01", "tcp/22")]["reachable"])                     # private: rule, no route
        self.assertTrue(e[("internet", "web01", "tcp/22")]["reachable"])
        self.assertEqual(self.edges[("app01", "52.94.0.10", "tcp/443")], "unexpected")       # egress doesn't name it

    def test_the_security_group_review(self):
        f = {(x["group"], x["what"].split(" ")[0] + " " + x["what"].split(" ")[1]): x for x in self.g["security_groups"]}
        found = sorted((x["group"], x["severity"]) for x in self.g["security_groups"])
        self.assertIn(("sg-web", "high"), found)                                              # SSH to the world
        self.assertTrue(next(x for x in self.g["security_groups"] if x["group"] == "sg-web")["reachable"])
        ssh_db = next(x for x in self.g["security_groups"] if x["group"] == "sg-db")
        self.assertEqual((ssh_db["severity"], ssh_db["reachable"]), ("high", False))          # open, but not routed
        whats = {x["group"]: [y["what"] for y in self.g["security_groups"] if y["group"] == x["group"]]
                 for x in self.g["security_groups"]}
        self.assertTrue(any("attached to nothing" in w for w in whats["sg-old"]))
        self.assertTrue(any("RDP" in w for w in whats["sg-old"]))
        self.assertTrue(any("default group allows traffic" in w for w in whats["sg-default"]))
        self.assertTrue(any("sg-gone" in w for w in whats["sg-app"]))
        self.assertNotIn("sg-alb", whats)                                                     # 443 to the world: meant
        self.assertTrue(f)

    def test_sc7_and_cm7_check_the_security_groups(self):
        recs = [atone.load_record(self.d, e) for e in atone.current_index(self.d) if e["kind"] == "aws"]
        m = {x["control"]: x for x in atone.STARTER_MAPPINGS}
        sc7 = atone.run_check(m["sc-7"]["checks"][0], recs, "sc-7", {})
        self.assertEqual(sc7["status"], "fail")
        self.assertIn("1 reachable from the internet", sc7["detail"])                # web01's SSH; db01's isn't
        self.assertTrue(any("sg-web" in q["quote"] and "reachable from the internet" in q["quote"] for q in sc7["quotes"]))
        cm7 = atone.run_check(next(c for c in m["cm-7"]["checks"] if c["type"] == "security_groups"), recs, "cm-7", {})
        self.assertEqual(cm7["status"], "fail")                                      # sg-old: attached to nothing
        html = atone.report("arch", Path(tempfile.mkdtemp()), log=lambda *a: None).read_text()
        self.assertIn("<h2>Security groups</h2>", html)
        self.assertIn("opens SSH to the whole internet", html)

    def test_the_boundary_and_what_crosses_it(self):
        inside = {n["id"] for n in self.g["nodes"] if n["inside"]}
        self.assertEqual(inside, {"web01", "app01", "db01", "public-alb", "reports-db"})
        self.assertIn("app01 -> 52.94.0.10 tcp/443", self.g["crossing"])

    def test_drawio_and_svg_are_well_formed_and_say_what_they_show(self):
        import xml.etree.ElementTree as ET
        model = ET.parse(self.out / "network.drawio").getroot()
        cells = model.findall(".//mxCell")
        self.assertTrue(any(c.get("id") == "boundary" for c in cells))
        self.assertEqual(sum(1 for c in cells if c.get("edge") == "1" and c.get("source")), len(self.g["edges"]))
        self.assertTrue(any("dashed=1" in (c.get("style") or "") for c in cells if c.get("source")))
        ET.parse(self.out / "network.svg")

    def test_connections_are_a_set_that_grows_and_recent_ones_count(self):
        d = atone.init_system("overtime", None)
        fx = json.loads((FIX / "architecture.json").read_text())
        atone.write_json(d / "system.json", fx["spec"])
        batch = {"proto": "tcp", "direction": "out", "local": "10.0.2.20", "remote": "10.0.3.30:5433", "process": "nightly batch"}
        recs = [atone.make_record("overtime", k, h, src, c) for k, h, src, c in fx["records"] if k != "flows"]
        recs.append(atone.make_record("overtime", "flows", "app01", "connections", [batch]))
        atone.save_records(d, recs)
        n = atone.git(d, "rev-list", "--count", "HEAD").stdout
        atone.save_records(d, [atone.make_record("overtime", "flows", "app01", "connections", [])])  # closed since
        self.assertEqual(atone.git(d, "rev-list", "--count", "HEAD").stdout, n)          # nothing new: no commit
        e = {(x["from"], x["to"], x["port"]): x for x in atone.build_graph("overtime")["edges"]}
        self.assertIn("actual", e[("app01", "db01", "tcp/5433")]["layers"])                # seen, in the window
        seen = atone.read_json(d / "runs" / "connections-seen.json")
        for k in seen:
            seen[k] -= 40 * 86400                                                            # last seen long ago
        atone.write_json(d / "runs" / "connections-seen.json", seen)
        e = {(x["from"], x["to"], x["port"]): x for x in atone.build_graph("overtime")["edges"]}
        self.assertNotIn(("app01", "db01", "tcp/5433"), e)                                  # not seen recently

    def test_what_changed_since_the_last_drawing(self):
        atone.write_json(self.d / "interfaces.json", json.loads((FIX / "architecture.json").read_text())["documented"]
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


class Configured(unittest.TestCase):
    """Intentional connections, from config files, with readers that know no product."""

    def ends(self, text, patterns=None):
        r = atone.extract_endpoints(text, patterns)
        return [(c["host"], c["port"]) for c in r["connects"]], [l["port"] for l in r["listens"]]

    def test_urls_jdbc_tns_and_nearby_settings(self):
        conn, listen = self.ends("server.port=9000\nspring.datasource.url=jdbc:oracle:thin:@//db01.ex.internal:1521/P\n"
                                 "ldap.url=ldaps://ldap.ex.internal\nmail.host=smtp.ex.internal\nmail.port=25\n")
        self.assertEqual(conn, [("db01.ex.internal", 1521), ("ldap.ex.internal", 636), ("smtp.ex.internal", 25)])
        self.assertEqual(listen, [9000])
        self.assertEqual(self.ends("PROD=(ADDRESS=(PROTOCOL=TCP)(HOST=db01)(PORT=1521))")[0], [("db01", 1521)])
        self.assertEqual(self.ends("<url>jdbc:oracle:thin:@db01:1521:PROD</url>")[0], [("db01", 1521)])

    def test_what_isnt_a_connection(self):
        conn, _ = self.ends("# proxy_pass http://old.ex.internal:8080;\ncache=redis://localhost:6379\n"
                            "<domain xmlns=\"http://xmlns.oracle.com/weblogic/domain\">\nAPI=https://${API_HOST}/v1\n")
        self.assertEqual(conn, [])

    def test_listeners_in_their_usual_forms(self):
        for text, want in (("    listen 443 ssl;", [443]), ("listen [::]:8443 ssl http2;", [8443]), ("Port 22", [22]),
                           ("<listen-port>7001</listen-port><ssl-listen-port>7002</ssl-listen-port>", [7001, 7002])):
            self.assertEqual(self.ends(text)[1], want, text)

    def test_a_system_specs_own_pattern(self):
        pat = [{"pattern": r"WSL=//(?P<host>[\w.-]+):(?P<port>\d+)", "about": "a WSL address"}]
        self.assertEqual(self.ends("WSL=//jolt01:9100\n", pat)[0], [("jolt01", 9100)])


class Oscal(unittest.TestCase):
    """OSCAL 1.1.2 (checked against NIST's schemas by hand: they need modules beyond the standard library)."""

    def test_the_ssp_claims_only_what_the_checks_say(self):
        d = Workbooks().system("osc")                     # evidence, scans, tailoring (PE-3 inherited), checks
        out = Path(tempfile.mkdtemp())
        atone.write_oscal("osc", out, log=lambda *a: None)
        ssp = json.loads((out / "ssp.json").read_text())["system-security-plan"]
        for key in ("uuid", "metadata", "import-profile", "system-characteristics", "system-implementation",
                    "control-implementation"):
            self.assertIn(key, ssp)
        reqs = {r["control-id"]: r for r in ssp["control-implementation"]["implemented-requirements"]}
        self.assertEqual(reqs["au-11"]["by-components"][0]["implementation-status"], {"state": "partial"})
        self.assertNotIn("implementation-status", reqs["ac-11"]["by-components"][0])        # unknown: no claim
        self.assertIn("to be described by a person", reqs["ac-11"]["by-components"][0]["description"])
        self.assertEqual(reqs["pe-3"]["by-components"][0]["description"], "Inherited from AWS GovCloud.")
        poam = json.loads((out / "poam.json").read_text())["plan-of-action-and-milestones"]
        self.assertTrue(any(i["title"] == "Oracle JDK out of date" for i in poam["poam-items"]))
        ar = json.loads((out / "assessment-results.json").read_text())["assessment-results"]
        self.assertTrue(ar["results"][0]["observations"])
        again = Path(tempfile.mkdtemp())
        atone.write_oscal("osc", again, log=lambda *a: None)                      # the same uuids: diffs are real
        self.assertEqual(json.loads((again / "ssp.json").read_text())["system-security-plan"]["uuid"], ssp["uuid"])


class Codex(unittest.TestCase):
    """The codex: the model and the history. Reviews, decisions, the POA&M, packages, and a fresh machine."""

    def test_draft_review_decide_package_and_the_history_of_it(self):
        d = Workbooks().system("hist")                    # evidence, scans, PE-3 inherited, checks, workbooks
        self.assertTrue(atone.codex_commit(d, "the tailoring, mappings and workbooks"))   # a person's edits, committed
        eid = next(e["id"] for e in atone.current_index(d) if e["kind"] == "file")
        atone.save_statement(d, atone.verify_narrative(d, {"control": "au-11", "claims": [
            {"text": "Rotated audit logs are kept.", "cites": [{"evidence": eid, "quote": "max_log_file_action = keep_logs"}]}]}))
        ctl = atone.read_json(atone.control_path(d, "au-11"))
        self.assertEqual((ctl["statement"]["text"], ctl["statement"]["reviewed_by"]), ("Rotated audit logs are kept.", None))
        atone.review_statements(d, ["au-11"], "Jane Doe (ISSE)")
        self.assertEqual(atone.read_json(atone.control_path(d, "au-11"))["statement"]["reviewed_by"], "Jane Doe (ISSE)")
        h = atone.history(d, control="au-11")
        self.assertEqual([c["subject"] for c in h[:2]], ["review: AU-11", "AU-11: implementation statement drafted"])
        self.assertIn("Reviewed-by: Jane Doe (ISSE)", h[0]["trailers"])
        self.assertIn(f"Evidence: {eid}", h[1]["trailers"])
        atone.check_system("hist", log=lambda *a: None)                     # checks keep the statement and review
        self.assertEqual(atone.read_json(atone.control_path(d, "au-11"))["statement"]["reviewed_by"], "Jane Doe (ISSE)")
        # decisions: a risk acceptance; the POA&M schedule approved; an item closed
        atone.decide(d, "risk-acceptance", "TLS 1.0 stays on the legacy port until the vendor upgrade", "Sam Roe (ISSO)",
                     ["sc-8"], "2027-03-01")
        poam = {x["key"]: x for x in (atone.read_json(p) for p in (d / "poam").glob("*.json"))}
        key = next(k for k, x in poam.items() if x["weakness"] == "Oracle JDK out of date")
        atone.write_json(d / "drafts" / "poam-schedule.json", {key: "2027-01-15"})
        atone.codex_commit(d, "poam: a proposed schedule")                              # the agent's proposal
        self.assertEqual(atone.approved_schedule(d), {})                    # proposed isn't approved
        atone.decide(d, "poam-schedule", "dates as proposed", "Sam Roe (ISSO)")
        self.assertEqual(atone.approved_schedule(d), {key: "2027-01-15"})
        atone.decide(d, "poam-close", "patched and rescanned", "Sam Roe (ISSO)", items=[key])
        closed = next(atone.read_json(p) for p in (d / "poam").glob("*.json") if atone.read_json(p)["key"] == key)
        self.assertEqual((closed["status"], closed["closed_by"]), ("closed", "Sam Roe (ISSO)"))
        self.assertTrue(any("Decided-by: Sam Roe (ISSO)" in c["trailers"] for c in atone.history(d, path="decisions")))
        # a package: generated into packages/TAG, committed and tagged; never replaced
        out = atone.package("hist", "conmon-2026-11", "November", log=lambda *a: None)
        for f in ("ssp-matrix.xlsx", "poam.xlsx", "network.drawio", "report.html", "oscal/ssp.json"):
            self.assertTrue((out / f).exists(), f)
        self.assertEqual(atone.git(d, "tag", "-l").stdout.split(), ["conmon-2026-11"])
        self.assertEqual(atone.git(d, "status", "--porcelain").stdout.strip(), "")       # everything committed
        with self.assertRaises(atone.AtoneError):
            atone.package("hist", "conmon-2026-11", log=lambda *a: None)

    def test_a_fresh_machine_clones_the_codex(self):
        d = evidence_system("orig", [("file", "h1", "/etc/audit/auditd.conf", AUDITD)])
        bare = Path(tempfile.mkdtemp()) / "orig.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "master", str(bare)], check=True)   # a server's default
        subprocess.run(["git", "-C", str(d), "push", "-q", str(bare), "main"], check=True)
        other = Path(tempfile.mkdtemp())
        old = atone.HOME
        try:
            atone.HOME = other                                                    # another machine's ~/atone
            d2 = atone.init_system("orig", from_url=str(bare))
            self.assertEqual([e["id"] for e in atone.current_index(d2)], [e["id"] for e in atone.current_index(d)])
            self.assertTrue((d2 / ".git" / "hooks" / "pre-commit").exists())     # the guard, on this machine too
            self.assertIsNone(atone.current_index(d2)[0]["last_seen"])           # it hasn't collected here yet
            self.assertIn("codex: orig set up", atone.git(d2, "log", "--format=%s").stdout)     # its history, not a new one
        finally:
            atone.HOME = old


class Atonement(unittest.TestCase):
    """The attack graph: drafted as data, checked against its evidence, analysed by plain code (the self-pruning
    spanning tree): exposure, controls, the fewest lock-downs, what-ifs, blind spots, and lock-downs that stay."""

    def system(self, name):
        d = evidence_system(name, [
            ("file", "web01", "/etc/nginx/sites-enabled/app", "server { listen 443 ssl; proxy_pass http://127.0.0.1:8080; }"),
            ("aws", "aws", "s3api get-bucket-policy payroll-export", '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/app"}}]}'),
            ("aws", "aws", "ec2 describe-instances", '{"HttpTokens": "optional", "IamInstanceProfile": "app"}')])
        ids = {e["source"]: e["id"] for e in atone.current_index(d)}
        atone.write_json(d / "attack" / "conditions.json", [
            {"id": "net:internet", "kind": "access"}, {"id": "access:web", "kind": "access"},
            {"id": "exec:web", "kind": "execution"}, {"id": "cred:app-role", "kind": "credential"},
            {"id": "data:payroll", "kind": "data"}, {"id": "cond:elsewhere", "kind": "access"},
            {"id": "cred:admin", "kind": "credential"},
            {"id": "effect:payroll-read", "kind": "effect", "impact": "high", "consequence": "everyone's pay exposed"},
            {"id": "effect:payroll-tamper", "kind": "effect", "impact": "high"}])
        atone.write_json(d / "attack" / "profiles.json", [{"id": "internet", "starts": ["net:internet"]}])
        step = lambda sid, **kw: atone.write_json(d / "attack" / "steps" / f"{sid}.json", {"id": sid, **kw})
        nginx, policy, ec2 = ids["/etc/nginx/sites-enabled/app"], ids["s3api get-bucket-policy payroll-export"], ids["ec2 describe-instances"]
        step("web-open", **{"from": "net:internet", "to": "access:web", "effort": "free", "basis": "evidence",
                            "cites": [{"evidence": nginx, "quote": "listen 443 ssl"}], "detection": [{"by": "ALB logs"}]})
        step("web-rce", **{"from": "access:web", "to": "exec:web", "technique": "T1190", "effort": "commodity",
                           "basis": "assumed", "detection": [{"by": "WAF"}]})
        step("imds", **{"from": "exec:web", "to": "cred:app-role", "technique": "T1552.005", "effort": "free",
                        "basis": "evidence", "cites": [{"evidence": ec2, "quote": '"HttpTokens": "optional"'}]})
        step("bucket-read", **{"from": "cred:app-role", "to": "data:payroll", "technique": "T1530", "effort": "free",
                               "basis": "evidence", "cites": [{"evidence": policy, "quote": "role/app"}],
                               "detection": [{"by": "CloudTrail data events"}]})
        step("exfil", **{"from": "data:payroll", "to": "effect:payroll-read", "effort": "free", "basis": "assumed",
                         "detection": [{"by": "VPC flow logs"}]})
        step("bucket-public", **{"from": "net:internet", "to": "data:payroll", "effort": "blocked", "basis": "evidence",
                                 "cites": [{"evidence": policy, "quote": "role/app"}], "detection": [{"by": "CloudTrail"}]})
        step("side-trip", **{"from": "exec:web", "to": "cond:elsewhere", "effort": "free", "basis": "assumed"})
        step("tamper", **{"from": "net:internet", "to": "effect:payroll-tamper", "requires": ["cred:admin"],
                          "effort": "free", "basis": "assumed"})
        step("claims-too-much", **{"from": "net:internet", "to": "cond:elsewhere", "effort": "blocked",
                                   "basis": "evidence", "cites": [{"evidence": nginx, "quote": "mTLS required"}]})
        return d

    def test_the_spanning_tree_keeps_exactly_the_paths(self):
        adj = {"a": [("b", 1), ("x", 2)], "b": [("c", 3)], "x": [("y", 4)], "c": [("b", 5)], "z": [("c", 6)]}
        sub = atone.spst(adj, ["a"], ["c"])
        self.assertEqual({k for v in sub.values() for _, k in v}, {1, 3, 5})   # not the dead end, nor z (unreachable)

    def test_exposure_controls_the_fewest_lock_downs_and_blind_spots(self):
        d = self.system("atone1")
        a = atone.analyse_attack(d)
        pair = {(x["profile"], x["effect"]): x for x in a["pairs"]}
        x = pair[("internet", "effect:payroll-read")]
        self.assertEqual((x["exposure"], x["layers"], x["ok"]), ("commodity", 0, False))   # through the assumed RCE
        self.assertEqual(len(x["cut"]), 1)                                           # one lock-down cuts it
        self.assertNotIn("side-trip", x["steps"])                                    # not on a path: pruned
        self.assertEqual(x["unseen"], ["imds"])                                      # nothing watches the metadata grab
        self.assertNotIn(("internet", "effect:payroll-tamper"), pair)                # needs cred:admin: no way there
        self.assertIn("web-rce", a["assumed"])
        self.assertTrue(any("claims-too-much" in p and "doesn't hold" in p for p in a["problems"]))   # unproven control
        self.assertFalse(a["done"])
        # what if the metadata service needed tokens: only the bucket's own control stands, so one control
        w = atone.analyse_attack(d, close=["imds"])
        y = {(x["profile"], x["effect"]): x for x in w["pairs"]}[("internet", "effect:payroll-read")]
        self.assertEqual((y["exposure"], y["layers"]), (None, 1))
        self.assertEqual(y["single_control"], ["bucket-public", "imds"])
        text = atone.attack_report(a, paths=3)
        self.assertIn("OPEN internet -> effect:payroll-read", text)
        self.assertIn("path: web-open [free] -> web-rce [commodity] -> imds [free] -> bucket-read [free] -> exfil [commodity]", text)

    def test_a_lock_down_holds_while_its_check_passes(self):
        d = self.system("atone2")
        atone.write_json(d / "risks" / "imdsv2.json", {
            "id": "imdsv2", "closes": ["imds"], "change": "require IMDSv2 tokens on the instances",
            "check": {"evidence": {"kind": "aws", "source": "ec2 describe-instances"}, "type": "present",
                      "pattern": '"HttpTokens": "required"'}})
        self.assertEqual(atone.analyse_attack(d)["risks"]["imdsv2"], "fail")       # not done yet: still open
        atone.save_records(d, [atone.make_record("atone2", "aws", "aws", "ec2 describe-instances",
                                                 '{"HttpTokens": "required", "IamInstanceProfile": "app"}')])
        a = atone.analyse_attack(d)
        self.assertEqual(a["risks"]["imdsv2"], "pass")
        x = {(x["profile"], x["effect"]): x for x in a["pairs"]}[("internet", "effect:payroll-read")]
        self.assertEqual((x["exposure"], x["layers"]), (None, 1))                   # locked: the check is the control

    def test_the_plan_puts_atonement_first_and_people_decide(self):
        d = self.system("atone3")
        atone.write_json(d / "risks" / "imdsv2.json", {"id": "imdsv2", "closes": ["web-rce"],
                                                       "change": "patch the app and put a WAF rule in front"})
        ids = [i["id"] for i in atone.plan("atone3")["items"]]
        self.assertLess(ids.index("attack-graph"), ids.index("documents"))
        self.assertIn("atone:internet->effect:payroll-read", ids)
        self.assertIn("risk:imdsv2", ids)
        atone.write_json(d / "engagement.json", {"targets": ["replica-web01"], "depth": "exploit"})
        atone.decide(d, "engagement", "replicas only, push hard", "pat")
        self.assertEqual(atone.read_json(d / "engagement.json", {})["agreed"]["by"], "pat")
        atone.decide(d, "risk-acceptance", "the app is retired next month", "pat", items=["imdsv2"])
        x = {(x["profile"], x["effect"]): x for x in atone.analyse_attack(d)["pairs"]}[("internet", "effect:payroll-read")]
        self.assertEqual((x["ok"], x["accepted"]), (False, ["imdsv2"]))       # accepted, never called safe
        self.assertIn("ACCEPTED internet -> effect:payroll-read", atone.attack_report(atone.analyse_attack(d)))

    def test_how_much_each_control_carries_and_what_its_failing_would_do(self):
        d = self.system("atone4")
        for sid in ("bucket-public", "bucket-read"):        # one bucket policy blocks both ways to the data
            p = d / "attack" / "steps" / f"{sid}.json"
            atone.write_json(p, {**atone.read_json(p, {}), "effort": "blocked", "control": "s3:payroll-bucket-policy"})
        a = atone.analyse_attack(d)
        x = {(x["profile"], x["effect"]): x for x in a["pairs"]}[("internet", "effect:payroll-read")]
        self.assertEqual((x["exposure"], x["layers"]), (None, 1))
        [c] = atone.control_importance(a["graph"], a)
        self.assertEqual((c["control"], c["steps"], c["paths"], c["pairs"]),
                         ("s3:payroll-bucket-policy", ["bucket-public", "bucket-read"], 2, ["internet -> effect:payroll-read"]))
        self.assertEqual(c["if_failed_open"], ["internet -> effect:payroll-read"])      # nothing else in the way
        text = atone.controls_report([c])
        self.assertIn("gates 2 attack paths across 1 profile-to-effect pair", text)
        self.assertIn("a single point of failure: add a layer here", text)

    def test_the_library_and_the_formats(self):
        self.assertIn("Cloud Instance Metadata API", atone.describe_technique("t1552.005"))
        self.assertIn("ac-2", atone.describe_technique("T1078.004"))                # mapped to 800-53, ids as the catalog's
        self.assertIn("T1552.005", [i for i, _ in atone.search_library("instance metadata credentials")])
        for kind, fmt in atone.attack_formats().items():
            self.assertEqual(atone.format_problems(fmt, fmt["example"]), [], kind)
        self.assertIn("attack formats", atone.describe_format("", atone.attack_formats(), "attack"))


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
        m = atone.read_json(d / "mappings" / "controls" / "starter.json")
        m.append({"control": "ac-11", "evidence": [{"name": "f", "kind": "file"}],
                  "checks": [{"id": "x", "type": "present", "evidence": "f", "pattern": "script"}]})
        atone.write_json(d / "mappings" / "controls" / "starter.json", m)
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
        self.assertIn("pieces of evidence", out)
        code, out = run("evidence", "cli")
        first = out.split()[0]
        self.assertTrue(first.startswith("accounts."))
        code, out = run("evidence", "cli", "show", first)
        self.assertIn("verified", out.splitlines()[0])
        code, out = run("evidence", "cli", "search", "root")
        self.assertIn("passwd entries", out)

    def test_a_claim_can_cite_the_customers_document_and_verify_checks_it_says_so(self):
        d = evidence_system("docs", [("file", "h1", "/etc/audit/auditd.conf", AUDITD)])
        shutil.copy(FIX / "ssp.docx", d / "workbooks" / "ssp.docx")
        v = atone.verify_narrative(d, {"control": "ca-3", "claims": [
            {"text": "The SSP states the web tier accepts HTTPS from the agency network.",
             "cites": [{"document": "workbooks/ssp.docx", "quote": "accepts HTTPS from the agency network"}]},
            {"text": "The SSP says it's quantum.", "cites": [{"document": "workbooks/ssp.docx", "quote": "quantum"}]},
            {"text": "Outside.", "cites": [{"document": "../../etc/passwd", "quote": "root"}]}]})
        self.assertEqual(v["coverage"], {"evidence": 0, "document": 1, "person": 0, "dropped": 2})
        self.assertEqual(len(v["claims"][0]["cites"][0]["sha256"]), 64)
        self.assertIn("no document", v["dropped"][1]["why"])

    def test_evidence_from_a_host_the_system_doesnt_name_isnt_counted(self):
        f = atone.in_boundary({"hosts": [{"name": "app01", "addresses": ["10.0.0.5"]}]})
        self.assertEqual([f(h) for h in ("app01.example.internal", "10.0.0.5", "db01", "10.0.0.6", "aws")],
                         [True, True, False, False, True])
        self.assertTrue(atone.in_boundary({})("anything"))                     # until the spec names hosts

    def test_each_mapping_format_is_written_once_and_checked(self):
        for kind, fmt in atone.mapping_formats().items():
            self.assertEqual(atone.format_problems(fmt, fmt["example"]), [], kind)   # its own example holds
            self.assertIn("example:", atone.describe_format(kind))
        self.assertEqual(atone.format_problems(atone.SCANNER_MAPPING, json.loads((FIX / "vulns.mapping.json").read_text())), [])
        bad = {**atone.SSP_MAPPING["example"], "header-row": 3, "status_values": {"met": "Implemented", "done": "X"}}
        probs = atone.format_problems(atone.SSP_MAPPING, bad)
        self.assertTrue(any("'header-row'" in p for p in probs) and any("'done'" in p for p in probs))
        self.assertTrue(all(atone.format_problems(atone.CONTROL_MAPPING, m) == [] for m in atone.STARTER_MAPPINGS))

    def test_a_word_document_reads_as_text_headings_lists_and_tables(self):
        t = atone.doc_text(FIX / "ssp.docx")                                    # made by LibreOffice, as Word saves
        self.assertIn("## 9.3 Interconnections", t)
        self.assertIn("- web to app on tcp/8443", t)
        self.assertIn("| internet | web | tcp/443 |", t)
        self.assertIn("db_password=<redacted>", t)
        self.assertIn("3: A=Control ID | B=Control Name", atone.doc_text(FIX / "ssp-matrix.xlsx"))

    def test_discover_lists_config_files_but_never_reads_them(self):
        run("init", "disc")
        code, out = run("discover", "disc")
        self.assertEqual(code, 0)
        found = atone.read_json(atone.system_dir("disc") / "discovery.json")["hosts"][0]
        self.assertTrue(found["processes"])
        paths = found["configs"]["named by running processes"] + [
            f"{k}/{f}" for k, fs in found["configs"]["in /etc, by directory"].items() for f in fs]
        self.assertTrue(all(isinstance(c, str) for c in paths))                                # paths only
        self.assertFalse(any(atone.denied(c) for c in paths))


if __name__ == "__main__":
    unittest.main(verbosity=1)
