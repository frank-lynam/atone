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
        src = atone.sources_dir()
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
