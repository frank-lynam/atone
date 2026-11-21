#!/usr/bin/env python3
"""atone: keeps a system's authorization (ATO) true to the system.

An expert pack for hobkin, and a deterministic toolkit anyone can run without an agent. The toolkit never calls a
model: it collects evidence from the real system, checks NIST SP 800-53 controls against it, verifies every claim a
drafted narrative cites, fills in the customer's own workbooks and draws the architecture. The agent (a hobkin with
this pack) drafts, by running the toolkit and reading what it says. See DESIGN.md.

    atone init SYSTEM [--store s3://bucket/prefix | DIR]   a folder for a system (its spec, tailoring, mappings)
    atone discover SYSTEM [--ssh user@host]...   what runs on the hosts: for drafting the system spec
    atone collect SYSTEM [--kind K]... [--ssh user@host]...   evidence, from the built-in collectors
    atone import SYSTEM [FILE]... [--sample FILE]   scanner results (OpenSCAP natively; others through a mapping)
    atone evidence SYSTEM [list | show ID | search WORDS]   the current evidence
    atone mappings SYSTEM         the control mappings (the ISSE's), and anything wrong with them
    atone check SYSTEM [CONTROL]  every control against its mapping and the evidence: met, partly, not met, unknown
    atone verify SYSTEM [DRAFT]...   a drafted narrative's citations, each checked against the evidence it quotes
    atone workbook inspect FILE   a workbook's sheets, headers and drop-downs: for drafting its template mapping
    atone fill SYSTEM --out DIR   copies of the working documents, filled in, with what changed and why
    atone controls fetch          NIST's OSCAL catalog and baselines (recorded with their hashes)
    atone controls SYSTEM [list | show ID]   the system's controls: its baseline, tailored
    atone controls lore [--out FILE]   the catalog as a lore, compiled word for word (no model)
    atone --version

Everything lives under $ATONE_HOME (default ~/atone): sources/ (the OSCAL files), systems/NAME/ (a system's spec,
tailoring, site file, mappings, imports and runs) and, unless a system names another, store/ (its evidence).
Standard library only, plus lorewell for lores.
"""
from __future__ import annotations

import argparse
import fnmatch
import glob
import gzip
import hashlib
import json
import os
import pwd
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

__version__ = "0.1.0"

# ---- map: `grep -n '^# ----' atone.py` lists these sections.
#   settings      where things live, the redaction floor, the credential deny-list
#   store         where evidence goes: a folder, or S3 through the AWS CLI
#   evidence      records (source, time, hash, redacted content), the run index, finding evidence
#   collectors    the built-in, read-only menu (COLLECTORS), run here or over ssh; discovery
#   imports       scanner results: OpenSCAP natively, anything else through a mapping file
#   controls      NIST's OSCAL catalog and baselines, the system's tailoring, the exact lore
#   system        a system's folder: spec, tailoring, site file; collecting and importing into it
#   checks        control mappings (the ISSE's), the check engine, verifying a narrative's citations
#   workbooks     the customer's Excel files: read, filled in (a copy, only cell values), what changed
#   command line  argument parsing, main


# ---- settings: where things live, the redaction floor, the credential deny-list

HOME = Path(os.environ.get("ATONE_HOME") or "~/atone").expanduser()

# Never stored, whoever collects it, before anything is written: keys, tokens, passwords, credentials in URLs, long
# secret-looking blobs. Always on; a system can only add to it.
REDACT = [
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "<redacted key>"),
    (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "<redacted>"),                                 # AWS access key ids
    (r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}", "<redacted>"),                              # API keys (sk-...)
    (r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}", "<redacted>"),
    (r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}", "<redacted>"),                          # JWTs
    (r"(?i)\b(bearer|basic)\s+[\w.~+/=-]{8,}", r"\1 <redacted>"),                     # Authorization: Bearer ...
    (r"(?i)(\b[\w.-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|"
     r"session[_-]?id|authorization))([\"']?\s*[:=]\s*[\"']?)(?!<redacted)[^\s&\"',;<]+", r"\1\2<redacted>"),
     # (any prefix: db_password=, jdbc.password:, AWS_SECRET_ACCESS_KEY=)
    (r"(?i)(<(?:password|passwd|credential|secret)[^>]*>)[^<]+(</)", r"\1<redacted>\2"),   # XML config values
    (r"(://[^/\s:@]+):[^/\s@]+@", r"\1:<redacted>@"),                                 # user:pass@ in URLs
    (r"(?<![\w/+=])[A-Za-z0-9+/]{40,}={0,2}(?![\w/+=])", "<redacted blob>"),          # long base64: keys, tokens
]
_REDACT = [(re.compile(p, re.S), r) for p, r in REDACT]

# Never collected, whatever a spec or a site file names: credentials and the places they live. (Policy files like
# /etc/sudoers are evidence, not credentials: they may be read.)
DENY_PATHS = ["~/.ssh/*", "~/.aws/*", "~/.gnupg/*", "~/.config/*", "~/.hobkins/*", "~/.claude/*",
              "~/.local/share/keyrings/*", "~/.netrc", "~/.pgpass", "~/.docker/*", "~/.kube/*", "/etc/shadow*",
              "/etc/gshadow*", "/etc/ssl/private/*", "/root/.ssh/*", "/proc/*", "/sys/*", "/dev/*"]
DENY_NAMES = re.compile(r"(?i)(\.pem$|\.key$|\.p12$|\.pfx$|\.jks$|\.keystore$|\.kdbx$|id_rsa|id_ed25519|id_ecdsa|"
                        r"credential|secret|token|passw|shadow|wallet)")
FILE_MAX = 512 * 1024            # the biggest file the `file` collector takes (bigger: its head and a note)


def redact(text: str, extra: list[str] | None = None) -> str:
    for p, r in _REDACT:
        text = p.sub(r, text)
    for p in extra or []:
        text = re.sub(p, "<redacted>", text)
    return text


def denied(path: str) -> str | None:
    """Why a path may never be collected (None: it may)."""
    real = os.path.realpath(os.path.expanduser(path))
    for pat in DENY_PATHS:
        p = os.path.expanduser(pat)
        if fnmatch.fnmatch(real, p) or real == p.rstrip("/*") or fnmatch.fnmatch(os.path.expanduser(path), p):
            return f"{path} is under {pat}, which is never collected"
    if DENY_NAMES.search(os.path.basename(real)):
        return f"{path} looks like a credential file, which is never collected"
    return None


class AtoneError(Exception):
    pass


# ---- store: where evidence goes: a folder, or S3 through the AWS CLI

class Store:
    """Evidence records, gzipped JSON, laid out by system, kind, date and host:
    PREFIX/system=NAME/kind=KIND/dt=YYYY-MM-DD/host=HOST/STAMP_RAND.json.gz"""

    def __init__(self, url: str):
        self.s3 = url.startswith("s3://")
        self.url = url.rstrip("/") if self.s3 else str(Path(url).expanduser().resolve())
        if self.s3 and not shutil.which("aws"):
            raise AtoneError("an S3 store needs the AWS CLI (aws), and there's none here")

    def _aws(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["aws", "s3", *args], capture_output=True, text=True, timeout=600)

    def put(self, key: str, data: bytes) -> None:
        if self.s3:
            with tempfile.NamedTemporaryFile() as f:
                f.write(data)
                f.flush()
                r = self._aws("cp", f.name, f"{self.url}/{key}", "--only-show-errors")
            if r.returncode:
                raise AtoneError(f"couldn't write {self.url}/{key}: {r.stderr.strip()}")
            return
        dest = Path(self.url) / key
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".part")
        tmp.write_bytes(data)
        os.replace(tmp, dest)

    def get(self, key: str) -> bytes | None:
        if self.s3:
            with tempfile.TemporaryDirectory() as t:
                r = self._aws("cp", f"{self.url}/{key}", f"{t}/x", "--only-show-errors")
                return Path(f"{t}/x").read_bytes() if r.returncode == 0 else None
        p = Path(self.url) / key
        return p.read_bytes() if p.is_file() else None


# ---- evidence: records (source, time, hash, redacted content), the run index, finding evidence

def stamp(t: float | None = None) -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(t or time.time()))


def make_record(system: str, kind: str, host: str, source: str, content, site: bool = False,
                extra_redact: list[str] | None = None) -> dict:
    """One piece of evidence. `content` is text or JSON-able data; it's redacted, then hashed: the hash is of what's
    stored, so anyone can check a record against itself, and collecting again shows whether it changed."""
    text = content if isinstance(content, str) else json.dumps(content, indent=1, sort_keys=True, default=str)
    text = redact(text, extra_redact)
    sha = hashlib.sha256(text.encode()).hexdigest()
    now = time.time()
    return {"id": f"{kind}.{re.sub(r'[^A-Za-z0-9_-]+', '-', host)}.{stamp(now)}.{sha[:8]}", "system": system,
            "kind": kind, "host": host, "at": now, "source": source, "site": site, "sha256": sha,
            "content": text, "atone": __version__}


def record_key(rec: dict) -> str:
    day = time.strftime("%Y-%m-%d", time.gmtime(rec["at"]))
    return (f"system={rec['system']}/kind={rec['kind']}/dt={day}/host={rec['host']}/"
            f"{stamp(rec['at'])}_{secrets.token_hex(3)}.json.gz")


def check_record(rec: dict) -> bool:
    """The record's content is what its hash says."""
    return hashlib.sha256(rec["content"].encode()).hexdigest() == rec["sha256"]


# ---- collectors: the built-in, read-only menu (COLLECTORS), run here or over ssh; discovery

def run_cmd(argv: list[str], timeout: float = 120) -> tuple[int, str]:
    """A fixed, read-only command of a collector's own (never one from a spec): (exit code, output)."""
    if not shutil.which(argv[0]):
        return 127, f"{argv[0]}: not installed here"
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return 124, f"{' '.join(argv)}: timed out after {timeout:.0f}s"
    return r.returncode, r.stdout + (("\n" + r.stderr.strip()) if r.stderr.strip() and r.returncode else "")


def read_text(path: str, limit: int = FILE_MAX) -> tuple[str | None, str]:
    """(text, note): a file's text if it may be read and can be; else None and why."""
    why = denied(path)
    if why:
        return None, why
    try:
        with open(path, "rb") as f:
            data = f.read(limit + 1)
    except OSError as e:
        return None, f"{path}: {e.strerror}"
    note = ""
    if len(data) > limit:
        data, note = data[:limit], f"(first {limit // 1024} KB of a bigger file)"
    if b"\0" in data[:4096]:
        return None, f"{path}: binary, not collected"
    return data.decode("utf-8", "replace"), note


def c_accounts(spec: dict) -> list[tuple[str, object]]:
    """Users and groups (not their password hashes: those are in shadow, never read), sudo rules, recent logins."""
    out = []
    users = [{"user": p.pw_name, "uid": p.pw_uid, "gid": p.pw_gid, "home": p.pw_dir, "shell": p.pw_shell,
              "gecos": p.pw_gecos} for p in pwd.getpwall()]
    out.append(("passwd entries", users))
    text, note = read_text("/etc/group")
    out.append(("/etc/group", text if text is not None else note))
    for path in ["/etc/sudoers"] + sorted(str(p) for p in Path("/etc/sudoers.d").glob("*")
                                          if Path("/etc/sudoers.d").is_dir()):
        text, note = read_text(path)
        out.append((path, text if text is not None else f"not readable here: {note}"))
    code, text = run_cmd(["lastlog"])
    out.append(("lastlog", text if code == 0 else f"lastlog: {text}"))
    return out


def c_packages(spec: dict) -> list[tuple[str, object]]:
    if shutil.which("rpm"):
        code, text = run_cmd(["rpm", "-qa", "--qf", "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH} %{INSTALLTIME}\n"])
        return [("rpm -qa", "\n".join(sorted(text.splitlines())) if code == 0 else text)]
    if shutil.which("dpkg-query"):
        code, text = run_cmd(["dpkg-query", "-W", "-f", "${Package} ${Version} ${Architecture}\n"])
        return [("dpkg-query -W", "\n".join(sorted(text.splitlines())) if code == 0 else text)]
    return [("packages", "no rpm or dpkg here")]


def c_services(spec: dict) -> list[tuple[str, object]]:
    out = []
    code, text = run_cmd(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"])
    out.append(("systemctl list-units --type=service --all", text))
    code, text = run_cmd(["systemctl", "list-unit-files", "--type=service", "--no-pager", "--plain", "--no-legend"])
    out.append(("systemctl list-unit-files --type=service", text))
    return out


def proc_sockets() -> dict[str, dict]:
    """{socket inode: {pid, process, user}} for the processes this account can see."""
    owners = {}
    for pid in (p for p in os.listdir("/proc") if p.isdigit()):
        try:
            names = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        try:
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
            uid = os.stat(f"/proc/{pid}").st_uid
            user = pwd.getpwuid(uid).pw_name
        except (OSError, KeyError):
            cmd, user = "?", "?"
        for fd in names:
            try:
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            m = re.match(r"socket:\[(\d+)\]", link)
            if m:
                owners[m.group(1)] = {"pid": int(pid), "process": cmd[:300], "user": user}
    return owners


def _addr(hexaddr: str, v6: bool) -> tuple[str, int]:
    ip, port = hexaddr.split(":")
    raw = bytes.fromhex(ip)
    if v6:
        raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        return socket.inet_ntop(socket.AF_INET6, raw), int(port, 16)
    return socket.inet_ntop(socket.AF_INET, raw[::-1]), int(port, 16)


def proc_net() -> list[dict]:
    """Every TCP socket (listening and connected) and UDP socket, from /proc/net: no tools needed."""
    owners = proc_sockets()
    rows = []
    for proto, path, v6 in (("tcp", "/proc/net/tcp", False), ("tcp", "/proc/net/tcp6", True),
                            ("udp", "/proc/net/udp", False), ("udp", "/proc/net/udp6", True)):
        try:
            lines = Path(path).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) < 10:
                continue
            local, remote, state, inode = _addr(f[1], v6), _addr(f[2], v6), f[3], f[9]
            st = {"0A": "listen", "01": "established"}.get(state, "other") if proto == "tcp" else \
                ("listen" if remote[1] == 0 else "connected")
            if st == "other":
                continue
            rows.append({"proto": proto, "state": st, "local": f"{local[0]}:{local[1]}",
                         "remote": f"{remote[0]}:{remote[1]}", **owners.get(inode, {})})
    return rows


def c_listeners(spec: dict) -> list[tuple[str, object]]:
    return [("/proc/net (listening)", sorted((r for r in proc_net() if r["state"] == "listen"),
                                             key=lambda r: (r["proto"], r["local"])))]


def c_flows(spec: dict) -> list[tuple[str, object]]:
    """Connections open now (run on a schedule, they add up to the connections seen over time)."""
    return [("/proc/net (connected)", sorted((r for r in proc_net() if r["state"] != "listen"),
                                             key=lambda r: (r["local"], r["remote"])))]


def c_firewall(spec: dict) -> list[tuple[str, object]]:
    out = []
    for argv in (["nft", "list", "ruleset"], ["firewall-cmd", "--list-all-zones"], ["iptables-save"]):
        code, text = run_cmd(argv)
        if code != 127:
            out.append((" ".join(argv), text))
    return out or [("firewall", "no nft, firewall-cmd or iptables-save here")]


def c_file(spec: dict) -> list[tuple[str, object]]:
    """The files the system spec names (config that defines connections, audit settings...), never credentials."""
    out = []
    for comp in spec.get("components") or []:
        for f in comp.get("files") or []:
            for path in sorted(glob.glob(os.path.expanduser(f.get("path", "")))) or [f.get("path", "")]:
                text, note = read_text(path)
                out.append((path, text if text is not None else f"not collected: {note}"))
    return out


def c_aws(spec: dict) -> list[tuple[str, object]]:
    """Read-only AWS calls (describe/get/list), through the AWS CLI and whatever credentials it has here."""
    if not shutil.which("aws"):
        return [("aws", "no AWS CLI here")]
    region = (spec.get("aws") or {}).get("region")
    calls = [["ec2", "describe-security-groups"], ["ec2", "describe-network-acls"], ["ec2", "describe-route-tables"],
             ["ec2", "describe-vpcs"], ["ec2", "describe-subnets"], ["ec2", "describe-instances"],
             ["ec2", "describe-vpc-endpoints"], ["ec2", "describe-flow-logs"], ["elbv2", "describe-load-balancers"],
             ["cloudtrail", "describe-trails"],
             ["configservice", "describe-configuration-recorder-status"], ["kms", "list-keys"],
             ["iam", "get-account-summary"]]
    out = []
    for call in calls:
        argv = ["aws", *call, "--output", "json"] + (["--region", region] if region else [])
        code, text = run_cmd(argv, timeout=180)
        try:
            out.append((" ".join(argv[1:3]), json.loads(text) if code == 0 else text))
        except json.JSONDecodeError:
            out.append((" ".join(argv[1:3]), text))
    return out


# The menu: a spec can name these, and nothing else
COLLECTORS = {
    "accounts": (c_accounts, "users, groups, sudo rules, last logins (never password hashes)"),
    "packages": (c_packages, "installed packages and versions"),
    "services": (c_services, "services, their state, and whether they start at boot"),
    "listeners": (c_listeners, "ports listened on, and the process and account behind each"),
    "flows": (c_flows, "connections open now (over time: connections seen)"),
    "firewall": (c_firewall, "host firewall rules"),
    "file": (c_file, "the files the system spec names (never credentials)"),
    "aws": (c_aws, "security groups, network ACLs, routes, VPCs, load balancers, CloudTrail, Config, KMS (read-only)"),
}
LOCAL_KINDS = [k for k in COLLECTORS if k != "aws"]     # what runs on each host; aws runs once, from here


def collect_here(kinds: list[str], spec: dict) -> list[dict]:
    """Run collectors on this host: [{kind, source, content}] (not yet records: the caller makes those)."""
    out = []
    for kind in kinds:
        if kind not in COLLECTORS:
            raise AtoneError(f"no collector {kind!r}: the menu is {', '.join(COLLECTORS)}")
        try:
            parts = COLLECTORS[kind][0](spec)
        except Exception as e:                 # one collector failing is evidence of that, not the end of the run
            parts = [(kind, f"the {kind} collector failed here: {type(e).__name__}: {e}")]
        for source, content in parts:
            out.append({"kind": kind, "source": source, "content": content})
    return out


def discover_here() -> dict:
    """What runs on this host, for drafting a system spec: the OS, processes, listeners, services, and which
    configuration files exist (listed, never read out)."""
    osr, _ = read_text("/etc/os-release")
    procs = []
    for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
        try:
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            argv = [a.decode(errors="replace") for a in argv if a]
            if not argv:
                continue
            exe = os.readlink(f"/proc/{pid}/exe") if os.access(f"/proc/{pid}/exe", os.R_OK) else ""
            user = pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
        except (OSError, KeyError):
            continue
        procs.append({"pid": int(pid), "user": user, "exe": exe, "argv": [redact(a) for a in argv[:40]]})
    configs = set()
    for p in procs:
        for a in p["argv"]:
            for m in re.findall(r"(/[\w./@+-]+\.(?:xml|conf|cfg|ini|properties|yaml|yml|json|toml|ora|env|cnf))", a):
                configs.add(m)
    for d in ("/etc",):
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if not denied(os.path.join(root, x) + "/x")]
            if root.count(os.sep) > 3:
                dirs[:] = []
            for f in files:
                if re.search(r"\.(conf|cfg|ini|xml|properties|yaml|yml|cnf)$", f):
                    configs.add(os.path.join(root, f))
    return {"host": socket.gethostname(), "os": osr or "", "processes": procs,
            "listeners": [r for r in proc_net() if r["state"] == "listen"],
            "services": run_cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager",
                                 "--plain", "--no-legend"])[1],
            "configs": sorted(c for c in configs if not denied(c) and os.path.exists(c))}


def over_ssh(target: str, args: list[str], timeout: float = 600) -> dict:
    """Run this very file on another host over ssh (python3 there; nothing installed), and read its JSON."""
    src = Path(__file__).read_text()
    remote = "python3 - " + " ".join(shlex.quote(a) for a in args)
    try:
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", target, remote], input=src,
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise AtoneError(f"{target}: timed out")
    if r.returncode:
        raise AtoneError(f"{target}: {r.stderr.strip() or f'exit code {r.returncode}'}")
    return json.loads(r.stdout)


# ---- imports: scanner results: OpenSCAP natively, anything else through a mapping file

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def control_ids(ref: str) -> list[str]:
    """800-53 control ids from a reference's text: "AC-2(1)" -> ac-2.1, "CM-6(a)" -> cm-6 (a statement part, not an
    enhancement), "AC-17(a),CM-7(a)" -> both."""
    out = []
    for m in re.finditer(r"\b([A-Z]{2})-(\d+)((?:\(\w+\))*)", ref.upper()):
        cid = f"{m.group(1).lower()}-{int(m.group(2))}"
        for sub in re.findall(r"\((\w+)\)", m.group(3)):
            if sub.isdigit():
                cid += f".{int(sub)}"
            else:
                break                                   # (a), (b): a part of the statement; the control is enough
        if cid not in out:
            out.append(cid)
    return out


def is_oscap(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(4096).decode("utf-8", "replace")
    except OSError:
        return False
    return "checklists.nist.gov/xccdf" in head or "scap.nist.gov/schema/asset-reporting-format" in head


def import_oscap(path: Path) -> list[dict]:
    """OpenSCAP results (XCCDF results, or ARF): one piece of evidence per test result (a host and a profile), each
    rule's result with the 800-53 controls the SCAP Security Guide says it bears on."""
    import xml.etree.ElementTree as ET
    root = ET.parse(path).getroot()
    rules = {}
    for el in root.iter():
        if _local(el.tag) != "Rule":
            continue
        refs, title = [], ""
        for child in el:
            name = _local(child.tag)
            if name == "title":
                title = "".join(child.itertext()).strip()
            elif name == "reference" and "800-53" in (child.get("href") or ""):
                refs += control_ids("".join(child.itertext()))
        rules[el.get("id")] = {"title": title, "controls": refs, "severity": el.get("severity")}
    out = []
    for tr in (el for el in root.iter() if _local(el.tag) == "TestResult"):
        target = next(("".join(c.itertext()).strip() for c in tr if _local(c.tag) == "target"), "") or "unknown"
        profile = next((c.get("idref") for c in tr if _local(c.tag) == "profile"), "") or ""
        results = []
        for rr in (c for c in tr if _local(c.tag) == "rule-result"):
            rid = rr.get("idref")
            result = next(("".join(c.itertext()).strip() for c in rr if _local(c.tag) == "result"), "")
            if result in ("notselected", "notapplicable"):
                continue
            r = rules.get(rid) or {}
            results.append({"rule": rid, "title": r.get("title", ""), "result": result,
                            "severity": rr.get("severity") or r.get("severity"), "controls": r.get("controls") or []})
        out.append({"kind": "scan", "host": target,
                    "source": f"openscap {profile.rsplit('_profile_', 1)[-1] or 'results'} ({path.name})",
                    "content": {"tool": "openscap", "profile": profile, "target": target,
                                "start": tr.get("start-time"), "end": tr.get("end-time"), "results": results}})
    if not out:
        raise AtoneError(f"{path.name}: OpenSCAP output with no test results in it")
    return out


def _rows_csv(path: Path) -> list[dict]:
    import csv
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        return list(csv.DictReader(f))


def _rows_xml(path: Path, record: str, fields: dict) -> list[dict]:
    import xml.etree.ElementTree as ET
    root = ET.parse(path).getroot()
    rows = []
    for el in root.iterfind(record):
        row = {}
        for name, where in fields.items():
            if not isinstance(where, str):
                continue
            if "@" in where:                        # an attribute: "@name", or a child's: "agent/@status"
                path, _, attr = where.rpartition("@")
                node = el.find(path.rstrip("/")) if path.rstrip("/") else el
                row[where] = node.get(attr, "") if node is not None else ""
            else:
                found = el.find(where)
                row[where] = "".join(found.itertext()).strip() if found is not None else el.get(where, "")
        rows.append(row)
    return rows


def severity_of(value: str, rules: dict) -> str:
    """A scanner's severity as the customer's words: rules map a name to the scanner's values ("critical": ["Critical"])
    or a numeric floor ("high": ">=7")."""
    v = (value or "").strip()
    for name, rule in rules.items():
        if isinstance(rule, list) and v.lower() in (str(x).lower() for x in rule):
            return name
        if isinstance(rule, str) and rule.startswith(">="):
            try:
                if float(v) >= float(rule[2:]):
                    return name
            except ValueError:
                pass
    return v or "unknown"


def import_mapped(path: Path, mapping: dict) -> list[dict]:
    """A scanner's export read through its mapping file: {"tool", "format": "csv"|"xml", "record" (xml: the path to each
    finding), "fields": {host, finding, id, severity, cve, first_seen, solution, status: the column or path of each},
    "severity": {name: values or ">=N"}}. One piece of evidence per host."""
    fields = mapping.get("fields") or {}
    if not fields.get("host") or not fields.get("finding"):
        raise AtoneError(f"{mapping.get('_file', 'the mapping')}: fields needs at least host and finding")
    rows = _rows_xml(path, mapping["record"], fields) if mapping.get("format") == "xml" else _rows_csv(path)
    if rows and mapping.get("format") != "xml":
        missing = [c for c in fields.values() if isinstance(c, str) and c not in rows[0]]
        if missing:
            raise AtoneError(f"{path.name} has no column {', '.join(map(repr, missing))} "
                             f"(it has: {', '.join(list(rows[0])[:30])})")
    by_host: dict[str, list] = {}
    for row in rows:
        f = {k: (row.get(v) or "").strip() for k, v in fields.items() if isinstance(v, str)}
        if not f.get("host") or not f.get("finding"):
            continue
        f["severity"] = severity_of(f.get("severity", ""), mapping.get("severity") or {})
        f["cve"] = re.findall(r"CVE-\d{4}-\d{4,}", f.get("cve", "") or f.get("finding", ""))
        by_host.setdefault(f["host"], []).append(f)
    tool = mapping.get("tool") or "scanner"
    return [{"kind": "scan", "host": host, "source": f"{tool} ({path.name})",
             "content": {"tool": tool, "findings": found}} for host, found in sorted(by_host.items())]


def import_file(path: Path, mappings: list[dict]) -> list[dict]:
    """One file: OpenSCAP if it is, else the first mapping whose "match" (a glob) fits its name."""
    if is_oscap(path):
        return import_oscap(path)
    for m in mappings:
        if fnmatch.fnmatch(path.name, m.get("match") or ""):
            return import_mapped(path, m)
    raise AtoneError(f"{path.name}: not OpenSCAP output, and no scanner mapping matches it. Draft one from its "
                     f"columns (atone import SYSTEM --sample {path}) as imports/TOOL.mapping.json")


def sample(path: Path, n: int = 5) -> str:
    """A file's columns and first rows, redacted: what an agent drafts a scanner mapping from."""
    if is_oscap(path):
        return f"{path.name} is OpenSCAP output: read natively, no mapping needed"
    if path.suffix.lower() == ".xml":
        text, note = read_text(str(path), 16 * 1024)
        return redact(text or note)
    rows = _rows_csv(path)
    return redact(json.dumps({"columns": list(rows[0]) if rows else [], "rows": rows[:n]}, indent=1))


# ---- controls: NIST's OSCAL catalog and baselines, the system's tailoring, the exact lore

OSCAL = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/"
SOURCES = {
    "catalog": OSCAL + "NIST_SP-800-53_rev5_catalog.json",
    "low": OSCAL + "NIST_SP-800-53_rev5_LOW-baseline_profile.json",
    "moderate": OSCAL + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
    "high": OSCAL + "NIST_SP-800-53_rev5_HIGH-baseline_profile.json",
    "privacy": OSCAL + "NIST_SP-800-53_rev5_PRIVACY-baseline_profile.json",
}


def sources_dir() -> Path:
    return HOME / "sources"


def fetch_sources(log=print) -> dict:
    """Download NIST's OSCAL files and record what was fetched (url, time, size, SHA-256) in sources/lock.json:
    what every control's words can be traced back to."""
    d = sources_dir()
    d.mkdir(parents=True, exist_ok=True)
    lock = {}
    for name, url in SOURCES.items():
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": f"atone/{__version__}"}),
                                    timeout=120) as r:
            data = r.read()
        json.loads(data)                                    # it must at least be JSON
        (d / f"{name}.json").write_bytes(data)
        lock[name] = {"url": url, "fetched": time.time(), "bytes": len(data),
                      "sha256": hashlib.sha256(data).hexdigest()}
        log(f"{name}: {len(data) // 1024} KB, sha256 {lock[name]['sha256'][:16]}...")
    (d / "lock.json").write_text(json.dumps(lock, indent=2) + "\n")
    return lock


def _prop(obj: dict, name: str, cls: str | None = None) -> str | None:
    for p in obj.get("props") or []:
        if p.get("name") == name and (cls is None or p.get("class") == cls) and \
                (cls is not None or p.get("class") in (None, "sp800-53")):
            return p.get("value")
    return None


def _params(ctl: dict) -> dict:
    out = {}
    for p in ctl.get("params") or []:
        label = p.get("label") or _prop(p, "alt-label", "sp800-53") or ""
        if p.get("select"):
            how = p["select"].get("how-many", "one")
            label = f"Selection ({how.replace('-', ' ')}): " + "; ".join(p["select"].get("choice") or [])
        out[p["id"]] = {"label": label, "guideline": " ".join(g.get("prose", "") for g in p.get("guidelines") or [])}
    return out


def render_prose(text: str, params: dict, values: dict | None = None, depth: int = 0) -> str:
    """OSCAL prose with its parameters filled in: a tailored value where there is one, else [Assignment: label] (a
    selection's choices can hold parameters of their own: those too)."""
    def sub(m):
        pid = m.group(1)
        if values and pid in values:
            return str(values[pid])
        p = params.get(pid) or {}
        label = render_prose(p.get("label", pid), params, values, depth + 1) if depth < 3 else p.get("label", pid)
        return f"[{label}]" if label.startswith("Selection") else f"[Assignment: {label}]"
    return re.sub(r"\{\{\s*insert:\s*param,\s*([\w.-]+)\s*\}\}", sub, text or "")


def _part_text(part: dict, params: dict, values: dict | None, depth: int = 0) -> list[str]:
    lines = []
    label = _prop(part, "label") or ""
    prose = render_prose(part.get("prose", ""), params, values)
    if prose or label:
        lines.append("  " * depth + (f"{label} " if label else "") + prose)
    for sub in part.get("parts") or []:
        lines += _part_text(sub, params, values, depth + 1)
    return lines


def load_catalog(path: Path | None = None) -> dict:
    """{control id: {...}} from NIST's OSCAL catalog: controls and enhancements alike, each with its label, title,
    family, statement, guidance, assessment objective, parameters, related controls, and whether it's withdrawn."""
    path = path or sources_dir() / "catalog.json"
    if not path.exists():
        raise AtoneError(f"no catalog at {path}: run `atone controls fetch` first")
    cat = json.loads(path.read_text())["catalog"]
    out = {}

    def add(ctl: dict, family: dict, parent: str | None):
        params = _params(ctl)
        parts = {p["name"]: p for p in ctl.get("parts") or [] if p.get("name") != "assessment-method"}
        out[ctl["id"]] = {
            "id": ctl["id"], "label": _prop(ctl, "label") or ctl["id"].upper(), "title": ctl.get("title", ""),
            "family": family["id"], "family_title": family.get("title", ""), "parent": parent,
            "withdrawn": _prop(ctl, "status") == "withdrawn",
            "params": params,
            "statement_parts": parts.get("statement"),
            "guidance": (parts.get("guidance") or {}).get("prose", ""),
            "objective_parts": parts.get("assessment-objective"),
            "related": sorted({l["href"][1:] for l in ctl.get("links") or []
                               if l.get("rel") == "related" and re.match(r"#[a-z]{2}-\d", l.get("href", ""))}),
            "moved_to": next((l["href"].lstrip("#") for l in ctl.get("links") or []
                              if l.get("rel") in ("moved-to", "incorporated-into")), None),
        }
        for enh in ctl.get("controls") or []:
            add(enh, family, ctl["id"])

    for fam in cat.get("groups") or []:
        for ctl in fam.get("controls") or []:
            add(ctl, fam, None)
    return out


def control_text(c: dict, values: dict | None = None) -> str:
    """A control's statement as words, its parameters filled in from `values` where given."""
    if not c.get("statement_parts"):
        return ""
    return "\n".join(_part_text(c["statement_parts"], c["params"], values)).strip()


def load_baseline(name: str) -> list[str]:
    """The control ids a baseline profile includes (NIST's LOW, MODERATE, HIGH or PRIVACY)."""
    path = sources_dir() / f"{name.lower()}.json"
    if not path.exists():
        raise AtoneError(f"no {name} baseline at {path}: run `atone controls fetch` first "
                         f"(baselines: {', '.join(k for k in SOURCES if k != 'catalog')})")
    prof = json.loads(path.read_text())["profile"]
    ids = []
    for imp in prof.get("imports") or []:
        for inc in imp.get("include-controls") or []:
            ids += inc.get("with-ids") or []
    return ids


def system_controls(sysdir: Path, catalog: dict | None = None) -> list[dict]:
    """The system's controls: its baseline, tailored (added, removed), each marked as the system's own, inherited or
    shared, with its parameter values. In the catalog's order."""
    t = read_json(sysdir / "tailoring.json", {})
    catalog = catalog or load_catalog()
    ids = set(load_baseline(t.get("baseline", "moderate"))) | set(t.get("add") or [])
    ids -= set(t.get("remove") or [])
    inherited, shared = t.get("inherited") or {}, t.get("shared") or {}
    out = []
    for cid, c in catalog.items():
        if cid not in ids:
            continue
        resp = "inherited" if cid in inherited else "shared" if cid in shared else "system"
        out.append({**c, "responsibility": resp, "provider": (inherited.get(cid) or shared.get(cid) or {}),
                    "values": {k: v for k, v in (t.get("params") or {}).items() if k in c["params"]}})
    unknown = sorted(ids - set(catalog))
    if unknown:
        raise AtoneError(f"tailoring names controls the catalog doesn't have: {', '.join(unknown[:10])}")
    return out


def compile_controls_lore(out: Path, catalog_path: Path | None = None) -> dict:
    """The catalog as a lorewell lore, word for word: a section per control (its statement, guidance and assessment
    objective, exactly as NIST wrote them) and a symbol per control id. No model touches it."""
    import lorewell
    cat = load_catalog(catalog_path)
    lock = read_json(sources_dir() / "lock.json", {}).get("catalog") or {}
    with tempfile.TemporaryDirectory() as t:
        src = Path(t)
        sections, symbols = [], []
        families = {}
        for c in cat.values():
            families.setdefault(c["family"], c["family_title"])
        for fam, title in families.items():
            sections.append({"id": fam, "parent": None, "title": f"{fam.upper()}: {title}",
                             "body": f"The {title} family of NIST SP 800-53 Rev 5.", "source": lock.get("url", "")})
        for c in cat.values():
            body = [f"{c['label']} {c['title']}" + (" (withdrawn" + (f": now {c['moved_to'].upper()}" if c["moved_to"]
                                                                    else "") + ")" if c["withdrawn"] else "")]
            stmt = control_text(c)
            if stmt:
                body += ["", "Control:", stmt]
            if c["guidance"]:
                body += ["", "Discussion:", c["guidance"]]
            if c["objective_parts"]:
                obj = "\n".join(_part_text(c["objective_parts"], c["params"], None)).strip()
                if obj:
                    body += ["", "Assessment objective (SP 800-53A):", obj]
            if c["params"]:
                body += ["", "Parameters:"] + [f"- {k}: {v['label']}" + (f" ({v['guideline']})" if v["guideline"] else "")
                                               for k, v in c["params"].items()]
            sections.append({"id": c["id"], "parent": c["parent"] or c["family"], "title": f"{c['label']} {c['title']}",
                             "body": "\n".join(body), "source": lock.get("url", "")})
            symbols.append({"name": c["label"], "kind": "keyword", "signature": c["label"], "summary": c["title"],
                            "section": c["id"], "body": stmt[:4000]})
        (src / "pack.json").write_text(json.dumps({
            "name": "nist-800-53r5", "title": "NIST SP 800-53 Rev 5 (with 800-53A objectives), compiled exactly",
            "language": "NIST SP 800-53", "version": "rev5", "description": "Every control and enhancement, word for "
            "word from NIST's OSCAL catalog" + (f" (sha256 {lock['sha256'][:16]}...)" if lock.get("sha256") else "")}))
        for name, rows in (("sections.jsonl", sections), ("symbols.jsonl", symbols)):
            (src / name).write_text("".join(json.dumps(r) + "\n" for r in rows))
        (src / "cheatsheet.md").write_text(
            "Look a control up by its id (`symbol AC-2(1)`), or search its words (`search session lock`). Each "
            "control's section has its statement, NIST's discussion, and the 800-53A assessment objective, word for "
            "word. Parameters in [Assignment: ...] are the organization's to set (the system's tailoring).\n")
        return lorewell.compile_pack(src, out, check=False, log=lambda *a: None)


# ---- system: a system's folder: spec, tailoring, site file

def read_json(path: Path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as e:
        raise AtoneError(f"{path} isn't valid JSON: {e}")


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str) + "\n")
    os.replace(tmp, path)


def valid_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name or ""):
        raise AtoneError(f"not a system name: {name!r} (letters, digits, - _ .)")
    return name


def system_dir(name: str, must_exist: bool = True) -> Path:
    d = HOME / "systems" / valid_name(name)
    if must_exist and not d.is_dir():
        raise AtoneError(f"no system {name}: atone init {name}")
    return d


TAILORING_STARTER = {
    "_about": "The system's tailoring: its baseline (low, moderate, high, privacy), controls added and removed, "
              "parameter values (by parameter id, e.g. ac-02_odp.06), and controls inherited from a provider or "
              "shared with one. Inherited and shared: {control id: {\"from\": provider, \"matrix\": its "
              "responsibility matrix}}.",
    "baseline": "moderate", "add": [], "remove": [], "params": {}, "inherited": {}, "shared": {},
}
SPEC_STARTER = {
    "_about": "What the system is: its hosts, its components (which hosts run them, the config files that define "
              "their connections), and the evidence to collect. Drafted from `atone discover`; reviewed by a person.",
    "hosts": [],
    "components": [
        {"name": "linux", "about": "the operating system on every host (generic: edit to fit)", "hosts": [],
         "files": [{"path": "/etc/audit/auditd.conf"}, {"path": "/etc/audit/rules.d/*.rules"},
                   {"path": "/etc/chrony.conf"}, {"path": "/etc/chrony/chrony.conf"}, {"path": "/etc/ssh/sshd_config"},
                   {"path": "/etc/login.defs"}, {"path": "/etc/security/pwquality.conf"}]},
    ],
    "collect": LOCAL_KINDS + ["aws"], "aws": {},
}

# The starter library: generic Linux and AWS control mappings for a first slice (AU, CM, and the access controls
# OpenSCAP covers). Copied into each new system's mappings/starter/, where they're the ISSE's to edit: drafts, not
# rulings. Each says which evidence bears on the control, the checks (data: see CHECK_TYPES), and what a person
# must supply.
F = lambda path: {"kind": "file", "source": path}
STARTER_MAPPINGS = [
    {"control": "au-2", "about": "Event logging: the audit daemon runs and has rules",
     "evidence": [{"name": "services", "kind": "services"}, {"name": "rules", **F("/etc/audit/rules.d/*.rules")}],
     "checks": [{"id": "auditd-running", "what": "auditd is running", "type": "present", "evidence": "services",
                 "pattern": r"^auditd\.service\s+loaded\s+active\s+running"},
                {"id": "audit-rules", "what": "audit rules are defined", "type": "present", "evidence": "rules",
                 "pattern": r"^-[aw]\s"},
                {"id": "oscap", "type": "scan"}],
     "needs_person": ["the event types the organization decided to log, and who agreed them (AU-2a, AU-2c)"]},
    {"control": "au-3", "about": "Content of audit records", "evidence": [], "checks": [{"id": "oscap", "type": "scan"}]},
    {"control": "au-4", "about": "Audit log storage capacity",
     "evidence": [{"name": "auditd", **F("/etc/audit/auditd.conf")}],
     "checks": [{"id": "space-left", "what": "auditd acts before the disk fills", "type": "present",
                 "evidence": "auditd", "pattern": r"^\s*space_left\s*=\s*\S+"}, {"id": "oscap", "type": "scan"}]},
    {"control": "au-5", "about": "Response to audit logging process failures",
     "evidence": [{"name": "auditd", **F("/etc/audit/auditd.conf")}],
     "checks": [{"id": "disk-full", "what": "auditd has an action when its disk is full", "type": "present",
                 "evidence": "auditd", "pattern": r"^\s*disk_full_action\s*=\s*(halt|single|suspend|syslog|email)"},
                {"id": "oscap", "type": "scan"}],
     "needs_person": ["who is alerted on an audit failure, and how fast (AU-5a)"]},
    {"control": "au-8", "about": "Time stamps: clocks synchronized",
     "evidence": [{"name": "services", "kind": "services"}, {"name": "chrony", "kind": "file", "source": "*chrony.conf"}],
     "checks": [{"id": "chronyd", "what": "a time service runs", "type": "present", "evidence": "services",
                 "pattern": r"^(chronyd|systemd-timesyncd|ntpd)\.service\s+loaded\s+active\s+running"},
                {"id": "time-source", "what": "it has a time source", "type": "present", "evidence": "chrony",
                 "pattern": r"^\s*(server|pool)\s+\S+"}]},
    {"control": "au-9", "about": "Protection of audit information", "evidence": [], "checks": [{"id": "oscap", "type": "scan"}]},
    {"control": "au-11", "about": "Audit record retention",
     "evidence": [{"name": "auditd", **F("/etc/audit/auditd.conf")}],
     "checks": [{"id": "keep-logs", "what": "auditd keeps rotated logs", "type": "present", "evidence": "auditd",
                 "pattern": r"^\s*max_log_file_action\s*=\s*(keep_logs|rotate)"}, {"id": "oscap", "type": "scan"}],
     "needs_person": ["the records retention policy that sets the period (AU-11), and where logs are kept for it "
                      "(eaveswatch's store, if it runs)"]},
    {"control": "au-12", "about": "Audit record generation",
     "evidence": [{"name": "unit-files", "kind": "services", "source": "systemctl list-unit-files*"}],
     "checks": [{"id": "auditd-at-boot", "what": "auditd starts at boot", "type": "present", "evidence": "unit-files",
                 "pattern": r"^auditd\.service\s+enabled"}, {"id": "oscap", "type": "scan"}]},
    {"control": "cm-2", "about": "Baseline configuration: the installed software is known",
     "evidence": [{"name": "packages", "kind": "packages"}],
     "checks": [{"id": "inventory", "what": "the installed packages were collected", "type": "exists",
                 "evidence": "packages"}],
     "needs_person": ["the documented baseline configuration, and when it was last reviewed (CM-2a, CM-2b)"]},
    {"control": "cm-6", "about": "Configuration settings: the hardening profile",
     "evidence": [], "checks": [{"id": "oscap", "type": "scan"}],
     "needs_person": ["which configuration standard (STIG, CIS) and profile is the system's, and its deviations"]},
    {"control": "cm-7", "about": "Least functionality: no needless services",
     "evidence": [{"name": "packages", "kind": "packages"}],
     "checks": [{"id": "no-cleartext", "what": "no telnet, rsh, tftp or ftp servers installed", "type": "absent",
                 "evidence": "packages", "pattern": r"^(telnet-server|rsh-server|tftp-server|vsftpd|xinetd)\s"},
                {"id": "oscap", "type": "scan"}],
     "needs_person": ["the ports, protocols and services the system needs (CM-7b): the listeners are compared with "
                      "them in the architecture"]},
    {"control": "cm-8", "about": "System component inventory",
     "evidence": [{"name": "packages", "kind": "packages"}, {"name": "aws", "kind": "aws", "source": "ec2 describe-instances"}],
     "checks": [{"id": "hosts", "what": "each host's software was collected", "type": "exists", "evidence": "packages"},
                {"id": "instances", "what": "the AWS instances were listed", "type": "exists", "evidence": "aws"}]},
    {"control": "ac-2", "about": "Account management", "evidence": [{"name": "passwd", "kind": "accounts",
                                                                     "source": "passwd entries"}],
     "checks": [{"id": "one-root", "what": "only root has uid 0", "type": "count", "evidence": "passwd",
                 "field_patterns": {"uid": "^0$"}, "op": "==", "value": 1}, {"id": "oscap", "type": "scan"}],
     "needs_person": ["the account types allowed, account managers, and the approval process (AC-2a-c)"]},
    {"control": "ac-6", "about": "Least privilege", "evidence": [{"name": "sudo", "kind": "accounts", "source": "/etc/sudoers*"}],
     "checks": [{"id": "no-nopasswd", "what": "no sudo rule skips the password", "type": "absent", "evidence": "sudo",
                 "pattern": r"^[^#\n]*NOPASSWD"}, {"id": "oscap", "type": "scan"}]},
    {"control": "ac-12", "about": "Session termination", "evidence": [], "checks": [{"id": "oscap", "type": "scan"}]},
    {"control": "sc-7", "about": "Boundary protection: nothing open to the whole internet but what's meant to be",
     "evidence": [{"name": "groups", "kind": "aws", "source": "ec2 describe-security-groups"}],
     "checks": [{"id": "no-world-ssh", "what": "no security group opens SSH (22) to 0.0.0.0/0", "type": "absent",
                 "evidence": "groups",
                 "pattern": r'"FromPort": 22,\s*"IpProtocol": "tcp",\s*"IpRanges": \[\s*\{[^]]*"CidrIp": "0\.0\.0\.0/0"'}],
     "needs_person": ["the boundary's managed interfaces, and what's meant to be reachable from outside (SC-7a, b)"]},
]
SITE_STARTER = {
    "_about": "Written by a person, never by an agent: commands atone doesn't have, and patterns to redact on top "
              "of the built-in floor. Evidence from a site command is marked as such in every report.",
    "commands": {}, "redact": [],
}


def init_system(name: str, store: str | None) -> Path:
    d = system_dir(name, must_exist=False)
    for sub in ("mappings", "imports", "runs", "workbooks", "drafts"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    starter = d / "mappings" / "starter.json"
    if not starter.exists():
        write_json(starter, STARTER_MAPPINGS)
    for fname, starter in (("tailoring.json", TAILORING_STARTER), ("system.json", SPEC_STARTER),
                           ("site.json", SITE_STARTER)):
        if not (d / fname).exists():
            write_json(d / fname, starter)
    conf = read_json(d / "atone.json", {})
    if store or "store" not in conf:
        conf["store"] = store or str(HOME / "store")
        write_json(d / "atone.json", conf)
    return d


def system_store(d: Path) -> Store:
    return Store(read_json(d / "atone.json", {}).get("store") or str(HOME / "store"))


def save_records(d: Path, recs: list[dict]) -> str:
    """Records to the store, and the run's index (ids and keys, no content) to runs/RUN/evidence.jsonl."""
    run = stamp()
    store = system_store(d)
    idx = d / "runs" / run
    idx.mkdir(parents=True, exist_ok=True)
    with open(idx / "evidence.jsonl", "a") as f:
        for rec in recs:
            key = record_key(rec)
            store.put(key, gzip.compress(json.dumps(rec).encode()))
            f.write(json.dumps({k: rec[k] for k in ("id", "kind", "host", "at", "source", "site", "sha256")
                                if k in rec} | ({"file_sha256": rec["file_sha256"]} if "file_sha256" in rec else {})
                               | {"key": key, "bytes": len(rec["content"])}) + "\n")
    (d / "runs" / "latest").write_text(run + "\n")
    return run


def run_index(d: Path, run: str | None = None) -> list[dict]:
    if not run and (d / "runs" / "latest").exists():
        run = (d / "runs" / "latest").read_text().strip()
    if not run:
        return []
    path = d / "runs" / run / "evidence.jsonl"
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()] if path.exists() else []


def current_index(d: Path, fresh_days: float | None = None) -> list[dict]:
    """The evidence that's current: for each (kind, host, source), its newest record, if it's no older than the
    system's fresh_days (atone.json; default 30). Collecting and importing add to it, run by run."""
    days = fresh_days if fresh_days is not None else float(read_json(d / "atone.json", {}).get("fresh_days") or 30)
    cut = time.time() - days * 86400
    newest: dict[tuple, dict] = {}
    runs = sorted(p.name for p in (d / "runs").iterdir() if p.is_dir()) if (d / "runs").is_dir() else []
    for run in runs:
        for e in run_index(d, run):
            k = (e["kind"], e["host"], e["source"])
            if e["at"] >= cut and (k not in newest or e["at"] >= newest[k]["at"]):
                newest[k] = {**e, "run": run}
    return sorted(newest.values(), key=lambda e: (e["kind"], e["host"], e["source"]))


def load_record(d: Path, entry: dict) -> dict | None:
    data = system_store(d).get(entry["key"])
    return json.loads(gzip.decompress(data)) if data else None


def collect(name: str, kinds: list[str] | None = None, targets: list[str] | None = None, log=print) -> str:
    """Evidence from the built-in collectors: on this host (or each --ssh target), then the AWS calls once."""
    d = system_dir(name)
    spec = read_json(d / "system.json", {})
    site = read_json(d / "site.json", {})
    kinds = kinds or spec.get("collect") or LOCAL_KINDS
    local = [k for k in kinds if k != "aws"]
    recs = []
    for target in targets or [None]:
        if target:
            got = over_ssh(target, ["__collect", json.dumps({"kinds": local, "spec": spec})])
            host = got["host"]
            parts = got["parts"]
        else:
            host, parts = socket.gethostname(), collect_here(local, spec)
        for p in parts:
            recs.append(make_record(name, p["kind"], host, p["source"], p["content"], extra_redact=site.get("redact")))
        log(f"{host}: {len(parts)} pieces of evidence ({', '.join(local)})")
    if "aws" in kinds:
        for source, content in c_aws(spec):
            recs.append(make_record(name, "aws", "aws", source, content, extra_redact=site.get("redact")))
        log("aws: done")
    for label, cmd in (site.get("commands") or {}).items():         # a person's own, marked as such
        code, text = run_cmd(shlex.split(cmd), timeout=300)
        recs.append(make_record(name, "site", socket.gethostname(), f"site command {label}: {cmd}",
                                text if code == 0 else f"exit code {code}: {text}", site=True,
                                extra_redact=site.get("redact")))
    run = save_records(d, recs)
    log(f"{len(recs)} records in run {run}")
    return run


def import_results(name: str, files: list[str] | None = None, log=print) -> str:
    """Scanner results into evidence: the files given, or everything in the system's imports/ folder."""
    d = system_dir(name)
    site = read_json(d / "site.json", {})
    mappings = []
    for mp in sorted((d / "imports").glob("*.mapping.json")):
        m = read_json(mp, {})
        mappings.append({**m, "_file": mp.name})
    paths = [Path(f) for f in files] if files else sorted(p for p in (d / "imports").iterdir()
                                                           if p.is_file() and not p.name.endswith(".mapping.json"))
    if not paths:
        raise AtoneError(f"nothing to import: put scanner exports in {d / 'imports'}, or name them")
    recs = []
    for path in paths:
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        for part in import_file(path, mappings):
            rec = make_record(name, part["kind"], part["host"], part["source"], part["content"],
                              extra_redact=site.get("redact"))
            rec["file_sha256"] = sha                     # the export it came from, as it was
            recs.append(rec)
        log(f"{path.name}: {sum(1 for r in recs if r['file_sha256'] == sha)} hosts")
    run = save_records(d, recs)
    log(f"{len(recs)} records in run {run}")
    return run


# ---- checks: control mappings (data the ISSE owns), the check engine, verifying a narrative's citations

# What a mapping's check can be: each is run by plain code, never by evaluating anything from the file
CHECK_TYPES = {
    "present": "a pattern is found in the evidence",
    "absent": "a pattern is NOT found in the evidence (e.g. NOPASSWD in sudo rules)",
    "value": "a value a pattern captures, compared (op: == != >= <= > < in) with a value or a tailored {param:ID}",
    "count": "how many items of a JSON list (filtered by field patterns) there are, compared with a value",
    "scan": "the OpenSCAP rules that reference this control: all must pass",
    "findings": "imported findings at the given severities: their count compared with a value",
    "exists": "the evidence was collected at all (and readable)",
}
STATUSES = ("met", "partly", "not met", "unknown", "inherited")
NOT_READ = re.compile(r"^(not collected|not readable here|.*: not installed here|.*collector failed)", re.I)


def load_mappings(d: Path) -> dict[str, dict]:
    """{control id: mapping} from the system's mappings/ folder (a file may hold one mapping or a list)."""
    out = {}
    for p in sorted((d / "mappings").rglob("*.json")):
        data = read_json(p, [])
        for m in data if isinstance(data, list) else [data]:
            if isinstance(m, dict) and m.get("control"):
                out[m["control"]] = {**m, "_file": str(p.relative_to(d))}
    return out


def mapping_problems(m: dict) -> list[str]:
    """What's wrong with a mapping (an empty list: nothing)."""
    out, names = [], {e.get("name") for e in m.get("evidence") or []}
    for e in m.get("evidence") or []:
        if e.get("kind") not in set(COLLECTORS) | {"scan", "site"}:
            out.append(f"evidence {e.get('name')!r}: kind {e.get('kind')!r} isn't a collector, scan or site")
    for c in m.get("checks") or []:
        if c.get("type") not in CHECK_TYPES:
            out.append(f"check {c.get('id')!r}: type {c.get('type')!r} isn't one of {', '.join(CHECK_TYPES)}")
        if c.get("type") != "scan" and c.get("evidence") not in names:
            out.append(f"check {c.get('id')!r}: no evidence named {c.get('evidence')!r}")
        for key in ("pattern", "field_patterns"):
            pats = [c.get(key)] if key == "pattern" else list((c.get(key) or {}).values())
            for pat in pats:
                if pat:
                    try:
                        re.compile(pat)
                    except re.error as e:
                        out.append(f"check {c.get('id')!r}: pattern {pat!r} doesn't compile ({e})")
    return out


def select(index: list[dict], sel: dict, spec: dict) -> list[dict]:
    """The current evidence an evidence selector picks: kind, source (a glob), host (a glob) or component (the hosts
    the system spec says run it), tool (for scans)."""
    hosts = None
    if sel.get("component"):
        comp = next((c for c in spec.get("components") or [] if c.get("name") == sel["component"]), None)
        hosts = set((comp or {}).get("hosts") or [])
    out = []
    for e in index:
        if e["kind"] != sel.get("kind"):
            continue
        if sel.get("source") and not fnmatch.fnmatch(e["source"], sel["source"]):
            continue
        if sel.get("tool") and not e["source"].startswith(sel["tool"]):
            continue
        if sel.get("host") and not fnmatch.fnmatch(e["host"], sel["host"]):
            continue
        if hosts is not None and e["host"] not in hosts:
            continue
        out.append(e)
    return out


def _compare(got, op: str, want) -> bool:
    try:
        g, w = float(got), float(want)
    except (TypeError, ValueError):
        g, w = str(got).strip().lower(), str(want).strip().lower()
    if op == "in":
        return str(got).strip().lower() in [str(x).strip().lower() for x in (want if isinstance(want, list) else [want])]
    return {"==": g == w, "!=": g != w, ">=": g >= w, "<=": g <= w, ">": g > w, "<": g < w}.get(op, False)


def _want(value, values: dict):
    """A check's value, or a tailored parameter's ({param:ID}); None if that parameter isn't set."""
    if isinstance(value, str):
        m = re.fullmatch(r"\{param:([\w.-]+)\}", value.strip())
        if m:
            v = values.get(m.group(1))
            if v is None:
                return None
            num = re.match(r"\s*(\d+(?:\.\d+)?)", str(v))
            return num.group(1) if num else v
    return value


def _quote(content: str, start: int, end: int) -> str:
    """The line (or lines) around a match: what a narrative can cite word for word."""
    a = content.rfind("\n", 0, start) + 1
    b = content.find("\n", end)
    return content[a:b if b != -1 else len(content)].strip()[:300]


def run_check(c: dict, recs: list[dict], ctl_id: str, values: dict) -> dict:
    """One check over the evidence it names: {status: pass|fail|unknown, evidence: [ids], quotes: [...], detail}."""
    t = c.get("type")
    out = {"check": c.get("id") or t, "what": c.get("what", ""), "type": t, "evidence": [r["id"] for r in recs],
           "quotes": [], "detail": ""}
    usable = [r for r in recs if not NOT_READ.match(r["content"].strip())]
    if not recs or (t != "exists" and not usable):
        out.update(status="unknown", detail="no evidence" if not recs else
                   "the evidence couldn't be read here: " + "; ".join(r["content"].strip()[:120] for r in recs[:3]))
        return out
    flags = re.I | re.M
    if t == "exists":
        out.update(status="pass" if usable else "fail", detail=f"{len(usable)} of {len(recs)} readable")
    elif t in ("present", "absent"):
        hits = [(r, m) for r in usable for m in [re.search(c["pattern"], r["content"], flags)] if m]
        out["quotes"] = [{"evidence": r["id"], "quote": _quote(r["content"], m.start(), m.end())} for r, m in hits]
        ok = bool(hits) if t == "present" else not hits
        out.update(status="pass" if ok else "fail",
                   detail=(f"found in {len(hits)} of {len(usable)}" if hits else f"not found in {len(usable)}"))
    elif t == "value":
        want = _want(c.get("value"), values)
        if want is None:
            out.update(status="unknown", detail=f"{c.get('value')} isn't set in the tailoring")
            return out
        results = []
        for r in usable:
            m = re.search(c["pattern"], r["content"], flags)
            if not m:
                results.append((r, None, False))
                continue
            got = m.group(1) if m.groups() else m.group(0)
            results.append((r, got, _compare(got, c.get("op", "=="), want)))
            out["quotes"].append({"evidence": r["id"], "quote": _quote(r["content"], m.start(), m.end())})
        bad = [r["host"] for r, got, ok in results if not ok]
        out.update(status="fail" if bad else "pass",
                   detail=f"{c.get('op', '==')} {want}: " + ", ".join(f"{r['host']}={got}" for r, got, _ in results))
    elif t == "count":
        n, items = 0, []
        for r in usable:
            try:
                data = json.loads(r["content"])
            except json.JSONDecodeError:
                continue
            for it in data if isinstance(data, list) else []:
                if all(re.search(p, str(it.get(f, "")), re.I) for f, p in (c.get("field_patterns") or {}).items()):
                    n += 1
                    items.append(it)
        ok = _compare(n, c.get("op", "=="), _want(c.get("value", 0), values))
        out["quotes"] = [{"evidence": usable[0]["id"], "quote": json.dumps(it, sort_keys=True)[:300]} for it in items[:5]]
        out.update(status="pass" if ok else "fail", detail=f"{n} {c.get('op', '==')} {c.get('value', 0)}")
    elif t == "scan":
        rules = []
        for r in usable:
            try:
                data = json.loads(r["content"])
            except json.JSONDecodeError:
                continue
            for res in data.get("results") or []:
                ctls = res.get("controls") or []
                if ctl_id in ctls or any(x in ctls for x in c.get("controls") or []):
                    rules.append((r, res))
        failed = [(r, res) for r, res in rules if res["result"] not in ("pass", "fixed")]
        out["quotes"] = [{"evidence": r["id"], "quote": f"{res['title']}: {res['result']}"} for r, res in (failed or rules)[:8]]
        out["evidence"] = sorted({r["id"] for r, _ in rules}) or out["evidence"]
        if not rules:
            out.update(status="unknown", detail="no OpenSCAP rule in the evidence references this control")
        else:
            out.update(status="fail" if failed else "pass",
                       detail=f"{len(rules) - len(failed)} of {len(rules)} rules pass" + (
                           ": failing " + "; ".join(f"{res['title']} ({r['host']})" for r, res in failed[:5]) if failed else ""))
    elif t == "findings":
        sev = [s.lower() for s in c.get("severity") or []]
        found = []
        for r in usable:
            try:
                data = json.loads(r["content"])
            except json.JSONDecodeError:
                continue
            found += [(r, f) for f in data.get("findings") or [] if not sev or str(f.get("severity", "")).lower() in sev]
        ok = _compare(len(found), c.get("op", "=="), c.get("value", 0))
        out["quotes"] = [{"evidence": r["id"], "quote": f"{f.get('host')}: {f.get('finding')} ({f.get('severity')})"}
                         for r, f in found[:8]]
        out.update(status="pass" if ok else "fail", detail=f"{len(found)} findings ({', '.join(sev) or 'any severity'})")
    return out


def check_system(name: str, log=print) -> dict:
    """Every control in the system's baseline, against its mapping and the current evidence: per control, its checks'
    results, a status (met, partly, not met, unknown, inherited), and what a person must supply. Written to
    runs/checks-STAMP.json (and runs/checks-latest.json)."""
    d = system_dir(name)
    spec = read_json(d / "system.json", {})
    ctls = system_controls(d)
    maps = load_mappings(d)
    index = current_index(d)
    cache: dict[str, dict] = {}

    def recs_for(sel):
        out = []
        for e in select(index, sel, spec):
            if e["id"] not in cache:
                cache[e["id"]] = load_record(d, e) or {}
            if cache[e["id"]]:
                out.append(cache[e["id"]])
        return out

    results = {}
    for c in ctls:
        m = maps.get(c["id"])
        entry = {"control": c["id"], "label": c["label"], "title": c["title"], "responsibility": c["responsibility"],
                 "mapping": (m or {}).get("_file"), "checks": [], "needs_person": list((m or {}).get("needs_person") or [])}
        if c["responsibility"] == "inherited":
            entry.update(status="inherited", provider=c["provider"])
        elif not m:
            entry.update(status="unknown", why="no mapping for this control yet")
        elif mapping_problems(m):
            entry.update(status="unknown", why="its mapping has problems: " + "; ".join(mapping_problems(m)))
        else:
            sels = {e["name"]: e for e in m.get("evidence") or []}
            for chk in m.get("checks") or []:
                sel = sels.get(chk.get("evidence")) or {"kind": "scan", "tool": "openscap"}
                entry["checks"].append(run_check(chk, recs_for(sel), c["id"], c["values"]))
            states = [r["status"] for r in entry["checks"]]
            entry["status"] = ("unknown" if not states or all(s == "unknown" for s in states) else
                               "not met" if all(s == "fail" for s in states if s != "unknown") else
                               "met" if all(s == "pass" for s in states) and not entry["needs_person"] else "partly")
        results[c["id"]] = entry
    counts = {s: sum(1 for r in results.values() if r["status"] == s) for s in STATUSES}
    out = {"system": name, "at": time.time(), "controls": results, "counts": counts,
           "evidence": len(index), "atone": __version__}
    write_json(d / "runs" / f"checks-{stamp()}.json", out)
    write_json(d / "runs" / "checks-latest.json", out)
    log(", ".join(f"{v} {k}" for k, v in counts.items()) + f" ({len(results)} controls, {len(index)} pieces of evidence)")
    return out


def _norm(text: str) -> str:
    return " ".join(text.split()).lower()


def verify_narrative(d: Path, draft: dict) -> dict:
    """Check every citation in a drafted narrative: each claim must cite current evidence whose (hash-checked)
    content contains the words it quotes. A claim from a person cites who and when instead ({"person": ...}). Claims
    that don't hold are dropped, with why; the statement is rebuilt from what's left."""
    index = {e["id"]: e for e in current_index(d)}
    superseded = {}
    for run in sorted(p.name for p in (d / "runs").iterdir() if p.is_dir()) if (d / "runs").is_dir() else []:
        for e in run_index(d, run):
            if e["id"] not in index:
                superseded[e["id"]] = e
    kept, dropped = [], []
    for claim in draft.get("claims") or []:
        text, cites = (claim.get("text") or "").strip(), claim.get("cites") or []
        if claim.get("person"):
            kept.append({**claim, "basis": "person"})
            continue
        why = None if cites else "it cites nothing"
        for cite in cites:
            e = index.get(cite.get("evidence"))
            if not e:
                why = (f"{cite.get('evidence')} has been superseded by newer evidence" if cite.get("evidence") in superseded
                       else f"no evidence {cite.get('evidence')!r}")
                break
            rec = load_record(d, e)
            if not rec or not check_record(rec):
                why = f"{e['id']} doesn't match its hash"
                break
            if not cite.get("quote") or _norm(cite["quote"]) not in _norm(rec["content"]):
                why = f"{e['id']} doesn't say {clip_text(cite.get('quote') or '(no quote)', 80)!r}"
                break
        if why:
            dropped.append({"text": text, "why": why})
        else:
            kept.append({**claim, "basis": "evidence"})
    return {"control": draft.get("control"), "statement": " ".join(c["text"].strip() for c in kept),
            "claims": kept, "dropped": dropped, "verified_at": time.time(),
            "coverage": {"evidence": sum(1 for c in kept if c["basis"] == "evidence"),
                         "person": sum(1 for c in kept if c["basis"] == "person"), "dropped": len(dropped)}}


def clip_text(text: str, n: int) -> str:
    one = " ".join(text.split())
    return one if len(one) <= n else one[:n - 3] + "..."


# ---- workbooks: the customer's Excel files: read them, fill them in (a copy, only cell values), say what changed

NS_MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
NS_REL = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
CELL_MAX = 32000                 # Excel's limit is 32,767 characters in a cell


def col_index(col: str) -> int:
    n = 0
    for ch in col.upper():
        n = n * 26 + ord(ch) - 64
    return n


def col_letters(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def split_ref(ref: str) -> tuple[str, int]:
    m = re.fullmatch(r"\$?([A-Z]+)\$?(\d+)", ref.upper())
    if not m:
        raise AtoneError(f"not a cell reference: {ref}")
    return m.group(1), int(m.group(2))


def in_sqref(ref: str, sqref: str) -> bool:
    col, row = split_ref(ref)
    c, r = col_index(col), row
    for part in sqref.split():
        a, _, b = part.partition(":")
        ca, ra = split_ref(a)
        cb, rb = split_ref(b or a)
        if col_index(ca) <= c <= col_index(cb) and ra <= r <= rb:
            return True
    return False


class Workbook:
    """An .xlsx, read (never written: see write_cells): its sheets, cells (shared strings, inline strings, numbers,
    formulas), merged cells and drop-down lists."""

    def __init__(self, path):
        import xml.etree.ElementTree as ET
        import zipfile
        self.path = Path(path)
        try:
            self.zip = zipfile.ZipFile(self.path)
        except zipfile.BadZipFile:
            raise AtoneError(f"{self.path.name} isn't an .xlsx (a zip file): save it as Excel Workbook (.xlsx)")
        self.ET = ET
        wb = ET.fromstring(self.zip.read("xl/workbook.xml"))
        rels = ET.fromstring(self.zip.read("xl/_rels/workbook.xml.rels"))
        targets = {r.get("Id"): r.get("Target") for r in rels}
        self.sheets = {}
        for s in wb.iter(NS_MAIN + "sheet"):
            t = targets.get(s.get(NS_REL + "id"), "")
            self.sheets[s.get("name")] = t.lstrip("/") if t.startswith("/") else "xl/" + t
        self.names = {n.get("name"): (n.text or "") for n in wb.iter(NS_MAIN + "definedName")}
        self.strings = []
        if "xl/sharedStrings.xml" in self.zip.namelist():
            for si in ET.fromstring(self.zip.read("xl/sharedStrings.xml")).iter(NS_MAIN + "si"):
                self.strings.append("".join(t.text or "" for t in si.iter(NS_MAIN + "t")))
        self._cells = {}

    def sheet_xml(self, sheet: str) -> bytes:
        if sheet not in self.sheets:
            raise AtoneError(f"{self.path.name} has no sheet {sheet!r} (it has: {', '.join(self.sheets)})")
        return self.zip.read(self.sheets[sheet])

    def cells(self, sheet: str) -> dict[str, dict]:
        """{ref: {"value": text, "style": s, "formula": bool}}"""
        if sheet in self._cells:
            return self._cells[sheet]
        root = self.ET.fromstring(self.sheet_xml(sheet))
        out = {}
        for c in root.iter(NS_MAIN + "c"):
            t, v = c.get("t"), c.find(NS_MAIN + "v")
            if t == "s" and v is not None:
                value = self.strings[int(v.text)]
            elif t == "inlineStr":
                value = "".join(x.text or "" for x in c.iter(NS_MAIN + "t"))
            else:
                value = v.text if v is not None and v.text is not None else ""
            out[c.get("r")] = {"value": value, "style": c.get("s"), "formula": c.find(NS_MAIN + "f") is not None}
        self._cells[sheet] = out
        return out

    def value(self, sheet: str, ref: str) -> str:
        return (self.cells(sheet).get(ref) or {}).get("value", "")

    def rows(self, sheet: str) -> dict[int, dict[str, str]]:
        """{row: {column letters: value}} for every non-empty cell."""
        out: dict[int, dict[str, str]] = {}
        for ref, c in self.cells(sheet).items():
            col, row = split_ref(ref)
            if str(c["value"]).strip():
                out.setdefault(row, {})[col] = c["value"]
        return dict(sorted(out.items()))

    def merged(self, sheet: str) -> list[str]:
        root = self.ET.fromstring(self.sheet_xml(sheet))
        return [m.get("ref") for m in root.iter(NS_MAIN + "mergeCell")]

    def _range_values(self, ref: str) -> list[str]:
        sheet, _, rng = ref.rpartition("!")
        sheet = sheet.strip("'") if sheet else None
        a, _, b = rng.replace("$", "").partition(":")
        ca, ra = split_ref(a)
        cb, rb = split_ref(b or a)
        vals = []
        for r in range(ra, rb + 1):
            for c in range(col_index(ca), col_index(cb) + 1):
                v = self.value(sheet, f"{col_letters(c)}{r}") if sheet else ""
                if str(v).strip():
                    vals.append(str(v).strip())
        return vals

    def validations(self, sheet: str) -> list[tuple[str, list[str]]]:
        """The drop-down lists on a sheet: [(the cells they cover, their values)], whether the values are inline
        ("A,B"), a range (Lists!$A$1:$A$5) or a defined name."""
        root = self.ET.fromstring(self.sheet_xml(sheet))
        out = []
        for dv in root.iter(NS_MAIN + "dataValidation"):
            if dv.get("type") != "list":
                continue
            f = dv.find(NS_MAIN + "formula1")
            formula = (f.text or "").strip() if f is not None else ""
            if formula.startswith('"'):
                vals = [v.strip() for v in formula.strip('"').split(",") if v.strip()]
            else:
                ref = self.names.get(formula.lstrip("="), formula.lstrip("="))
                try:
                    vals = self._range_values(ref)
                except (AtoneError, KeyError):
                    vals = []
            out.append((dv.get("sqref") or "", vals))
        return out

    def allowed(self, sheet: str, ref: str) -> list[str] | None:
        """The drop-down values a cell allows, or None if it has no list."""
        for sqref, vals in self.validations(sheet):
            if in_sqref(ref, sqref):
                return vals
        return None


def _xml_text(value: str) -> str:
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(value))
    if len(value) > CELL_MAX:
        value = value[:CELL_MAX - 40] + " [... continued in atone's report]"
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cell_xml(ref: str, style: str | None, value) -> str:
    s = f' s="{style}"' if style is not None else ""
    return f'<c r="{ref}"{s} t="inlineStr"><is><t xml:space="preserve">{_xml_text(value)}</t></is></c>'


def edit_sheet_xml(xml: str, edits: dict[str, object], styles_by_col: dict[str, str] | None = None) -> tuple[str, list]:
    """Set cells' values in a sheet's XML as text, touching nothing else: the cell's own element is replaced (its
    style kept); a missing cell or row is inserted in order. A formula cell is never written. Returns the new XML and
    the refs skipped (formulas)."""
    skipped = []
    styles_by_col = styles_by_col or {}
    for ref, value in sorted(edits.items(), key=lambda kv: (split_ref(kv[0])[1], col_index(split_ref(kv[0])[0]))):
        col, rown = split_ref(ref)
        row_re = re.compile(r'<row\b[^>]*\br="%d"[^>]*?(?:/>|>.*?</row>)' % rown, re.S)
        m = row_re.search(xml)
        if not m:                                     # a new row, in order
            new_row = f'<row r="{rown}">{_cell_xml(ref, styles_by_col.get(col), value)}</row>'
            later = [r for r in re.finditer(r'<row\b[^>]*\br="(\d+)"', xml) if int(r.group(1)) > rown]
            if later:
                xml = xml[:later[0].start()] + new_row + xml[later[0].start():]
            elif "<sheetData/>" in xml:
                xml = xml.replace("<sheetData/>", f"<sheetData>{new_row}</sheetData>")
            else:
                i = xml.index("</sheetData>")
                xml = xml[:i] + new_row + xml[i:]
            continue
        row = m.group(0)
        if row.endswith("/>"):
            row = row[:-2] + "></row>"
        cell_re = re.compile(r'<c\b[^>]*\br="%s"[^>]*?(?:/>|>.*?</c>)' % ref, re.S)
        cm = cell_re.search(row)
        if cm:
            old = cm.group(0)
            if "<f>" in old or "<f " in old:
                skipped.append(ref)
                continue
            sm = re.search(r'\bs="(\d+)"', old[:old.find(">") + 1])
            new = row[:cm.start()] + _cell_xml(ref, sm.group(1) if sm else styles_by_col.get(col), value) + row[cm.end():]
        else:
            cells = list(re.finditer(r'<c\b[^>]*\br="([A-Z]+)\d+"', row))
            after = next((c for c in cells if col_index(c.group(1)) > col_index(col)), None)
            at = after.start() if after else row.rindex("</row>")
            new = row[:at] + _cell_xml(ref, styles_by_col.get(col), value) + row[at:]
        xml = xml[:m.start()] + new + xml[m.end():]
    dim = re.search(r'<dimension ref="([A-Z]+\d+)(?::([A-Z]+\d+))?"', xml)
    if dim and edits:
        maxc = max([col_index(split_ref(r)[0]) for r in edits] + [col_index(split_ref(dim.group(2) or dim.group(1))[0])])
        maxr = max([split_ref(r)[1] for r in edits] + [split_ref(dim.group(2) or dim.group(1))[1]])
        xml = xml[:dim.start()] + f'<dimension ref="{dim.group(1)}:{col_letters(maxc)}{maxr}"' + xml[dim.end():]
    return xml, skipped


def write_cells(src: Path, dst: Path, edits: dict[str, dict[str, object]], styles: dict[str, dict] | None = None) -> list:
    """A copy of the workbook with these cells set ({sheet: {ref: value}}): every other part of the file is copied
    byte for byte. Returns the refs skipped (formula cells, never overwritten)."""
    import zipfile
    wb = Workbook(src)
    parts = {wb.sheets[s]: s for s in edits}
    skipped = []
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".part")
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(tmp, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info)
            if info.filename in parts:
                sheet = parts[info.filename]
                xml, sk = edit_sheet_xml(data.decode("utf-8"), edits[sheet], (styles or {}).get(sheet))
                skipped += [f"{sheet}!{r}" for r in sk]
                data = xml.encode("utf-8")
            zout.writestr(info, data, compress_type=info.compress_type)
    os.replace(tmp, dst)
    return skipped


def resolve_columns(wb: Workbook, sheet: str, header_row: int, columns: dict) -> dict[str, str]:
    """A template mapping's columns ({field: header text or column letters}) as column letters."""
    headers = {re.sub(r"\s+", " ", str(v)).strip().lower(): col for col, v in wb.rows(sheet).get(header_row, {}).items()}
    out = {}
    for field, want in columns.items():
        if re.fullmatch(r"[A-Z]{1,3}", str(want)):
            out[field] = want
        elif str(want).strip().lower() in headers:
            out[field] = headers[str(want).strip().lower()]
        else:
            raise AtoneError(f"{wb.path.name}!{sheet}: no column headed {want!r} in row {header_row} "
                             f"(the headers: {', '.join(repr(h) for h in headers)})")
    return out


def normalize_control(text: str) -> str | None:
    """A workbook's control id as atone's: "AC-2(1)", "AC-02 (01)", "ac-2.1" -> ac-2.1."""
    m = re.match(r"\s*([A-Za-z]{2})-0*(\d+)\s*(?:\(\s*0*(\d+)\s*\)|\.0*(\d+))?\s*$", str(text or ""))
    if not m:
        return None
    enh = m.group(3) or m.group(4)
    return f"{m.group(1).lower()}-{int(m.group(2))}" + (f".{int(enh)}" if enh else "")


def inspect_workbook(path: Path) -> str:
    """What an agent drafts a template mapping from: each sheet's likely header row, its columns, the drop-down lists
    and what they cover, merged cells, and a few rows."""
    wb = Workbook(path)
    out = [f"{wb.path.name}: sheets {', '.join(wb.sheets)}"]
    for sheet in wb.sheets:
        rows = wb.rows(sheet)
        header = next((r for r, cells in rows.items() if len(cells) >= 3), None)
        out.append(f"\n## {sheet}: {len(rows)} rows" + (f"; header row {header}" if header else ""))
        if header:
            out.append("columns: " + "; ".join(f"{c} = {v!r}" for c, v in rows[header].items()))
            for r in [r for r in rows if r > header][:4]:
                out.append(f"  row {r}: " + "; ".join(f"{c}={clip_text(redact(str(v)), 50)!r}" for c, v in rows[r].items()))
        for sqref, vals in wb.validations(sheet):
            out.append(f"drop-down on {sqref}: {vals}")
        if wb.merged(sheet):
            out.append(f"merged: {', '.join(wb.merged(sheet)[:10])}")
    return "\n".join(out)


def _status_value(mapping: dict, status: str) -> str | None:
    return (mapping.get("status_values") or {}).get(status)


def check_status_values(wb: Workbook, sheet: str, ref: str, mapping: dict) -> list[str]:
    """Status values come from the workbook: each one the mapping uses must be in the column's drop-down."""
    allowed = wb.allowed(sheet, ref)
    if allowed is None:
        return []
    return [f"status value {v!r} (for {k}) isn't in the workbook's drop-down ({', '.join(allowed)})"
            for k, v in (mapping.get("status_values") or {}).items() if v and v not in allowed]


def plan_ssp(d: Path, wb: Workbook, mapping: dict) -> tuple[dict, list, list]:
    """The cells to set in an SSP control matrix, from the latest checks and the verified narratives: (edits, changes,
    flags). What's already filled in is kept; where the evidence disagrees with it, that's a flag, not an edit."""
    sheet, hdr = mapping["sheet"], int(mapping.get("header_row", 1))
    cols = resolve_columns(wb, sheet, hdr, mapping["columns"])
    checks = (read_json(d / "runs" / "checks-latest.json", {}) or {}).get("controls") or {}
    edits, changes, flags = {}, [], []
    probs = check_status_values(wb, sheet, f"{cols['status']}{hdr + 1}", mapping) if "status" in cols else []
    if probs:
        raise AtoneError(f"{wb.path.name}: " + "; ".join(probs))

    def setcell(ref, value, why, evidence=()):
        old = wb.value(sheet, ref)
        if str(old).strip() == str(value).strip():
            return
        if str(old).strip():
            flags.append({"cell": f"{sheet}!{ref}", "has": old, "atone": value, "why": why, "evidence": list(evidence)})
            return
        edits[ref] = value
        changes.append({"cell": f"{sheet}!{ref}", "was": old, "now": value, "why": why, "evidence": list(evidence)})

    for rown, cells in wb.rows(sheet).items():
        if rown <= hdr:
            continue
        cid = normalize_control(cells.get(cols["control"], ""))
        if not cid:
            continue
        res = checks.get(cid)
        draft = read_json(d / "drafts" / "verified" / f"{cid}.json", None)
        ev = sorted({e for c in (res or {}).get("checks") or [] for e in c.get("evidence") or []})
        if res and "status" in cols:
            v = _status_value(mapping, res["status"])
            if v:
                detail = "; ".join(f"{c['check']}: {c['status']}" for c in res.get("checks") or []) or res.get("why", "")
                setcell(f"{cols['status']}{rown}", v, f"atone's checks: {res['status']} ({detail})", ev)
        if "statement" in cols:
            if draft and draft.get("statement"):
                cites = sorted({c["evidence"] for cl in draft["claims"] for c in cl.get("cites") or []})
                setcell(f"{cols['statement']}{rown}", draft["statement"], "a verified narrative", cites)
            elif res and res["status"] == "inherited":
                prov = (res.get("provider") or {}).get("from") or "the provider"
                setcell(f"{cols['statement']}{rown}", f"Inherited from {prov}.", "inherited, per the system's tailoring")
        if "evidence" in cols and (res or draft):
            ids = sorted(set(ev) | {c["evidence"] for cl in (draft or {}).get("claims") or [] for c in cl.get("cites") or []})
            text = "atone: " + ("; ".join(ids) if ids else "no evidence yet") + (
                f" ({res['status']})" if res else "")
            ref = f"{cols['evidence']}{rown}"
            if str(wb.value(sheet, ref)).startswith("atone:") or not str(wb.value(sheet, ref)).strip():
                if wb.value(sheet, ref) != text:
                    edits[ref] = text
                    changes.append({"cell": f"{sheet}!{ref}", "was": wb.value(sheet, ref), "now": text,
                                    "why": "atone's evidence for this row", "evidence": ids})
            else:
                flags.append({"cell": f"{sheet}!{ref}", "has": wb.value(sheet, ref), "atone": text,
                              "why": "the evidence column has someone's own words: left as it is", "evidence": ids})
    return {sheet: edits}, changes, flags


def poam_items(d: Path) -> list[dict]:
    """What belongs on a POA&M, from the current evidence and the latest checks: imported findings, failed OpenSCAP
    rules, and failed checks. Each with a key, so a row already on the POA&M is recognized."""
    items = []
    for e in current_index(d):
        if e["kind"] != "scan":
            continue
        rec = load_record(d, e) or {}
        try:
            data = json.loads(rec.get("content") or "{}")
        except json.JSONDecodeError:
            continue
        for f in data.get("findings") or []:
            items.append({"key": f"{data.get('tool')}|{f.get('id') or f.get('finding')}|{e['host']}",
                          "weakness": f.get("finding"), "description": f.get("solution") or "", "control": "RA-5",
                          "severity": f.get("severity"), "detected": f.get("first_seen") or "", "source": data.get("tool"),
                          "asset": e["host"], "evidence": e["id"]})
        for r in data.get("results") or []:
            if r.get("result") in ("fail", "error"):
                items.append({"key": f"openscap|{r['rule']}|{e['host']}", "weakness": r.get("title") or r["rule"],
                              "description": f"OpenSCAP rule {r['rule']} {r['result']}s",
                              "control": ", ".join(c.upper() for c in r.get("controls") or []) or "CM-6",
                              "severity": r.get("severity") or "", "detected": time.strftime("%Y-%m-%d", time.gmtime(e["at"])),
                              "source": "openscap", "asset": e["host"], "evidence": e["id"]})
    return items


def plan_poam(d: Path, wb: Workbook, mapping: dict) -> tuple[dict, list, list]:
    """New POA&M rows for what's open and not on it yet (each with its evidence), and flags for rows still open whose
    finding isn't in the latest evidence. Dates come from the schedule a person approved (drafts/poam-schedule.json:
    {key: date}); none are made up."""
    sheet, hdr = mapping["sheet"], int(mapping.get("header_row", 1))
    cols = resolve_columns(wb, sheet, hdr, mapping["columns"])
    probs = check_status_values(wb, sheet, f"{cols['status']}{hdr + 1}", mapping) if "status" in cols else []
    if probs:
        raise AtoneError(f"{wb.path.name}: " + "; ".join(probs))
    rows = {r: c for r, c in wb.rows(sheet).items() if r > hdr}
    have = {(str(c.get(cols.get("weakness", ""), "")).strip().lower(), str(c.get(cols.get("asset", ""), "")).strip().lower()): r
            for r, c in rows.items()}
    schedule = read_json(d / "drafts" / "poam-schedule.json", {}) or {}
    items = poam_items(d)
    last = max(rows) if rows else hdr
    styles = {col: (wb.cells(sheet).get(f"{col}{last}") or {}).get("style") for col in cols.values()}
    edits, changes, flags = {}, [], []
    fmt = mapping.get("id_format") or "ATONE-{n:04d}"
    n = sum(1 for c in rows.values() if str(c.get(cols.get("id", ""), "")).startswith(fmt.split("{")[0])) + 1
    seen = set()
    for it in items:
        k = (str(it["weakness"]).strip().lower(), str(it["asset"]).strip().lower())
        seen.add(k)
        if k in have:
            continue
        last += 1
        row = {"id": fmt.format(n=n), "weakness": it["weakness"], "description": it["description"],
               "control": it["control"], "severity": it["severity"], "detected": it["detected"],
               "due": schedule.get(it["key"], ""), "status": _status_value(mapping, "open") or "", "source": it["source"],
               "asset": it["asset"], "evidence": f"atone: {it['evidence']}"}
        n += 1
        for field, col in cols.items():
            if row.get(field) not in (None, ""):
                edits[f"{col}{last}"] = row[field]
        changes.append({"cell": f"{sheet}!A{last}", "now": row["id"], "why": f"new: {it['weakness']} on {it['asset']}",
                        "evidence": [it["evidence"]], "key": it["key"]})
    open_v = (_status_value(mapping, "open") or "").lower()
    for k, r in have.items():
        status = str(rows[r].get(cols.get("status", ""), "")).strip().lower()
        if status == open_v and k not in seen and any(it["asset"].lower() == k[1] for it in items):
            flags.append({"cell": f"{sheet}!{cols.get('status', 'A')}{r}", "has": rows[r].get(cols.get("status", "")),
                          "atone": _status_value(mapping, "closed"), "why": f"{rows[r].get(cols.get('weakness', ''))!r} is "
                          f"no longer in the latest evidence for {k[1]}: it looks closed (a person decides)", "evidence": []})
    return {sheet: edits}, changes, {"flags": flags, "styles": {sheet: styles}}


def fill_workbooks(name: str, out: Path, files: list[str] | None = None, log=print) -> list[dict]:
    """Fill copies of the system's working documents (workbooks/*.xlsx, each with its WORKBOOK.mapping.json) into
    `out`, with a NAME.changes.json beside each: every change (cell, was, now, why, evidence) and every flag."""
    d = system_dir(name)
    mappings = [{**read_json(p, {}), "_file": p.name} for p in sorted((d / "workbooks").glob("*.mapping.json"))]
    paths = [Path(f) for f in files] if files else sorted((d / "workbooks").glob("*.xlsx"))
    if not paths:
        raise AtoneError(f"no working documents: put them in {d / 'workbooks'} (with a mapping each: atone workbook "
                         f"inspect FILE shows what to map)")
    reports = []
    for path in paths:
        m = next((m for m in mappings if fnmatch.fnmatch(path.name, m.get("match") or "")), None)
        if not m:
            raise AtoneError(f"{path.name}: no template mapping matches it (workbooks/NAME.mapping.json, \"match\": a glob)")
        wb = Workbook(path)
        styles = None
        if m.get("kind") == "poam":
            edits, changes, extra = plan_poam(d, wb, m)
            flags, styles = extra["flags"], extra["styles"]
        else:
            edits, changes, flags = plan_ssp(d, wb, m)
        dest = out / path.name
        skipped = write_cells(path, dest, edits, styles)
        report = {"workbook": path.name, "output": str(dest), "mapping": m["_file"], "changes": changes,
                  "flags": flags, "skipped_formulas": skipped, "at": time.time()}
        write_json(out / (path.stem + ".changes.json"), report)
        log(f"{path.name}: {len(changes)} changes, {len(flags)} flags" + (f", {len(skipped)} formula cells left alone"
                                                                        if skipped else "") + f" -> {dest}")
        reports.append(report)
    return reports


# ---- command line: argument parsing, main

def cmd_evidence(args) -> str:
    d = system_dir(args.system)
    idx = run_index(d, args.run) if args.run else current_index(d)
    if args.what in (None, "list"):
        return "\n".join(f"{e['id']}  {e['source']}  ({e['bytes']} bytes{', SITE' if e['site'] else ''})"
                         for e in idx) or "no evidence yet: atone collect " + args.system
    if args.what == "show":
        e = next((e for e in idx if e["id"] == (args.words or [""])[0]), None)
        if not e:
            raise AtoneError(f"no evidence {(args.words or [''])[0]!r} in that run")
        rec = load_record(d, e)
        ok = "verified" if rec and check_record(rec) else "DOES NOT MATCH ITS HASH"
        return f"{rec['id']} ({rec['source']}, {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(rec['at']))}, " \
               f"sha256 {rec['sha256'][:16]}... {ok})\n\n{rec['content']}"
    if args.what == "search":
        words = [w.lower() for w in args.words or []]
        hits = []
        for e in idx:
            rec = load_record(d, e)
            text = (rec or {}).get("content", "").lower()
            if words and all(w in text or w in e["source"].lower() for w in words):
                line = next((l for l in rec["content"].splitlines() if words[0] in l.lower()), "")
                hits.append(f"{e['id']}  {e['source']}\n    {line.strip()[:200]}")
        return "\n".join(hits) or f"no evidence with {' '.join(args.words or [])!r}"
    raise AtoneError("evidence SYSTEM [list | show ID | search WORDS]")


def cmd_controls(args) -> str:
    if args.what == "fetch":
        fetch_sources()
        return f"in {sources_dir()} (what was fetched, with hashes: lock.json)"
    if args.what == "lore":
        out = Path(args.out or HOME / "lores" / "nist-800-53r5.lore.db")
        out.parent.mkdir(parents=True, exist_ok=True)
        r = compile_controls_lore(out)
        return f"{out}: {r['sections']} sections, {r['symbols']} symbols (install it: lorewell install {out})"
    d = system_dir(args.what)
    ctls = system_controls(d)
    sub = args.rest[0] if args.rest else "list"
    if sub == "list":
        return "\n".join(f"{c['label']:<12} {c['title']}" + ("" if c["responsibility"] == "system" else
                                                             f"  ({c['responsibility']})") for c in ctls) + \
            f"\n{len(ctls)} controls"
    if sub == "show" and len(args.rest) > 1:
        want = args.rest[1].lower()
        c = next((c for c in ctls if c["id"] == want or c["label"].lower() == want), None)
        if not c:
            raise AtoneError(f"{args.rest[1]} isn't in this system's controls")
        return f"{c['label']} {c['title']} ({c['responsibility']})\n\n{control_text(c, c['values'])}"
    raise AtoneError("controls fetch | lore | SYSTEM [list | show ID]")


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="atone", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="version", version=f"atone {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("init", help="a folder for a system")
    p.add_argument("system")
    p.add_argument("--store", help="where its evidence goes: s3://bucket/prefix or a folder (default ~/atone/store)")
    p = sub.add_parser("discover", help="what runs on the hosts (for drafting the system spec)")
    p.add_argument("system")
    p.add_argument("--ssh", action="append", default=[], help="user@host (repeatable; default: this host)")
    p = sub.add_parser("collect", help="evidence, from the built-in collectors")
    p.add_argument("system")
    p.add_argument("--kind", action="append", choices=list(COLLECTORS), help="only these collectors")
    p.add_argument("--ssh", action="append", default=[], help="user@host (repeatable; default: this host)")
    p = sub.add_parser("import", help="scanner results into evidence (OpenSCAP; others through imports/*.mapping.json)")
    p.add_argument("system")
    p.add_argument("files", nargs="*", help="default: everything in the system's imports/ folder")
    p.add_argument("--sample", metavar="FILE", help="a file's columns and first rows, for drafting its mapping")
    p = sub.add_parser("check", help="every control against its mapping and the current evidence")
    p.add_argument("system")
    p.add_argument("control", nargs="?", help="one control's results, in full")
    p = sub.add_parser("verify", help="check the citations in drafted narratives (drafts/*.json)")
    p.add_argument("system")
    p.add_argument("drafts", nargs="*", help="default: every draft in drafts/")
    p = sub.add_parser("mappings", help="the system's control mappings, and anything wrong with them")
    p.add_argument("system")
    p = sub.add_parser("workbook", help="inspect FILE: a workbook's sheets, headers and drop-downs (for its mapping)")
    p.add_argument("what", choices=["inspect"])
    p.add_argument("file")
    p = sub.add_parser("fill", help="fill copies of the working documents from the checks and verified narratives")
    p.add_argument("system")
    p.add_argument("files", nargs="*", help="default: the system's workbooks/*.xlsx")
    p.add_argument("--out", required=True, help="the folder for the filled copies and their change reports")
    p = sub.add_parser("evidence", help="the current evidence (or --run's): list, show ID, search WORDS")
    p.add_argument("system")
    p.add_argument("what", nargs="?", choices=["list", "show", "search"])
    p.add_argument("words", nargs="*")
    p.add_argument("--run")
    p = sub.add_parser("controls", help="fetch | lore | SYSTEM [list | show ID]")
    p.add_argument("what")
    p.add_argument("rest", nargs="*")
    p.add_argument("--out")
    return ap


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["__collect"]:                     # run over ssh, from this file piped in: JSON out
        req = json.loads(argv[1])
        print(json.dumps({"host": socket.gethostname(), "parts": collect_here(req["kinds"], req["spec"])},
                         default=str))
        return 0
    if argv[:1] == ["__discover"]:
        print(json.dumps(discover_here(), default=str))
        return 0
    args = parser().parse_args(argv)
    try:
        if args.cmd == "init":
            d = init_system(args.system, args.store)
            print(f"{args.system}: {d} (system.json: what it is; tailoring.json: its baseline and tailoring; "
                  f"site.json: a person's own commands)")
        elif args.cmd == "discover":
            d = system_dir(args.system)
            found = [over_ssh(t, ["__discover"]) for t in args.ssh] if args.ssh else [discover_here()]
            out = d / "discovery.json"
            write_json(out, {"at": time.time(), "hosts": found})
            print(f"{len(found)} host{'s' if len(found) != 1 else ''}: "
                  + ", ".join(f"{h['host']} ({len(h['processes'])} processes, {len(h['listeners'])} listeners, "
                              f"{len(h['configs'])} config files)" for h in found) + f"\n  in {out}")
        elif args.cmd == "collect":
            collect(args.system, args.kind, args.ssh)
        elif args.cmd == "import":
            if args.sample:
                print(sample(Path(args.sample)))
            else:
                import_results(args.system, args.files)
        elif args.cmd == "check":
            if args.control:
                res = read_json(system_dir(args.system) / "runs" / "checks-latest.json") or {}
                want = args.control.lower()
                hit = next((r for r in (res.get("controls") or {}).values() if want in (r["control"], r["label"].lower())), None)
                if not hit:
                    raise AtoneError(f"no results for {args.control}: atone check {args.system}")
                print(json.dumps(hit, indent=1))
            else:
                check_system(args.system)
        elif args.cmd == "verify":
            d = system_dir(args.system)
            paths = [Path(p) for p in args.drafts] or sorted((d / "drafts").glob("*.json"))
            for p in paths:
                v = verify_narrative(d, read_json(p))
                write_json(d / "drafts" / "verified" / p.name, v)
                cov = v["coverage"]
                print(f"{p.name}: {cov['evidence']} claims on evidence, {cov['person']} on a person's word, "
                      f"{cov['dropped']} dropped" + "".join(f"\n  dropped: {x['text'][:80]} ({x['why']})"
                                                          for x in v["dropped"]))
        elif args.cmd == "mappings":
            maps = load_mappings(system_dir(args.system))
            for cid, m in maps.items():
                probs = mapping_problems(m)
                print(f"{cid:<10} {m.get('about', '')[:60]:<60} {m['_file']}" + "".join(f"\n  ! {x}" for x in probs))
            print(f"{len(maps)} mappings")
        elif args.cmd == "workbook":
            print(inspect_workbook(Path(args.file)))
        elif args.cmd == "fill":
            fill_workbooks(args.system, Path(args.out), args.files)
        elif args.cmd == "evidence":
            print(cmd_evidence(args))
        elif args.cmd == "controls":
            print(cmd_controls(args))
        else:
            parser().print_help()
        return 0
    except AtoneError as e:
        print(f"atone: {e}", file=sys.stderr)
        return 2


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    cli()
