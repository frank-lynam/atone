#!/usr/bin/env python3
"""atone: keeps a system's authorization (ATO) true to the system.

An expert pack for hobkin, and a deterministic toolkit anyone can run without an agent. The toolkit never calls a
model: it collects evidence from the real system, checks NIST SP 800-53 controls against it, verifies every claim a
drafted narrative cites, fills in the customer's own workbooks and draws the architecture. The agent (a hobkin with
this pack) drafts, by running the toolkit and reading what it says. See DESIGN.md.

    atone init SYSTEM [--store s3://bucket/prefix | DIR]   a folder for a system (its spec, tailoring, mappings)
    atone discover SYSTEM [--ssh user@host]...   what runs on the hosts: for drafting the system spec
    atone collect SYSTEM [--kind K]... [--ssh user@host]...   evidence, from the built-in collectors
    atone evidence SYSTEM [list | show ID | search WORDS]
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
#   controls      NIST's OSCAL catalog and baselines, the system's tailoring, the exact lore
#   system        a system's folder: spec, tailoring, site file
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
    "hosts": [], "components": [], "collect": LOCAL_KINDS + ["aws"], "aws": {},
}
SITE_STARTER = {
    "_about": "Written by a person, never by an agent: commands atone doesn't have, and patterns to redact on top "
              "of the built-in floor. Evidence from a site command is marked as such in every report.",
    "commands": {}, "redact": [],
}


def init_system(name: str, store: str | None) -> Path:
    d = system_dir(name, must_exist=False)
    for sub in ("mappings", "imports", "runs", "workbooks"):
        (d / sub).mkdir(parents=True, exist_ok=True)
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
            f.write(json.dumps({k: rec[k] for k in ("id", "kind", "host", "at", "source", "site", "sha256")}
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


# ---- command line: argument parsing, main

def cmd_evidence(args) -> str:
    d = system_dir(args.system)
    idx = run_index(d, args.run)
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
    p = sub.add_parser("evidence", help="a run's evidence: list, show ID, search WORDS")
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
