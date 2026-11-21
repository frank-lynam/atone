#!/usr/bin/env python3
"""atone: keeps a system's authorization (ATO) true to the system.

An expert pack for hobkin, and a deterministic toolkit anyone can run without an agent. The toolkit never calls a
model: it collects evidence from the real system, checks NIST SP 800-53 controls against it, verifies every claim a
drafted narrative cites, fills in the customer's own workbooks and draws the architecture. The agent (a hobkin with
this pack) drafts, by running the toolkit and reading what it says. See DESIGN.md.

    atone init SYSTEM [--remote URL] [--from URL]   the system's codex: a git repository (or a clone of one)
    atone discover SYSTEM [--ssh user@host]...   what runs on the hosts: for drafting the system spec
    atone collect SYSTEM [--kind K]... [--ssh user@host]...   evidence, from the built-in collectors
    atone import SYSTEM [FILE]... [--sample FILE]   scanner results (OpenSCAP natively; others through a mapping)
    atone evidence SYSTEM [list | show ID | search WORDS]   the current evidence
    atone mappings SYSTEM         the control mappings (the ISSE's), and anything wrong with them
    atone check SYSTEM [CONTROL]  every control against its mapping and the evidence: met, partly, not met, unknown
    atone verify SYSTEM [DRAFT]...   a drafted narrative's citations, each checked against the evidence it quotes
    atone workbook inspect FILE   a workbook's sheets, headers and drop-downs: for drafting its template mapping
    atone fill SYSTEM --out DIR   copies of the working documents, filled in, with what changed and why
    atone connections SYSTEM      what each config file says its host connects to, and listens on
    atone draw SYSTEM --out DIR   the architecture: configured, seen, allowed and documented paths (draw.io, SVG)
    atone plan SYSTEM             the engagement plan: every piece of the effort, who can do it, what's done
    atone due SYSTEM              what's due by the cadence (nothing printed when nothing is: a hobkin's watch)
    atone report SYSTEM --out DIR [--conmon]   report.html, for people
    atone sources                 public guidance worth a lore, and NIST's files
    atone review SYSTEM [CONTROL...] --by NAME   a person reviews drafted statements (alone: what's waiting)
    atone decide SYSTEM KIND "what and why" --by NAME   a decision: risk acceptance, deviation, poam-schedule...
    atone package SYSTEM --tag TAG   the package into packages/TAG/, committed and tagged
    atone history SYSTEM [--control ID] [--path evidence/HOST]   the system's security history
    atone commit SYSTEM "message"   commit edits to the codex (spec, mappings, interfaces, drafts), with trailers
    atone oscal SYSTEM --out DIR  the SSP, assessment results and POA&M as OSCAL 1.1.2
    atone controls fetch [--from DIR]   a newer copy of NIST's OSCAL files (the package ships them)
    atone controls SYSTEM [list | show ID]   the system's controls: its baseline, tailored
    atone controls lore [--out FILE]   the catalog as a lore, compiled word for word (no model)
    atone --version

Each system's codex is a git repository at $ATONE_HOME/systems/NAME (default ~/atone): its single source of truth,
whose history is its security history (CODEX.md inside says what's where). $ATONE_HOME/sources/ holds a newer copy
of NIST's files, if one was fetched. systems/NAME/ (a system's spec,
tailoring, site file, mappings, imports and runs) and, unless a system names another, store/ (its evidence).
Standard library only, plus lorewell for lores.
"""
from __future__ import annotations

import argparse
import fnmatch
import glob
import hashlib
import json
import os
import pwd
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

__version__ = "0.2.0"

# ---- map: `grep -n '^# ----' atone.py` lists these sections.
#   settings      where things live, the redaction floor, the credential deny-list
#   store         where evidence goes: a folder, or S3 through the AWS CLI
#   evidence      records (source, time, hash, redacted content), the run index, finding evidence
#   collectors    the built-in, read-only menu (COLLECTORS), run here or over ssh; discovery
#   imports       scanner results: OpenSCAP natively, anything else through a mapping file
#   controls      NIST's OSCAL catalog and baselines, the system's tailoring, the exact lore
#   system        a system's folder: spec, tailoring, site file; collecting and importing into it
#   checks        control mappings (the ISSE's), the check engine, verifying a narrative's citations
#   workbooks     the customer's Excel files: read, filled in (a copy, only cell values), what changed; Word as text
#   architecture  one graph of actual, allowed and documented paths; draw.io and SVG, with what differs
#   plan          the engagement plan (what's left, who does it), what's due, the report people read
#   oscal         the SSP, assessment results and POA&M as OSCAL 1.1.2
#   pack          atone as an expert pack for hobkin: a chore and its skills (the hobkin.packs entry point)
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
     r"session[_-]?id|authorization))([\"']?\s*[:=]\s*[\"']?)(?!<redacted|\()[^\s&\"',;<]+", r"\1\2<redacted>"),
     # (any prefix: db_password=, jdbc.password:, AWS_SECRET_ACCESS_KEY=)
    (r"(?i)(<(?:password|passwd|credential|secret)[^>]*>)[^<]+(</)", r"\1<redacted>\2"),   # XML config values
    (r"(://[^/\s:@]+):[^/\s@]+@", r"\1:<redacted>@"),                                 # user:pass@ in URLs
    (r"(?<![\w/+=])(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*[0-9])[A-Za-z0-9+/]{40,}={0,2}"
     r"(?![\w/+=])", "<redacted blob>"),  # base64
    # (a long base64 blob, a key or token: upper and lower case and digits, as random ones all but always have; not
    # a hex hash like a SHA-256 or a commit id, nor a path, which almost never mix all three)
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

    def names(self, prefix: str = "") -> list[str]:
        """What's directly under a prefix: files, and folders as NAME/."""
        if self.s3:
            r = self._aws("ls", f"{self.url}/{prefix}")
            out = []
            for line in r.stdout.splitlines():
                parts = line.split()
                if parts[:1] == ["PRE"]:
                    out.append(parts[1])
                elif len(parts) >= 4:
                    out.append(" ".join(parts[3:]))
            return sorted(out)
        p = Path(self.url) / prefix
        return sorted(n + ("/" if (p / n).is_dir() else "") for n in os.listdir(p)) if p.is_dir() else []

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
    """Connections open now, each as which way it goes and to what: inbound to one of this host's listening ports
    (from an address; its port is ephemeral, so it's dropped), or outbound to a port elsewhere (this side's port is
    ephemeral). Kept in the codex as a set that grows: a new connection is a change, the same one again isn't."""
    rows = proc_net()
    listening = {(r["proto"], r["local"].rpartition(":")[2]) for r in rows if r["state"] == "listen"}
    out = {}
    for r in rows:
        if r["state"] == "listen":
            continue
        lip, _, lport = r["local"].rpartition(":")
        rip, _, rport = r["remote"].rpartition(":")
        if rip.startswith("127.") or rip in ("::1", "0.0.0.0", "::") or not rport or rport == "0":
            continue
        inbound = (r["proto"], lport) in listening
        row = {"proto": r["proto"], "direction": "in" if inbound else "out",
               "local": f"{lip}:{lport}" if inbound else lip, "remote": rip if inbound else f"{rip}:{rport}",
               "process": (r.get("process") or "")[:200], "user": r.get("user", "")}
        out[(row["proto"], row["direction"], row["local"], row["remote"], row["process"])] = row
    return [("connections", sorted(out.values(), key=lambda x: (x["direction"], x["local"], x["remote"])))]


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


AWS_CALLS = [["ec2", "describe-security-groups"], ["ec2", "describe-network-interfaces"], ["ec2", "describe-instances"],
             ["ec2", "describe-subnets"], ["ec2", "describe-route-tables"], ["ec2", "describe-network-acls"],
             ["ec2", "describe-vpcs"], ["ec2", "describe-vpc-endpoints"], ["ec2", "describe-flow-logs"],
             ["elbv2", "describe-load-balancers"], ["elbv2", "describe-target-groups"], ["rds", "describe-db-instances"],
             ["cloudtrail", "describe-trails"], ["configservice", "describe-configuration-recorder-status"],
             ["kms", "list-keys"], ["iam", "get-account-summary"]]


def c_aws(spec: dict) -> list[tuple[str, object]]:
    """Read-only AWS calls (describe/get/list), through the AWS CLI and whatever credentials it has here, in each of
    the spec's regions (aws.regions, or aws.region): security groups and what uses them, instances, subnets and
    routes, network ACLs, load balancers (their listeners, target groups and targets), RDS, CloudTrail, Config, KMS."""
    if not shutil.which("aws"):
        return [("aws", "no AWS CLI here")]
    conf = spec.get("aws") or {}
    regions = conf.get("regions") or ([conf["region"]] if conf.get("region") else [None])
    code, text = run_cmd(["aws", "sts", "get-caller-identity", "--output", "json"] +
                         (["--region", regions[0]] if regions[0] else []), timeout=60)
    if code != 0:      # no credentials (or no way to AWS): say so once, rather than every call failing slowly
        return [("aws", "no AWS access from here: " + (text.strip().splitlines() or ["(no output)"])[-1])]
    try:
        out = [("sts get-caller-identity", json.loads(text))]   # which account, and as whom (no secrets in it)
    except json.JSONDecodeError:
        out = [("sts get-caller-identity", text)]

    def call(args, label, region):
        argv = ["aws", *args, "--output", "json"] + (["--region", region] if region else [])
        code, text = run_cmd(argv, timeout=180)
        name = label + (f" [{region}]" if region and len(regions) > 1 else "")
        try:
            data = json.loads(text) if code == 0 else text
        except json.JSONDecodeError:
            data = text
        out.append((name, data))
        return data if isinstance(data, dict) else {}
    for region in regions:
        got = {}
        for c in AWS_CALLS:
            got[" ".join(c)] = call(c, " ".join(c), region)
        for lb in got.get("elbv2 describe-load-balancers", {}).get("LoadBalancers") or []:
            call(["elbv2", "describe-listeners", "--load-balancer-arn", lb["LoadBalancerArn"]],
                 f"elbv2 describe-listeners ({lb.get('LoadBalancerName')})", region)
        for tg in got.get("elbv2 describe-target-groups", {}).get("TargetGroups") or []:
            call(["elbv2", "describe-target-health", "--target-group-arn", tg["TargetGroupArn"]],
                 f"elbv2 describe-target-health ({tg.get('TargetGroupName')})", region)
    return out


def decode_cert(der: bytes) -> dict:
    """A certificate's subject, issuer, validity and names, with the standard library: Python's own certificate
    decoder where it has one; else just its fingerprint (the protocol and cipher are still recorded)."""
    out = {"sha256": hashlib.sha256(der).hexdigest()}
    try:
        import _ssl
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(__import__("ssl").DER_cert_to_PEM_cert(der))
        info = _ssl._test_decode_cert(f.name)
        os.unlink(f.name)
    except (ImportError, AttributeError, OSError, ValueError):
        return out
    flat = lambda rdns: ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)
    out.update({"subject": flat(info.get("subject", ())), "issuer": flat(info.get("issuer", ())),
                "not_before": info.get("notBefore"), "not_after": info.get("notAfter"),
                "names": [v for k, v in info.get("subjectAltName", ()) if k in ("DNS", "IP Address")],
                "self_signed": info.get("subject") == info.get("issuer")})
    try:
        out["days_left"] = int((__import__("ssl").cert_time_to_seconds(info["notAfter"]) - time.time()) // 86400)
    except (KeyError, ValueError):
        pass
    return out


def c_certs(spec: dict) -> list[tuple[str, object]]:
    """TLS on this host's listeners: for each TCP port listened on, a handshake from here (trust isn't checked:
    this only records what's offered): the protocol and cipher negotiated, and the certificate's subject, issuer,
    expiry and names. Ports that don't speak TLS are listed as such."""
    import ssl
    ports = sorted({(r["local"].rpartition(":")[0], int(r["local"].rpartition(":")[2]))
                    for r in proc_net() if r["proto"] == "tcp" and r["state"] == "listen"}, key=lambda x: x[1])
    def probe(ip, port):
        hosts = ["127.0.0.1"] if ip in ("0.0.0.0", "") else ["::1", "127.0.0.1"] if ip == "::" else [ip]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        for host in hosts:
            try:
                with socket.create_connection((host, port), timeout=3) as raw, ctx.wrap_socket(raw) as tls:
                    der = tls.getpeercert(binary_form=True)
                    return {"port": port, "address": ip, "protocol": tls.version(),
                            "cipher": (tls.cipher() or [""])[0],
                            **(decode_cert(der) if der else {"certificate": "none offered"})}
            except (ssl.SSLError, ConnectionError, socket.timeout, OSError):
                continue
        return port
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(16) as pool:            # a port that doesn't speak TLS can take its whole timeout
        got = list(pool.map(lambda a: probe(*a), ports))
    found, plain = [g for g in got if isinstance(g, dict)], [g for g in got if not isinstance(g, dict)]
    return [("TLS on listeners", found), ("listeners not speaking TLS (from here)", sorted(set(plain)))]


# The menu: a spec can name these, and nothing else
COLLECTORS = {
    "accounts": (c_accounts, "users, groups, sudo rules, last logins (never password hashes)"),
    "packages": (c_packages, "installed packages and versions"),
    "services": (c_services, "services, their state, and whether they start at boot"),
    "listeners": (c_listeners, "ports listened on, and the process and account behind each"),
    "flows": (c_flows, "connections open now (over time: connections seen)"),
    "firewall": (c_firewall, "host firewall rules"),
    "file": (c_file, "the files the system spec names (never credentials)"),
    "certs": (c_certs, "TLS on each listener: protocol, cipher, and the certificate's subject, issuer, expiry"),
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
    """What runs on this host, for drafting a system spec, compact enough to read whole: the OS, the processes (alike
    ones counted once), the listeners (with the process behind each, where this account can see it), the running
    services, and which configuration files exist (listed, never read out): first the ones a running process names,
    then the rest of /etc by directory."""
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
    named = sorted(c for c in configs if not denied(c) and os.path.exists(c))
    configs = set()
    for d in ("/etc",):
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if not denied(os.path.join(root, x) + "/x")]
            if root.count(os.sep) > 3:
                dirs[:] = []
            for f in files:
                if re.search(r"\.(conf|cfg|ini|xml|properties|yaml|yml|cnf)$", f):
                    configs.add(os.path.join(root, f))
    by_dir = {}
    for c in sorted(c for c in configs - set(named) if not denied(c) and os.path.exists(c)):
        by_dir.setdefault(os.path.dirname(c), []).append(os.path.basename(c))
    alike = {}
    for p in procs:
        cmd = clip_text(" ".join(p["argv"]), 240)
        alike.setdefault((p["user"], cmd), {"user": p["user"], "command": cmd, "count": 0})["count"] += 1
    listeners = {}
    for r in proc_net():
        if r["state"] == "listen":
            row = {"proto": r["proto"], "local": r["local"], "process": clip_text(r.get("process") or "", 160),
                   "user": r.get("user", "")}
            listeners[(row["proto"], row["local"])] = row
    return {"host": socket.gethostname(), "os": " ".join(l.split("=", 1)[1].strip('"') for l in (osr or "").splitlines()
                                                     if l.startswith("PRETTY_NAME=")) or (osr or "")[:200],
            "listeners": sorted(listeners.values(), key=lambda r: (r["proto"], int(r["local"].rpartition(":")[2]))),
            "services": run_cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager",
                                 "--plain", "--no-legend"])[1],
            "processes": sorted(alike.values(), key=lambda p: (p["user"], p["command"])),
            "configs": {"named by running processes": named, "in /etc, by directory": by_dir}}


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


def import_eaveswatch(url: str, system: str, env: str | None = None) -> list[dict]:
    """Evidence for the AU family from an eaveswatch store (its folder, or s3://...): what it collects and alerts on
    (its interpreter spec), which hosts ship logs (heartbeats), how far back the archive goes (its day partitions:
    retention), and that logs are reviewed (findings and fired alerts). Read only."""
    store = Store(url)
    base = f"systems/system={system}/"

    def jget(key):
        data = store.get(key)
        try:
            return json.loads(data) if data else None
        except json.JSONDecodeError:
            return None
    out = []
    versions = sorted((int(m.group(1)), n) for n in store.names(base + "interpreter/")
                      for m in [re.fullmatch(r"v(\d+)\.json", n)] if m)
    if versions:
        v, n = versions[-1]
        spec = jget(base + "interpreter/" + n) or {}
        out.append({"kind": "logs", "host": "eaveswatch", "source": f"eaveswatch interpreter v{v}",
                    "content": {"version": v, "sources": [{k: x.get(k) for k in ("name", "path", "journald", "kind")
                                                           if x.get(k)} for x in spec.get("sources") or []],
                                "alerts": spec.get("alerts") or [], "services": sorted(spec.get("services") or {})}})
    nodes = [jget(base + "nodes/" + n) for n in store.names(base + "nodes/") if n.endswith(".json")]
    nodes = [{"host": x.get("host"), "last_seen": x.get("at"), "role": x.get("role"), "interpreter": x.get("interpreter")}
             for x in nodes if x]
    if nodes:
        out.append({"kind": "logs", "host": "eaveswatch", "source": "eaveswatch nodes", "content": nodes})
    envs = [env] if env else [n[4:].rstrip("/") for n in store.names() if n.startswith("env=")]
    for e in envs:
        kinds = {}
        for kn in store.names(f"env={e}/"):
            if not kn.startswith("kind="):
                continue
            k = kn[5:].rstrip("/")
            days = sorted(n[3:].rstrip("/") for n in store.names(f"env={e}/{kn}") if n.startswith("dt="))
            if not days:
                continue
            hours = [n for n in store.names(f"env={e}/{kn}dt={days[-1]}/") if n.startswith("hour=")]
            hosts = sorted(n[5:].rstrip("/") for n in store.names(f"env={e}/{kn}dt={days[-1]}/{hours[-1]}")
                           if n.startswith("host=")) if hours else []
            import datetime as _dt
            span = (_dt.date.fromisoformat(days[-1]) - _dt.date.fromisoformat(days[0])).days + 1
            kinds[k] = {"oldest": days[0], "newest": days[-1], "days_present": len(days), "days_kept": span,
                        "hosts_latest": hosts}
        if kinds:
            out.append({"kind": "logs", "host": "eaveswatch", "source": f"eaveswatch archive ({e})",
                        "content": {"env": e, "days_kept": max(x["days_kept"] for x in kinds.values()), "kinds": kinds}})
    events = sorted(n for n in store.names(base + "ledger/") if n.endswith(".json"))
    alerts = [n for n in store.names(base + "alerts/") if n.endswith(".json")]
    if events or alerts:
        recent = [jget(base + "ledger/" + n) or {} for n in events[-20:]]
        out.append({"kind": "logs", "host": "eaveswatch", "source": "eaveswatch findings",
                    "content": {"findings_events": len(events), "alerts_fired": len(alerts),
                                "recent": [{k: ev.get(k) for k in ("at", "kind", "title", "severity", "status", "by")
                                            if ev.get(k)} for ev in recent]}})
    if not out:
        raise AtoneError(f"nothing for system {system!r} in {url} (an eaveswatch store has systems/system=NAME/)")
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
                    "source": f"openscap {profile.rsplit('_profile_', 1)[-1] or 'results'}",
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


# A mapping format: what each key means, what's required, an example. The readers check mappings against these, and
# `atone mappings --example KIND` prints them: the one place a format is written down.
SCANNER_MAPPING = {
    "file": "mappings/scanners/TOOL.mapping.json", "about": "how to read one scanner's exports",
    "keys": {"tool": "the scanner's name (it names the evidence)", "format": "csv or xml",
             "match": "a glob for its export files' names", "record": "xml only: the path to each finding",
             "fields": "{atone's field: the export's column (csv) or path (xml)}",
             "severity": "{critical|high|moderate|low: the export's words, or \">=N\" for a numeric score}"},
    "required": ["tool", "match", "fields"],
    "fields": {"host": "the asset's name (required)", "address": "its IP address", "finding": "what's wrong "
               "(required)", "id": "the scanner's id for it", "severity": "its severity", "cve": "CVE ids",
               "first_seen": "when it was first found", "solution": "the fix", "status": "open, fixed..."},
    "required_fields": ["host", "finding"],
    "open_fields": "any other field is kept as it is in each finding, for checks to read (agent_version, policy...)",
    "example": {"tool": "vulnscanner", "format": "csv", "match": "vulns-*.csv",
                "fields": {"host": "Asset Names", "address": "Asset IP Address", "finding": "Vulnerability Title",
                           "id": "Vulnerability ID", "severity": "Severity Level", "cve": "CVE IDs",
                           "first_seen": "First Found", "solution": "Solution"},
                "severity": {"critical": ">=9", "high": ">=7", "moderate": ">=4", "low": ">=0"}},
}


def import_mapped(path: Path, mapping: dict) -> list[dict]:
    """A scanner's export read through its mapping file (SCANNER_MAPPING says what's in one). One piece of evidence
    per host."""
    probs = format_problems(SCANNER_MAPPING, mapping)
    if probs:
        raise AtoneError(f"{mapping.get('_file', 'the mapping')}: " + "; ".join(probs))
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
    return [{"kind": "scan", "host": host, "source": tool,
             "content": {"tool": tool, "findings": found}} for host, found in sorted(by_host.items())]


def import_file(path: Path, mappings: list[dict]) -> list[dict]:
    """One file: OpenSCAP if it is, else the first mapping whose "match" (a glob) fits its name."""
    if is_oscap(path):
        return import_oscap(path)
    for m in mappings:
        if fnmatch.fnmatch(path.name, m.get("match") or ""):
            return import_mapped(path, m)
    raise AtoneError(f"{path.name}: not OpenSCAP output, and no scanner mapping matches it. Draft one from its "
                     f"columns (atone import SYSTEM --sample {path}) as mappings/scanners/TOOL.mapping.json")


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


# Shipped in the package, as plain text: no internet needed. (Piped over ssh to collect, this file has no __file__,
# and no use for the data.)
DATA = Path(globals().get("__file__") or ".").resolve().parent / "data"


def sources_dir() -> Path:
    """Where NIST's files are read from: a copy fetched into ~/atone/sources (atone controls fetch), else the ones
    shipped in the package."""
    return HOME / "sources" if (HOME / "sources" / "catalog.json").exists() else DATA / "nist"


def source_info(name: str) -> dict:
    """Where a NIST file came from: its url, when it was fetched, its SHA-256."""
    if sources_dir() == DATA / "nist":
        return (read_json(DATA / "lock.json", {}) or {}).get(f"nist/{name}.json") or {}
    return (read_json(sources_dir() / "lock.json", {}) or {}).get(name) or {}


def fetch_sources(from_dir: str | None = None, log=print) -> dict:
    """A newer copy of NIST's OSCAL files, into ~/atone/sources (used instead of the shipped ones), recorded with what
    each is (url or file, time, size, SHA-256) in its lock.json. From NIST's site, or from a folder they were
    downloaded into elsewhere (no internet needed): NIST's own file names or atone's (catalog.json, moderate.json...)."""
    d = HOME / "sources"
    d.mkdir(parents=True, exist_ok=True)
    lock = {}
    for name, url in SOURCES.items():
        if from_dir:
            cands = [Path(from_dir) / f"{name}.json", Path(from_dir) / url.rsplit("/", 1)[1]]
            src = next((c for c in cands if c.exists()), None)
            if not src:
                if name == "catalog":
                    raise AtoneError(f"no catalog in {from_dir} ({cands[1].name} or catalog.json)")
                continue
            data, origin = src.read_bytes(), str(src.resolve())
        else:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": f"atone/{__version__}"}),
                                        timeout=120) as r:
                data, origin = r.read(), url
        json.loads(data)                                    # it must at least be JSON
        (d / f"{name}.json").write_bytes(data)
        lock[name] = {"url": origin, "fetched": time.strftime("%Y-%m-%d"), "bytes": len(data),
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
        raise AtoneError(f"no catalog at {path}: the package's data is missing (reinstall atone)")
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
        raise AtoneError(f"no {name} baseline in {sources_dir()} (baselines: "
                         f"{', '.join(k for k in SOURCES if k != 'catalog')})")
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
    lock = source_info("catalog")
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
     "evidence": [{"name": "auditd", **F("/etc/audit/auditd.conf")},
                  {"name": "archive", "kind": "logs", "source": "eaveswatch archive*"}],
     "checks": [{"id": "keep-logs", "what": "auditd keeps rotated logs", "type": "present", "evidence": "auditd",
                 "pattern": r"^\s*max_log_file_action\s*=\s*(keep_logs|rotate)"}, {"id": "oscap", "type": "scan"},
                {"id": "archive-reaches-back", "what": "the log archive goes back the retention period (in days)",
                 "type": "value", "evidence": "archive", "pattern": r'"days_kept": (\d+)', "op": ">=",
                 "value": "{param:au-11_odp}"}],
     "needs_person": ["the records retention policy that sets the period (AU-11), and where logs are kept for it "
                      "(eaveswatch's store, if it runs)"]},
    {"control": "au-12", "about": "Audit record generation",
     "evidence": [{"name": "unit-files", "kind": "services", "source": "systemctl list-unit-files*"}],
     "checks": [{"id": "auditd-at-boot", "what": "auditd starts at boot", "type": "present", "evidence": "unit-files",
                 "pattern": r"^auditd\.service\s+enabled"}, {"id": "oscap", "type": "scan"}]},
    {"control": "au-6", "about": "Audit record review, analysis and reporting",
     "evidence": [{"name": "findings", "kind": "logs", "source": "eaveswatch findings"},
                  {"name": "spec", "kind": "logs", "source": "eaveswatch interpreter*"}],
     "checks": [{"id": "reviewed", "what": "logs are reviewed: findings are recorded", "type": "exists",
                 "evidence": "findings"},
                {"id": "alert-rules", "what": "alert rules are defined", "type": "present", "evidence": "spec",
                 "pattern": r'"alerts": \[\s*\{'}],
     "needs_person": ["how often logs are reviewed, by whom, and who findings are reported to (AU-6a, b)"]},
    {"control": "si-4", "about": "System monitoring",
     "evidence": [{"name": "nodes", "kind": "logs", "source": "eaveswatch nodes"},
                  {"name": "spec", "kind": "logs", "source": "eaveswatch interpreter*"}],
     "checks": [{"id": "monitored", "what": "hosts ship their logs to the monitor", "type": "exists", "evidence": "nodes"},
                {"id": "alert-rules", "what": "alert rules are defined", "type": "present", "evidence": "spec",
                 "pattern": r'"alerts": \[\s*\{'}, {"id": "oscap", "type": "scan"}],
     "needs_person": ["the monitoring objectives, and what's done with what's found (SI-4a, d)"]},
    {"control": "cm-2", "about": "Baseline configuration: the installed software is known",
     "evidence": [{"name": "packages", "kind": "packages"}],
     "checks": [{"id": "inventory", "what": "the installed packages were collected", "type": "exists",
                 "evidence": "packages"}],
     "needs_person": ["the documented baseline configuration, and when it was last reviewed (CM-2a, CM-2b)"]},
    {"control": "cm-6", "about": "Configuration settings: the hardening profile",
     "evidence": [], "checks": [{"id": "oscap", "type": "scan"}],
     "needs_person": ["which configuration standard (STIG, CIS) and profile is the system's, and its deviations"]},
    {"control": "cm-7", "about": "Least functionality: no needless services",
     "evidence": [{"name": "packages", "kind": "packages"}, {"name": "aws", "kind": "aws"}],
     "checks": [{"id": "no-cleartext", "what": "no telnet, rsh, tftp or ftp servers installed", "type": "absent",
                 "evidence": "packages", "pattern": r"^(telnet-server|rsh-server|tftp-server|vsftpd|xinetd)\s"},
                {"id": "oscap", "type": "scan"},
                {"id": "no-stray-groups", "what": "no security group is attached to nothing, or names a missing group",
                 "type": "security_groups", "evidence": "aws", "fail_on": ["low"]}],
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
    {"control": "sc-8", "about": "Transmission confidentiality: no old TLS on any listener",
     "evidence": [{"name": "tls", "kind": "certs", "source": "TLS on listeners"}],
     "checks": [{"id": "no-old-tls", "what": "no listener negotiates TLS 1.0 or 1.1", "type": "absent", "evidence": "tls",
                 "pattern": r'"protocol": "TLSv1(\.1)?"'}, {"id": "oscap", "type": "scan"}],
     "needs_person": ["which connections carry what data, and that each is encrypted (the data flow diagrams)"]},
    {"control": "sc-17", "about": "PKI certificates: none about to expire",
     "evidence": [{"name": "tls", "kind": "certs", "source": "TLS on listeners"}],
     "checks": [{"id": "not-expiring", "what": "no listener's certificate expires within 30 days", "type": "count",
                 "evidence": "tls", "field_patterns": {"days_left": r"^(-\d+|[0-2]?\d)$"}, "op": "==", "value": 0}],
     "needs_person": ["where the certificates come from (the approved PKI), and who renews them"]},
    {"control": "sc-7", "about": "Boundary protection: nothing open to the whole internet but what's meant to be",
     "evidence": [{"name": "aws", "kind": "aws"}],
     "checks": [{"id": "security-groups", "what": "no security group opens admin or other ports to the world, allows "
                 "all traffic, or is a default group that allows anything", "type": "security_groups", "evidence": "aws",
                 "public_ports": [80, 443], "fail_on": ["high", "moderate"]}],
     "needs_person": ["the boundary's managed interfaces, and what's meant to be reachable from outside (SC-7a, b)"]},
]
SITE_STARTER = {
    "_about": "Written by a person, never by an agent: commands atone doesn't have, and patterns to redact on top "
              "of the built-in floor. Evidence from a site command is marked as such in every report.",
    "commands": {}, "redact": [],
}


CODEX_IGNORE = """# local state: never part of the history
runs/
imports/*
!imports/.keep
PLAN.md
plan.json
discovery.json
*.part
*.tmp
# an agent's working notes, if it works from here
CHECKLIST.md
HANDOFF.md
"""
CODEX_MD = """# The atone codex for {name}

This repository is everything known about the security of **{name}**, and its history is the system's security
history. Artifacts (the SSP workbook, the POA&M, OSCAL, the diagrams, the report) are generated from it by atone;
never edit them by hand.

| Path | What it is |
|---|---|
| `system.json` | the system: purpose, owners, categorization, hosts, components and the config files that define them |
| `tailoring.json` | the baseline, controls added and removed, parameter values, inherited and shared controls |
| `interfaces.json` | the intended flows (the SSP's boundary and data flows) |
| `controls/` | each control: responsibility, status (from atone's checks), its implementation statement (claims with citations) and review |
| `decisions/` | what people decided: risk acceptances, deviations, false positives, approved dates; each with who and why |
| `poam/` | one file per weakness, from opened to closed |
| `mappings/` | how the system is assessed: control mappings, scanner and workbook mappings |
| `evidence/` | the latest observed state of each host and the AWS account, redacted; its history is the system's |
| `workbooks/` | the customer's working documents, as given |
| `packages/` | exactly what was delivered, at each tag |
| `site.json` | commands atone doesn't have (a person's own); evidence from them says so |

Commits carry their provenance as trailers (`Control:`, `Status:`, `Evidence:`, `Drafted-by:`, `Reviewed-by:`,
`Decided-by:`): `atone history {name}` reads them. `main` is the system as understood and approved; the agent
drafts on branches, and merging is approval. Tags mark what was delivered (`atone package`).

A pre-commit hook refuses anything atone's redaction floor would catch (keys, tokens, passwords), whoever commits.
"""
HOOK = """#!/bin/sh
# atone: refuse a commit that adds anything the redaction floor would catch (keys, tokens, passwords)
PYTHONPATH="{path}${{PYTHONPATH:+:$PYTHONPATH}}" exec "{python}" -m atone guard
"""


def git(d: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(["git", "-C", str(d), *args], capture_output=True, text=True)
    if check and r.returncode:
        raise AtoneError(f"git {' '.join(args)}: {(r.stderr or r.stdout).strip()}")
    return r


def guard_text(text: str, where: str = "") -> list[str]:
    """Lines the redaction floor would change: what must never be committed."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if redact(line) != line:
            shown = redact(line)
            out.append(f"{where}:{i}: {clip_text(shown, 120)}")
    return out


def guard_staged(d: Path) -> list[str]:
    """What the staged changes would add that the redaction floor catches."""
    diff = git(d, "diff", "--cached", "-U0", "--no-color", "--diff-filter=AM").stdout
    found, current = [], ""
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            if redact(line[1:]) != line[1:]:
                found.append(f"{current}: {clip_text(redact(line[1:]), 120)}")
    return found


def _ident(d: Path) -> list[str]:
    """The repository's own git identity (and signing) when it has one; else atone's, on this host."""
    if git(d, "config", "user.name", check=False).stdout.strip():
        return []
    host = socket.gethostname()
    return ["-c", f"user.name=atone on {host}", "-c", f"user.email=atone@{host}"]


def codex_commit(d: Path, subject: str, body: str = "", trailers: list[tuple[str, str]] | None = None,
                 paths: list[str] | None = None) -> str | None:
    """Commit what changed (in `paths`, or everything), with provenance as trailers. Nothing changed: no commit.
    The agent's commits say so (Drafted-by), from HOBKIN_ID. Signing is the repository's own configuration."""
    git(d, "add", "-A", "--", *(paths or ["."]))
    if git(d, "diff", "--cached", "--quiet", check=False).returncode == 0:
        return None
    bad = guard_staged(d)
    if bad:
        git(d, "reset", "-q")
        raise AtoneError("not committed: it would add what the redaction floor catches:\n  " + "\n  ".join(bad[:10]))
    trailers = list(trailers or [])
    if os.environ.get("HOBKIN_ID") and not any(k == "Drafted-by" for k, _ in trailers):
        trailers.append(("Drafted-by", f"hobkin {os.environ['HOBKIN_ID']}"))
    msg = subject + ("\n\n" + body.strip() if body.strip() else "") + (
        "\n\n" + "\n".join(f"{k}: {v}" for k, v in trailers) if trailers else "")
    r = subprocess.run(["git", "-C", str(d), *_ident(d), "commit", "-q", "-F", "-"], input=msg, capture_output=True,
                       text=True)
    if r.returncode:
        raise AtoneError(f"git commit: {(r.stderr or r.stdout).strip()}")
    return git(d, "rev-parse", "--short", "HEAD").stdout.strip()


def init_system(name: str, store: str | None = None, remote: str | None = None, from_url: str | None = None) -> Path:
    """A system's codex: a git repository at ~/atone/systems/NAME (cloned from `from_url` when there's one already,
    as on a fresh machine), with its layout, the starter mappings, and the guard hook."""
    d = system_dir(name, must_exist=False)
    if from_url and not (d / ".git").exists():
        d.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(["git", "clone", "-q", from_url, str(d)], capture_output=True, text=True)
        if r.returncode:
            raise AtoneError(f"git clone {from_url}: {r.stderr.strip()}")
        if git(d, "rev-parse", "-q", "--verify", "HEAD", check=False).returncode:
            # the remote's HEAD names a branch it doesn't have (a bare repository made with another default branch):
            # take main, or its only branch, rather than starting a second history
            heads = git(d, "for-each-ref", "--format=%(refname:lstrip=3)", "refs/remotes/origin").stdout.split()
            heads = [h for h in heads if h != "HEAD"]
            pick = "main" if "main" in heads else heads[0] if len(heads) == 1 else None
            if pick:
                git(d, "checkout", "-q", "-B", pick, f"origin/{pick}")
            elif heads:
                raise AtoneError(f"{from_url} has branches {', '.join(heads)} but no main: say which to use "
                                 "(git -C {d} checkout BRANCH)")
    d.mkdir(parents=True, exist_ok=True)
    if not (d / ".git").exists():
        git(d, "init", "-q", "-b", "main")
    for sub in ("mappings/controls", "mappings/scanners", "mappings/workbooks", "imports", "runs", "workbooks",
                "drafts", "controls", "decisions", "poam", "evidence", "packages"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    (d / "imports" / ".keep").touch()
    for path, text in ((".gitignore", CODEX_IGNORE), ("CODEX.md", CODEX_MD.format(name=name))):
        if not (d / path).exists():
            (d / path).write_text(text)
    starter = d / "mappings" / "controls" / "starter.json"
    if not starter.exists():
        write_json(starter, STARTER_MAPPINGS)
    for fname, start in (("tailoring.json", TAILORING_STARTER), ("system.json", SPEC_STARTER),
                         ("site.json", SITE_STARTER), ("interfaces.json", [])):
        if not (d / fname).exists():
            write_json(d / fname, start)
    conf = read_json(d / "atone.json", {})
    if store:
        conf["store"] = store
    if conf != read_json(d / "atone.json", None):
        write_json(d / "atone.json", conf)
    hook = d / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(HOOK.format(python=sys.executable, path=str(Path(__file__).resolve().parent.parent)))
    hook.chmod(0o755)
    if remote and git(d, "remote", check=False).stdout.strip() == "":
        git(d, "remote", "add", "origin", remote)
    codex_commit(d, f"codex: {name} set up" if not from_url else f"codex: {name} on {socket.gethostname()}",
                 trailers=[("System", name)])
    return d


def system_store(d: Path) -> Store | None:
    """Where raw scanner exports are archived, by hash (a folder or s3://...), if the system names one."""
    url = read_json(d / "atone.json", {}).get("store")
    return Store(url) if url else None


def slug(text: str, n: int = 100) -> str:
    out = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_.")[:n] or "x"
    return out if out == text[:n] else out + "-" + hashlib.sha1(text.encode()).hexdigest()[:6]


def _evidence_path(rec: dict) -> str:
    ext = "json" if rec["content"][:1] in "[{" else "txt"
    return f"evidence/{slug(rec['host'], 60)}/{rec['kind']}/{slug(rec['source'])}.{ext}"


def _seen(d: Path) -> dict:
    return read_json(d / "runs" / "seen.json", {}) or {}


def _merge_connections(old_text: str, new_rows: list, now: float) -> list:
    """Connections seen before and now: a set that grows (each with when it was first seen); this collect's are
    remembered locally (runs/connections-seen.json), so how recently each was seen never churns the history."""
    try:
        old = json.loads(old_text) if old_text else []
    except json.JSONDecodeError:
        old = []
    key = lambda r: (r.get("proto"), r.get("direction"), r.get("local"), r.get("remote"), r.get("process"))
    merged = {key(r): r for r in old if isinstance(r, dict)}
    for r in new_rows:
        if key(r) not in merged:
            merged[key(r)] = {**r, "first_seen": time.strftime("%Y-%m-%d", time.gmtime(now))}
    return sorted(merged.values(), key=lambda r: (r.get("direction", ""), r.get("local", ""), r.get("remote", "")))


def save_records(d: Path, recs: list[dict], subject: str | None = None, trailers=None) -> list[dict]:
    """Evidence into the codex: each record at its stable path (evidence/HOST/KIND/SOURCE), the content as it is
    (readable in a diff), its id, hash and when it was first seen in the host's index.json. A file changes only when
    the content does; then it's committed. Returns what changed: [{path, change, id}]."""
    now = time.time()
    seen = _seen(d)
    conn_seen = read_json(d / "runs" / "connections-seen.json", {}) or {}
    indexes: dict[str, dict] = {}
    changed = []
    for rec in recs:
        rel = _evidence_path(rec)
        host_dir = rel.split("/")[1]
        idx = indexes.setdefault(host_dir, read_json(d / "evidence" / host_dir / "index.json", {}) or {})
        if rec["kind"] == "flows" and rec["source"] == "connections":
            try:
                rows = json.loads(rec["content"])
            except json.JSONDecodeError:
                rows = []
            for r in rows:
                conn_seen[json.dumps([rec["host"], r.get("proto"), r.get("direction"), r.get("local"), r.get("remote"),
                                      r.get("process")])] = now
            old = (d / rel).read_text() if (d / rel).exists() else ""
            text = json.dumps(_merge_connections(old, rows, now), indent=1, sort_keys=True)
            rec = {**rec, "content": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}
        name = rel.split("/", 2)[2]
        prev = idx.get(name)
        seen[rel] = now
        if prev and prev.get("sha256") == rec["sha256"]:
            continue
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(rec["content"] if rec["content"].endswith("\n") else rec["content"] + "\n")
        idx[name] = {k: rec[k] for k in ("id", "kind", "host", "source", "site", "sha256") if k in rec}
        idx[name]["first_seen"] = rec["at"]
        for k in ("file_sha256", "from_file"):
            if k in rec:
                idx[name][k] = rec[k]
        changed.append({"path": rel, "change": "changed" if prev else "added", "id": rec["id"]})
    for host_dir, idx in indexes.items():
        write_json(d / "evidence" / host_dir / "index.json", idx)
    write_json(d / "runs" / "seen.json", seen)
    write_json(d / "runs" / "connections-seen.json", conn_seen)
    if changed:
        hosts = sorted({c["path"].split("/")[1] for c in changed})
        codex_commit(d, subject or f"evidence: {len(changed)} changed ({', '.join(hosts)})",
                     "\n".join(f"{c['change']}: {c['path']}" for c in changed[:200]),
                     (trailers or []) + [("Evidence", c["id"]) for c in changed[:50]], paths=["evidence"])
    return changed


def _content_hash_ok(text: str, sha: str) -> bool:
    return hashlib.sha256(text.encode()).hexdigest() == sha or \
        hashlib.sha256(text.rstrip("\n").encode()).hexdigest() == sha


def current_index(d: Path, fresh_days: float | None = None) -> list[dict]:
    """The evidence in the codex: the latest observed state of each source on each host. Each entry says when it was
    last collected here (`last_seen`, local; a fresh clone doesn't know, and says so with None)."""
    seen = _seen(d)
    out = []
    for idx_file in sorted((d / "evidence").glob("*/index.json")) if (d / "evidence").is_dir() else []:
        for name, meta in (read_json(idx_file, {}) or {}).items():
            rel = f"evidence/{idx_file.parent.name}/{name}"
            out.append({**meta, "path": rel, "at": seen.get(rel) or meta.get("first_seen"), "last_seen": seen.get(rel)})
    return sorted(out, key=lambda e: (e["kind"], e["host"], e["source"]))


def load_record(d: Path, entry: dict) -> dict | None:
    """A piece of evidence from the codex: its content (as hashed: the final newline added on writing taken off if
    it wasn't part of it), its id, hash and where it came from. `tampered` when the file doesn't match its hash."""
    p = d / entry["path"]
    if not p.exists():
        return None
    text = p.read_text()
    for content in (text, text[:-1] if text.endswith("\n") else None):
        if content is not None and hashlib.sha256(content.encode()).hexdigest() == entry["sha256"]:
            return {**entry, "content": content}
    return {**entry, "content": text, "tampered": True}


def was_evidence(d: Path, eid: str) -> bool:
    """Whether an evidence id was ever in the codex (it's in the history, superseded by newer evidence)."""
    return bool(git(d, "log", "--all", "--format=%h", "-S", eid, "--", "evidence", check=False).stdout.strip())


def search_index(d: Path):
    """The current evidence in a full-text index (SQLite FTS5: ranked, with snippets), kept in step: records that
    are new are added, ones no longer current are dropped. In runs/ (local); rebuilt from the codex if lost."""
    import sqlite3
    (d / "runs").mkdir(exist_ok=True)
    con = sqlite3.connect(d / "runs" / "evidence-index.db")
    con.executescript("CREATE TABLE IF NOT EXISTS docs (id TEXT PRIMARY KEY);"
                      "CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(id UNINDEXED, kind UNINDEXED, host, source, "
                      "content, tokenize = \"unicode61 tokenchars '_.-/'\");")
    have = {r[0] for r in con.execute("SELECT id FROM docs")}
    current = {e["id"]: e for e in current_index(d)}
    for gone in have - set(current):
        con.execute("DELETE FROM docs WHERE id = ?", (gone,))
        con.execute("DELETE FROM fts WHERE id = ?", (gone,))
    for eid in set(current) - have:
        rec = load_record(d, current[eid])
        if rec:
            con.execute("INSERT INTO docs (id) VALUES (?)", (eid,))
            con.execute("INSERT INTO fts (id, kind, host, source, content) VALUES (?,?,?,?,?)",
                        (eid, rec["kind"], rec["host"], rec["source"], rec["content"]))
    con.commit()
    return con


def search_evidence(d: Path, query: str, n: int = 20) -> list[dict]:
    """Ranked current evidence for some words (every word first, any if that finds nothing), each with a snippet."""
    words = re.findall(r"[\w./-]+", query)
    con = search_index(d)
    hits = []
    for op in (" AND ", " OR "):
        q = op.join('"' + w.replace('"', "") + '"*' for w in words)
        if not q:
            break
        hits = con.execute("SELECT id, kind, host, source, snippet(fts, 4, '[', ']', ' ... ', 16) FROM fts "
                           "WHERE fts MATCH ? ORDER BY bm25(fts) LIMIT ?", (q, n)).fetchall()
        if hits:
            break
    con.close()
    return [dict(zip(("id", "kind", "host", "source", "snippet"), h)) for h in hits]


def collect(name: str, kinds: list[str] | None = None, targets: list[str] | None = None, log=print) -> list[dict]:
    """Evidence from the built-in collectors, on this host (or each --ssh target), then the AWS calls once; what
    changed is committed to the codex."""
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
        got = c_aws(spec)
        for source, content in got:
            recs.append(make_record(name, "aws", "aws", source, content, extra_redact=site.get("redact")))
        log(f"aws: {got[0][1]}" if len(got) == 1 and isinstance(got[0][1], str) else f"aws: {len(got)} calls")
    for label, cmd in (site.get("commands") or {}).items():         # a person's own, marked as such
        code, text = run_cmd(shlex.split(cmd), timeout=300)
        recs.append(make_record(name, "site", socket.gethostname(), f"site command {label}: {cmd}",
                                text if code == 0 else f"exit code {code}: {text}", site=True,
                                extra_redact=site.get("redact")))
    changed = save_records(d, recs, f"evidence: collected ({', '.join(sorted({r['host'] for r in recs}))})")
    log(f"{len(recs)} pieces of evidence, {len(changed)} changed since the last collect"
        + (" (committed)" if changed else ""))
    return changed


def import_results(name: str, files: list[str] | None = None, log=print, eaveswatch: str | None = None,
                   ew_system: str | None = None, env: str | None = None) -> list[dict]:
    """Scanner results into evidence (committed to the codex): the files given, or everything in imports/; or, with
    `eaveswatch` (its store), what eaveswatch shows about logging. Raw exports stay out of the history (they're
    archived in the store by hash if the system names one): what's normalized from them goes in."""
    d = system_dir(name)
    site = read_json(d / "site.json", {})
    if eaveswatch:
        recs = [make_record(name, p["kind"], p["host"], p["source"], p["content"], extra_redact=site.get("redact"))
                for p in import_eaveswatch(eaveswatch, ew_system or name, env)]
        changed = save_records(d, recs, f"evidence: imported from eaveswatch ({ew_system or name})")
        log(f"eaveswatch: {', '.join(r['source'] for r in recs)} ({len(changed)} changed)")
        return changed
    mappings = [{**read_json(mp, {}), "_file": mp.name} for mp in sorted((d / "mappings" / "scanners").glob("*.mapping.json"))]
    paths = [Path(f) for f in files] if files else sorted(p for p in (d / "imports").iterdir()
                                                           if p.is_file() and not p.name.startswith("."))
    if not paths:
        raise AtoneError(f"nothing to import: put scanner exports in {d / 'imports'}, or name them")
    store = system_store(d)
    recs = []
    for path in paths:
        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        if store:
            store.put(f"exports/{sha}{path.suffix}", data)
        n = 0
        for part in import_file(path, mappings):
            rec = make_record(name, part["kind"], part["host"], part["source"], part["content"],
                              extra_redact=site.get("redact"))
            rec.update(file_sha256=sha, from_file=path.name)           # the export it came from, as it was
            recs.append(rec)
            n += 1
        hosts = sorted({r["host"] for r in recs if r.get("from_file") == path.name})
        strange = [h for h in hosts if not in_boundary(read_json(d / "system.json", {}))(h)]
        log(f"{path.name}: {n} hosts" + (f" (not this system's, so not counted: {', '.join(strange)})" if strange else ""))
    changed = save_records(d, recs, f"evidence: imported {', '.join(p.name for p in paths)}")
    log(f"{len(recs)} pieces of evidence, {len(changed)} changed" + (" (committed)" if changed else ""))
    return changed


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
    "security_groups": "the account's security groups reviewed (AWS evidence): fails on findings at the severities in "
                       "fail_on (default high, moderate); public_ports are the ports meant to be open to the world",
}
CONTROL_MAPPING = {
    "file": "mappings/controls/NAME.json (one mapping or a list)", "about": "the evidence that bears on a control, "
    "and the checks atone runs on it",
    "keys": {"control": "its id, lower case (au-11)", "about": "what it covers, in a line",
             "evidence": "[{name, kind (a collector, scan, logs or site), source (a glob), component, host, tool}]",
             "checks": "[{id, what, type (CHECK_TYPES), evidence (an evidence name), pattern, op, value, "
                       "field_patterns, fail_on, public_ports, controls}]",
             "needs_person": "[what only a person can supply, citing the control's parts]"},
    "required": ["control"],
    "example": next(m for m in STARTER_MAPPINGS if m["control"] == "au-11"),
}
STATUSES = ("met", "partly", "not met", "unknown", "inherited")
NOT_READ = re.compile(r"^(not collected|not readable here|.*: not installed here|.*collector failed)", re.I)


def load_mappings(d: Path) -> dict[str, dict]:
    """{control id: mapping} from the system's mappings/ folder (a file may hold one mapping or a list)."""
    out = {}
    for p in sorted((d / "mappings" / "controls").rglob("*.json")):
        data = read_json(p, [])
        for m in data if isinstance(data, list) else [data]:
            if isinstance(m, dict) and m.get("control"):
                out[m["control"]] = {**m, "_file": str(p.relative_to(d))}
    return out


def format_problems(fmt: dict, m: dict) -> list[str]:
    """What a mapping has that its format doesn't (a misspelt key is otherwise silently ignored), or lacks."""
    out = [f"no {k!r}" for k in fmt.get("required") or [] if not m.get(k)]
    out += [f"{k!r} isn't a key atone reads (it reads {', '.join(fmt['keys'])})" for k in m
            if not k.startswith("_") and k not in fmt["keys"]]
    for part in ("fields", "columns"):
        if part in fmt and isinstance(m.get(part), dict):
            out += [f"{part}: {k!r} isn't one atone reads (it reads {', '.join(fmt[part])})" for k in m[part]
                    if k not in fmt[part] and not fmt.get("open_" + part)]
            out += [f"{part} needs {k!r}" for k in fmt.get("required_" + part) or [] if not m[part].get(k)]
    if "status_values" in fmt and isinstance(m.get("status_values"), dict):
        out += [f"status_values: {k!r} isn't one of atone's ({', '.join(fmt['status_values'])})"
                for k in m["status_values"] if k not in fmt["status_values"]]
    return out


def mapping_problems(m: dict) -> list[str]:
    """What's wrong with a control mapping (an empty list: nothing)."""
    out, names = format_problems(CONTROL_MAPPING, m), {e.get("name") for e in m.get("evidence") or []}
    for e in m.get("evidence") or []:
        if e.get("kind") not in set(COLLECTORS) | {"scan", "site", "logs"}:
            out.append(f"evidence {e.get('name')!r}: kind {e.get('kind')!r} isn't a collector, scan, logs or site")
    for c in m.get("checks") or []:
        if c.get("type") not in CHECK_TYPES:
            out.append(f"check {c.get('id')!r}: type {c.get('type')!r} isn't one of {', '.join(CHECK_TYPES)}")
        if c.get("type") not in ("scan",) and c.get("evidence") not in names:
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


ABOUT_SYSTEM = {"aws", "eaveswatch"}        # evidence about the system that isn't from one of its hosts


def in_boundary(spec: dict):
    """A test for a record's host: is it one of the system's (by name, another name it's known by, an address, or the
    same short name: a scanner's app01.example.internal is the spec's app01)? Everything is, until the spec names
    hosts. Evidence from elsewhere (a scan of another system's host) never counts toward this system's controls."""
    known = set()
    for h in spec.get("hosts") or []:
        for n in ([h] if isinstance(h, str) else [h.get("name"), *(h.get("names") or []), *(h.get("addresses") or [])]):
            if n:
                known |= {str(n).lower(), str(n).lower().split(".")[0]} if not re.match(r"[\d.:]+$", str(n)) else {str(n)}
    if not known:
        return lambda host: True
    return lambda host: (host in ABOUT_SYSTEM or str(host).lower() in known
                         or (not re.match(r"[\d.:]+$", str(host)) and str(host).lower().split(".")[0] in known))


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
    elif t == "security_groups":
        items = []
        for r in usable:
            try:
                items.append((r["id"], r["source"], json.loads(r["content"])))
            except json.JSONDecodeError:
                continue
        model = aws_model(items)
        if not model["groups"]:
            out.update(status="unknown", detail="no security groups in the evidence")
            return out
        found = review_security_groups(model, tuple(c.get("public_ports") or (80, 443)))
        bad = [f for f in found if f["severity"] in (c.get("fail_on") or ["high", "moderate"])]
        out["quotes"] = [{"evidence": f["evidence"], "quote": f"{f['group']} ({f['name']}): {f['what']}"
                          + (f" [{f['rule']}]" if f["rule"] else "") + ("; reachable from the internet" if f["reachable"]
                                                                       else "; not reachable from the internet now")}
                         for f in (bad or found)[:10]]
        out.update(status="fail" if bad else "pass",
                   detail=f"{len(model['groups'])} groups: {len(bad)} findings at {', '.join(c.get('fail_on') or ['high', 'moderate'])}"
                          + (f" ({sum(1 for f in bad if f['reachable'])} reachable from the internet)" if bad else "")
                          + (f", {len(found) - len(bad)} lesser" if len(found) > len(bad) else ""))
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


def control_path(d: Path, cid: str) -> Path:
    return d / "controls" / f"{cid}.json"


def load_controls(d: Path) -> dict[str, dict]:
    """The model's controls: {id: what the codex says of it} (status and checks from atone's checks; the statement
    and its review from people and the agent)."""
    out = {}
    for p in sorted((d / "controls").glob("*.json")) if (d / "controls").is_dir() else []:
        c = read_json(p, {}) or {}
        if c.get("control"):
            out[c["control"]] = c
    return out


def save_control(d: Path, cid: str, data: dict) -> bool:
    """Write a control's file if it changed; whether it did."""
    path = control_path(d, cid)
    if read_json(path, None) == data:
        return False
    write_json(path, data)
    return True


def approved_schedule(d: Path) -> dict:
    """POA&M dates a person approved (decisions/poam-schedule.json: {item key: date}); none are made up."""
    return (read_json(d / "decisions" / "poam-schedule.json", {}) or {}).get("dates") or {}


def sync_poam(d: Path) -> tuple[list, list]:
    """The POA&M in the codex: a file per weakness (poam/KEY.json). New ones are opened, with their evidence; open
    ones whose finding isn't in the evidence any more are marked as looking closed (a person closes them: atone
    decide SYSTEM poam-close). Returns (opened, look closed)."""
    items = {it["key"]: it for it in poam_items(d)}
    opened, gone = [], []
    have = {}
    for p in sorted((d / "poam").glob("*.json")) if (d / "poam").is_dir() else []:
        x = read_json(p, {}) or {}
        if x.get("key"):
            have[x["key"]] = (p, x)
    today = time.strftime("%Y-%m-%d", time.gmtime())
    for key, it in items.items():
        if key in have:
            p, x = have[key]
            if x.get("evidence_says"):                 # back in the evidence: no longer looks closed
                x.pop("evidence_says")
                write_json(p, x)
            continue
        write_json(d / "poam" / f"{slug(key, 120)}.json", {**{k: it[k] for k in ("key", "weakness", "description",
                    "control", "severity", "source", "asset", "evidence")}, "detected": it["detected"] or today,
                    "opened": today, "status": "open"})
        opened.append(it)
    for key, (p, x) in have.items():
        if x.get("status") == "open" and key not in items and not x.get("evidence_says"):
            x["evidence_says"] = f"not in the evidence since {today}: it looks closed (a person decides)"
            write_json(p, x)
            gone.append(x)
    return opened, gone


def check_system(name: str, log=print) -> dict:
    """Every control in the system's baseline, against its mapping and the current evidence: per control, its checks'
    results, a status (met, partly, not met, unknown, inherited), and what a person must supply. Each control's
    file in controls/ is updated (its statement and review kept), the POA&M synced, and what changed committed, each
    status change a trailer. (runs/checks-latest.json keeps this run's results locally.)"""
    d = system_dir(name)
    spec = read_json(d / "system.json", {})
    ctls = system_controls(d)
    maps = load_mappings(d)
    index = current_index(d)
    inside = in_boundary(spec)
    inside = (lambda e, test=inside: e["kind"] == "site" or test(e["host"]))   # a person's commands: from here
    outside = sorted({e["host"] for e in index if not inside(e)})
    if outside:
        log(f"not counted: evidence from {', '.join(outside)}, which system.json doesn't name as this system's "
            "(add it there if it is)")
    index = [e for e in index if inside(e)]
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
    write_json(d / "runs" / "checks-latest.json", out)
    before = load_controls(d)
    changes = []
    for cid, entry in results.items():
        old = before.get(cid) or {}
        new = {**entry, **({"statement": old["statement"]} if old.get("statement") else {})}
        if save_control(d, cid, new) and old.get("status") != entry["status"]:
            changes.append((cid, old.get("status") or "new", entry["status"]))
    for cid in set(before) - set(results):           # tailored out: its file goes (the history keeps it)
        control_path(d, cid).unlink()
        changes.append((cid, before[cid].get("status"), "removed"))
    first = not before
    real = [c for c in changes if not (c[1] == "new" and c[2] == "unknown")]    # a new control nothing says about yet
    codex_commit(d, f"checks: the first assessment ({len(results)} controls)" if first else
                 f"checks: {len(real)} control status changes" if real else "checks: details updated",
                 ", ".join(f"{k} {v}" for k, v in counts.items() if v),
                 [("Status", f"{c} {a} -> {b}") for c, a, b in real[:100]], paths=["controls"])
    opened, gone = sync_poam(d)
    if opened or gone:
        codex_commit(d, f"poam: {len(opened)} opened" + (f", {len(gone)} look closed" if gone else ""),
                     "\n".join([f"opened: {i['weakness']} on {i['asset']} ({i['severity']})" for i in opened]
                               + [f"looks closed: {x['weakness']} on {x['asset']}" for x in gone]),
                     [("Evidence", i["evidence"]) for i in opened[:50]], paths=["poam"])
    log(", ".join(f"{v} {k}" for k, v in counts.items()) + f" ({len(results)} controls, {len(index)} pieces of evidence)"
        + (f"; {len(changes)} status changes" if changes else "") + (f"; POA&M: {len(opened)} opened" if opened else ""))
    return out


def save_statement(d: Path, verified: dict) -> str | None:
    """A verified narrative into its control's file (as drafted: a person reviews it with atone review), committed
    with the evidence it cites."""
    cid = verified["control"]
    ctl = read_json(control_path(d, cid), None) or {"control": cid}
    who = f"hobkin {os.environ['HOBKIN_ID']}" if os.environ.get("HOBKIN_ID") else \
        (git(d, "config", "user.name", check=False).stdout.strip() or "someone")
    ctl["statement"] = {"text": verified["statement"], "claims": verified["claims"], "dropped": verified["dropped"],
                        "coverage": verified["coverage"], "drafted_by": who,
                        "drafted_at": time.strftime("%Y-%m-%d", time.gmtime()), "reviewed_by": None, "reviewed_at": None}
    if not save_control(d, cid, ctl):
        return None
    cites = sorted({c["evidence"] for cl in verified["claims"] for c in cl.get("cites") or [] if c.get("evidence")})
    cov = verified["coverage"]
    return codex_commit(d, f"{ctl.get('label', cid.upper())}: implementation statement drafted",
                        f"{cov['evidence']} claims on evidence, {cov.get('document', 0)} on the customer's documents, "
                        f"{cov['person']} on a person's word, {cov['dropped']} dropped by verify.", [("Control", cid)] + [("Evidence", e) for e in cites],
                        paths=[str(control_path(d, cid).relative_to(d))])


def review_statements(d: Path, cids: list[str], by: str) -> str | None:
    """A person's review of drafted statements: who, and when, committed (Reviewed-by)."""
    today = time.strftime("%Y-%m-%d", time.gmtime())
    done = []
    for cid in cids:
        ctl = read_json(control_path(d, cid), None)
        if not ctl or not ctl.get("statement"):
            raise AtoneError(f"{cid} has no drafted statement to review")
        ctl["statement"].update(reviewed_by=by, reviewed_at=today)
        save_control(d, cid, ctl)
        done.append(ctl.get("label", cid))
    return codex_commit(d, f"review: {', '.join(done)}", f"Reviewed by {by}.",
                        [("Reviewed-by", by)] + [("Control", c) for c in cids], paths=["controls"])


DECISION_KINDS = ("risk-acceptance", "deviation", "false-positive", "tailoring", "poam-schedule", "poam-close", "other")


def decide(d: Path, kind: str, what: str, by: str, controls: list[str] | None = None, until: str | None = None,
           from_file: str | None = None, items: list[str] | None = None) -> str | None:
    """A person's decision, recorded and committed with who and why (Decided-by): a risk acceptance, a deviation, a
    false positive, a tailoring change; an approved POA&M schedule (from the agent's proposal, --from); closing POA&M
    items (--item)."""
    if kind not in DECISION_KINDS:
        raise AtoneError(f"a decision is one of: {', '.join(DECISION_KINDS)}")
    today = time.strftime("%Y-%m-%d", time.gmtime())
    rec = {"kind": kind, "what": what, "by": by, "at": today, "controls": controls or [], "until": until}
    paths = ["decisions"]
    if kind == "poam-schedule":
        dates = read_json(Path(from_file or d / "drafts" / "poam-schedule.json"), None)
        if not isinstance(dates, dict) or not dates:
            raise AtoneError("an approved schedule needs the proposed one: --from FILE ({item key: date})")
        write_json(d / "decisions" / "poam-schedule.json", {**rec, "dates": dates})
    else:
        if kind == "poam-close":
            if not items:
                raise AtoneError("poam-close needs --item KEY (one or more)")
            for p in sorted((d / "poam").glob("*.json")):
                x = read_json(p, {}) or {}
                if x.get("key") in items or p.stem in items:
                    x.update(status="closed", closed=today, closed_by=by, closed_because=what)
                    write_json(p, x)
            paths.append("poam")
        write_json(d / "decisions" / f"{today}-{kind}-{slug(what, 40)}.json", rec)
    return codex_commit(d, f"decision: {kind}: {clip_text(what, 60)}", what,
                        [("Decided-by", by)] + [("Control", c) for c in controls or []] + [("Kind", kind)], paths=paths)


def history(d: Path, control: str | None = None, path: str | None = None, since: str | None = None,
            n: int = 50) -> list[dict]:
    """The codex's history, newest first: each commit's date, author, subject and trailers. For one control: the
    commits that name it (a Control trailer) or touched its file; for a path (evidence/HOST...); since a date."""
    fmt = "--format=%h%x1f%an%x1f%aI%x1f%s%x1f%(trailers:unfold=true,separator=%x1d)%x1e"
    base = ["log", f"-n{n}", fmt] + ([f"--since={since}"] if since else [])
    runs = []
    if control:
        runs.append(base + [f"--grep=^Control: {control}$"])
        runs.append(base + ["--", str(control_path(d, control).relative_to(d))])
    else:
        runs.append(base + (["--", path] if path else []))
    found = {}
    for args in runs:
        for rec in git(d, *args, check=False).stdout.split("\x1e"):
            f = rec.strip("\n").split("\x1f")
            if len(f) >= 5:
                found[f[0]] = {"commit": f[0], "author": f[1], "at": f[2], "subject": f[3],
                               "trailers": [t for t in f[4].split("\x1d") if t.strip()]}
    return sorted(found.values(), key=lambda c: c["at"], reverse=True)[:n]


def package(name: str, tag: str, note: str = "", log=print) -> Path:
    """What's delivered, kept: the workbooks filled, the diagrams, OSCAL and the report into packages/TAG/,
    committed and tagged, so the history holds exactly what went out."""
    d = system_dir(name)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,80}", tag):
        raise AtoneError(f"not a tag: {tag!r}")
    if git(d, "rev-parse", "-q", "--verify", f"refs/tags/{tag}", check=False).returncode == 0:
        raise AtoneError(f"{tag} is taken: a package is never replaced")
    out = d / "packages" / tag
    out.mkdir(parents=True, exist_ok=True)
    if any((d / "workbooks").glob("*.xlsx")):
        fill_workbooks(name, out, log=log)
    draw_system(name, out, log=log)
    write_oscal(name, out / "oscal", log=log)
    report(name, out, log=log)
    codex_commit(d, f"package: {tag}", note or f"The package delivered as {tag}.", [("Package", tag)],
                 paths=[str(out.relative_to(d))])
    git(d, *_ident(d), "tag", "-a", tag, "-m", note or f"atone package {tag}")
    log(f"{tag}: {out} (committed and tagged)")
    return out





def _norm(text: str) -> str:
    return " ".join(text.split()).lower()


def verify_narrative(d: Path, draft: dict) -> dict:
    """Check every citation in a drafted narrative: each claim must cite current evidence whose (hash-checked)
    content contains the words it quotes, or a document in the codex ({"document": "workbooks/SSP.docx", "quote"}: a
    Word, Excel or text file, its text containing the quote; its SHA-256 is kept, so a later change to it shows). A
    claim a person told you cites who and when instead ({"person": ...}). Claims that don't hold are dropped, with
    why; the statement is rebuilt from what's left."""
    index = {e["id"]: e for e in current_index(d)}
    kept, dropped = [], []
    docs: dict[str, tuple] = {}

    def document(rel):
        if rel not in docs:
            p = (d / rel).resolve()
            if not p.is_relative_to(d.resolve()) or not p.is_file():
                docs[rel] = (None, f"no document {rel!r} in the codex")
            else:
                try:
                    text = doc_text(p) if p.suffix.lower() in (".docx", ".xlsx", ".xlsm") else p.read_text(errors="replace")
                    docs[rel] = (text, hashlib.sha256(p.read_bytes()).hexdigest())
                except AtoneError as e:
                    docs[rel] = (None, str(e))
        return docs[rel]
    for claim in draft.get("claims") or []:
        text, cites = (claim.get("text") or "").strip(), claim.get("cites") or []
        if claim.get("person"):
            kept.append({**claim, "basis": "person"})
            continue
        why = None if cites else "it cites nothing"
        for cite in cites:
            if cite.get("document") and not cite.get("evidence"):
                text, sha = document(cite["document"])
                if text is None:
                    why = sha
                    break
                if not cite.get("quote") or _norm(cite["quote"]) not in _norm(text):
                    why = f"{cite['document']} doesn't say {clip_text(cite.get('quote') or '(no quote)', 80)!r}"
                    break
                cite["sha256"] = sha
                continue
            e = index.get(cite.get("evidence"))
            if not e:
                why = (f"{cite.get('evidence')} has been superseded by newer evidence"
                       if cite.get("evidence") and was_evidence(d, cite["evidence"]) else f"no evidence {cite.get('evidence')!r}")
                break
            rec = load_record(d, e)
            if not rec or rec.get("tampered") or not check_record(rec):
                why = f"{e['id']} doesn't match its hash"
                break
            if not cite.get("quote") or _norm(cite["quote"]) not in _norm(rec["content"]):
                why = f"{e['id']} doesn't say {clip_text(cite.get('quote') or '(no quote)', 80)!r}"
                break
        if why:
            dropped.append({"text": text, "why": why})
        else:
            kept.append({**claim, "basis": "evidence" if any(c.get("evidence") for c in cites) else "document"})
    return {"control": draft.get("control"), "statement": " ".join(c["text"].strip() for c in kept),
            "claims": kept, "dropped": dropped, "verified_at": time.time(),
            "coverage": {"evidence": sum(1 for c in kept if c["basis"] == "evidence"),
                         "document": sum(1 for c in kept if c["basis"] == "document"),
                         "person": sum(1 for c in kept if c["basis"] == "person"), "dropped": len(dropped)}}


def clip_text(text: str, n: int) -> str:
    one = " ".join(text.split())
    return one if len(one) <= n else one[:n - 3] + "..."


# ---- workbooks: the customer's Excel files: read them, fill them in (a copy, only cell values), say what changed;
#      their Word documents, as text

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


def doc_text(path) -> str:
    """A working document as plain text, for reading or searching: a .docx's paragraphs in order, its headings as
    '#' lines (by the document's own heading styles), list items as '- ', and its tables as '|' rows; an .xlsx's
    sheets, row by row. Read with the standard library; redacted like everything else atone writes."""
    import xml.etree.ElementTree as ET
    import zipfile
    path = Path(path)
    if path.suffix.lower() in (".xlsx", ".xlsm"):
        wb = Workbook(path)
        out = []
        for sheet in wb.sheets:
            out.append(f"# {sheet}")
            for n, row in sorted(wb.rows(sheet).items()):
                vals = [f"{k}={v}" for k, v in sorted(row.items(), key=lambda kv: (len(kv[0]), kv[0])) if str(v).strip()]
                if vals:
                    out.append(f"{n}: " + " | ".join(vals))
            out.append("")
        return redact("\n".join(out))
    try:
        z = zipfile.ZipFile(path)
        body = ET.fromstring(z.read("word/document.xml"))
    except (zipfile.BadZipFile, KeyError):
        raise AtoneError(f"{path.name} isn't a .docx or .xlsx (save it as Word Document (.docx))")
    w = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    mc = "{http://schemas.openxmlformats.org/markup-compatibility/2006}"
    level = {}                                       # style id -> heading level, from the document's own styles
    try:
        for st in ET.fromstring(z.read("word/styles.xml")).iter(w + "style"):
            name = st.find(w + "name")
            m = re.match(r"(?i)heading\s*(\d)$|^title$", (name.get(w + "val") if name is not None else "") or "")
            if m:
                level[st.get(w + "styleId")] = int(m.group(1) or 1)
    except KeyError:
        pass

    def text(el):
        parts = []
        for e in el.iter():
            if e.tag == mc + "Fallback":                 # the same text again, for older readers
                continue
            if e.tag == w + "t":
                parts.append(e.text or "")
            elif e.tag == w + "tab":
                parts.append("\t")
            elif e.tag in (w + "br", w + "cr"):
                parts.append("\n")
        return "".join(parts).strip()

    def para(p):
        t = text(p)
        if not t:
            return None
        ppr = p.find(w + "pPr")
        sid = ppr.find(w + "pStyle").get(w + "val") if ppr is not None and ppr.find(w + "pStyle") is not None else ""
        if sid in level or re.match(r"(?i)heading(\d)$", sid or ""):
            return "#" * (level.get(sid) or int(re.match(r"(?i)heading(\d)", sid).group(1))) + " " + t
        if ppr is not None and ppr.find(w + "numPr") is not None:
            return "- " + t
        return t
    out = []
    for el in body.find(w + "body"):
        if el.tag == w + "p":
            t = para(el)
            if t:
                out.append(("\n" if t.startswith("#") else "") + t)
        elif el.tag == w + "tbl":
            for tr in el.iter(w + "tr"):
                cells = [" ".join(filter(None, (para(p) or "" for p in tc.iter(w + "p")))) for tc in tr.findall(w + "tc")]
                out.append("| " + " | ".join(c.replace("\n", " ") for c in cells) + " |")
            out.append("")
    return redact("\n".join(out).strip() + "\n")


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


_WORKBOOK_KEYS = {"match": "a glob for the workbook's file name", "kind": "ssp or poam", "sheet": "the sheet's name",
                  "header_row": "the row the column headers are on (1 is the first)",
                  "columns": "{atone's field: the column's header text, exactly (or its letters: C)}",
                  "status_values": "{atone's status: the workbook's own drop-down value, exactly as written}"}
SSP_MAPPING = {
    "file": "mappings/workbooks/NAME.mapping.json", "about": "where an SSP control matrix keeps each control's status "
    "and implementation statement", "keys": _WORKBOOK_KEYS, "required": ["match", "kind", "sheet", "columns"],
    "columns": {"control": "the control id (required)", "status": "its implementation status",
                "statement": "its implementation statement", "evidence": "where atone notes its evidence"},
    "required_columns": ["control"], "status_values": ["met", "partly", "not met", "inherited"],
    "example": {"match": "ssp-*.xlsx", "kind": "ssp", "sheet": "Controls", "header_row": 3,
                "columns": {"control": "Control ID", "status": "Status", "statement": "Implementation Statement",
                            "evidence": "Evidence"},
                "status_values": {"met": "Implemented", "partly": "Partially Implemented", "not met": "Planned",
                                  "inherited": "Inherited"}},
}
POAM_MAPPING = {
    "file": "mappings/workbooks/NAME.mapping.json", "about": "a POA&M's item rows, for adding what's open",
    "keys": {**_WORKBOOK_KEYS, "id_format": "the ids of rows atone adds (default ATONE-{n:04d})"},
    "required": ["match", "kind", "sheet", "columns"],
    "columns": {"id": "the item's id", "weakness": "its name (required)", "description": "what it is",
                "control": "the control", "severity": "its severity", "detected": "when it was found",
                "due": "its scheduled completion (only from an approved schedule)", "status": "open or closed",
                "source": "what found it", "asset": "where (required)", "evidence": "atone's evidence id"},
    "required_columns": ["weakness", "asset"], "status_values": ["open", "closed"],
    "example": {"match": "poam*.xlsx", "kind": "poam", "sheet": "POA&M Items", "header_row": 1,
                "columns": {"id": "POA&M ID", "weakness": "Weakness Name", "description": "Weakness Description",
                            "control": "Security Control", "severity": "Severity", "detected": "Detection Date",
                            "due": "Scheduled Completion Date", "status": "Status", "source": "Source",
                            "asset": "Asset"},
                "status_values": {"open": "Open", "closed": "Closed"}},
}


def mapping_formats() -> dict:
    return {"controls": CONTROL_MAPPING, "scanner": SCANNER_MAPPING, "ssp": SSP_MAPPING, "poam": POAM_MAPPING}


def describe_format(kind: str) -> str:
    """A mapping format as text: the same definitions the readers check mappings against."""
    formats = mapping_formats()
    if kind not in formats:
        return "mapping formats: " + ", ".join(f"{k} ({f['about']})" for k, f in formats.items()) + \
               "\n  atone mappings --example KIND"
    f = formats[kind]
    out = [f"# {kind}: {f['about']}", f"file: {f['file']}", "", "keys:"]
    out += [f"  {k}{' (required)' if k in f.get('required', []) else ''}: {v}" for k, v in f["keys"].items()]
    for part in ("fields", "columns"):
        if part in f:
            out += ["", f"{part}:"] + [f"  {k}: {v}" for k, v in f[part].items()]
            if f.get("open_" + part):
                out.append(f"  (others: {f['open_' + part]})")
    if "status_values" in f:
        out += ["", "status_values: atone's " + ", ".join(f["status_values"]) + " (map each to the workbook's own)"]
    if kind == "controls":
        out += ["", "check types:"] + [f"  {k}: {v}" for k, v in CHECK_TYPES.items()]
        out += ["", "evidence kinds: " + ", ".join(list(COLLECTORS) + ["scan", "logs", "site"])]
    out += ["", "example:", json.dumps(f["example"], indent=2)]
    return "\n".join(out)


def plan_ssp(d: Path, wb: Workbook, mapping: dict) -> tuple[dict, list, list]:
    """The cells to set in an SSP control matrix, from the latest checks and the verified narratives: (edits, changes,
    flags). What's already filled in is kept; where the evidence disagrees with it, that's a flag, not an edit."""
    sheet, hdr = mapping["sheet"], int(mapping.get("header_row", 1))
    cols = resolve_columns(wb, sheet, hdr, mapping["columns"])
    checks = load_controls(d)
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
        st = (res or {}).get("statement")
        draft = {"statement": st["text"], "claims": st["claims"], "reviewed_by": st.get("reviewed_by")} if st else None
        ev = sorted({e for c in (res or {}).get("checks") or [] for e in c.get("evidence") or []})
        if res and "status" in cols:
            v = _status_value(mapping, res["status"])
            if v:
                detail = "; ".join(f"{c['check']}: {c['status']}" for c in res.get("checks") or []) or res.get("why", "")
                setcell(f"{cols['status']}{rown}", v, f"atone's checks: {res['status']} ({detail})", ev)
        if "statement" in cols:
            if draft and draft.get("statement"):
                cites = sorted({c["evidence"] for cl in draft["claims"] for c in cl.get("cites") or []})
                setcell(f"{cols['statement']}{rown}", draft["statement"], "a verified narrative" + (
                    f", reviewed by {draft['reviewed_by']}" if draft.get("reviewed_by") else ", not yet reviewed"), cites)
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
    finding isn't in the latest evidence. Dates come from the schedule a person approved (atone decide ... poam-schedule);
    none are made up."""
    sheet, hdr = mapping["sheet"], int(mapping.get("header_row", 1))
    cols = resolve_columns(wb, sheet, hdr, mapping["columns"])
    probs = check_status_values(wb, sheet, f"{cols['status']}{hdr + 1}", mapping) if "status" in cols else []
    if probs:
        raise AtoneError(f"{wb.path.name}: " + "; ".join(probs))
    rows = {r: c for r, c in wb.rows(sheet).items() if r > hdr}
    have = {(str(c.get(cols.get("weakness", ""), "")).strip().lower(), str(c.get(cols.get("asset", ""), "")).strip().lower()): r
            for r, c in rows.items()}
    schedule = approved_schedule(d)
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
    mappings = [{**read_json(p, {}), "_file": p.name} for p in sorted((d / "mappings" / "workbooks").glob("*.mapping.json"))]
    paths = [Path(f) for f in files] if files else sorted((d / "workbooks").glob("*.xlsx"))
    if not paths:
        raise AtoneError(f"no working documents: put them in {d / 'workbooks'} (with a mapping each in "
                         f"mappings/workbooks/: atone workbook inspect FILE shows what to map)")
    reports = []
    for path in paths:
        m = next((m for m in mappings if fnmatch.fnmatch(path.name, m.get("match") or "")), None)
        if not m:
            raise AtoneError(f"{path.name}: no template mapping matches it (mappings/workbooks/NAME.mapping.json, "
                             "\"match\": a glob)")
        probs = format_problems(POAM_MAPPING if m.get("kind") == "poam" else SSP_MAPPING, m)
        if probs:
            raise AtoneError(f"{m['_file']}: " + "; ".join(probs))
        wb = Workbook(path)
        styles = None
        if m.get("kind") == "poam":
            edits, changes, extra = plan_poam(d, wb, m)
            flags, styles = extra["flags"], extra["styles"]
        else:
            edits, changes, flags = plan_ssp(d, wb, m)
        dest = out / path.name
        skipped = write_cells(path, dest, edits, styles)
        report = {"workbook": path.name, "output": dest.name, "mapping": m["_file"], "changes": changes,
                  "flags": flags, "skipped_formulas": skipped, "at": time.time()}
        write_json(out / (path.stem + ".changes.json"), report)
        write_json(d / "runs" / f"fill-{path.stem}.changes.json", report)
        log(f"{path.name}: {len(changes)} changes, {len(flags)} flags" + (f", {len(skipped)} formula cells left alone"
                                                                        if skipped else "") + f" -> {dest}")
        reports.append(report)
    return reports


# ---- architecture: one graph of actual, allowed and documented paths; drawn as draw.io and SVG, with what differs

EDGE_CLASSES = {
    "normal": "configured (or documented, or allowed) and seen",
    "idle": "configured but not seen in the window: intended, just quiet (a DR link, a monthly job)",
    "unused": "allowed by a rule, but nothing configures it and nothing used it: attack surface (tighten the rule)",
    "undocumented": "configured or seen, but not in the SSP: the SSP is out of date, or something shouldn't be there",
    "unexpected": "seen, but no config, rule or document explains it",
    "blocked": "configured, but no rule we can see allows it: it would fail (or a rule we can't see)",
    "documented only": "in the SSP, but neither configured nor seen",
}


DEFAULT_PORTS = {"http": 80, "https": 443, "ldap": 389, "ldaps": 636, "smtp": 25, "smtps": 465, "ftp": 21, "sftp": 22,
                 "ssh": 22, "amqp": 5672, "amqps": 5671, "redis": 6379, "rediss": 6380, "mongodb": 27017,
                 "postgresql": 5432, "postgres": 5432, "mysql": 3306, "mariadb": 3306, "sqlserver": 1433, "oracle": 1521,
                 "t3": 7001, "t3s": 7002, "iiop": 7001, "kafka": 9092, "nfs": 2049, "syslog": 514}
HOST_RE = r"(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
NOT_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "example.com", "schemas.xmlsoap.org", "www.w3.org",
             "java.sun.com", "xmlns.oracle.com", "xmlns.jcp.org", "www.oracle.com", "apache.org", "www.apache.org"}


def extract_endpoints(text: str, patterns: list[dict] | None = None) -> dict:
    """What a config file says its program connects to, and listens on, with generic readers that know no product:
    URLs (and a scheme's usual port), JDBC and Oracle thin strings, Oracle TNS (HOST, PORT) pairs, host and port
    settings near each other, host:port values of host-ish settings, and listen directives; plus a system spec's own
    patterns (regexes with named groups host and port, reviewed by a person) for what these miss.
    {"connects": [{host, port, proto, how, line}], "listens": [{port, how, line}]}"""
    lines = text.splitlines()
    connects, listens, seen = [], [], set()

    def add(host, port, how, i, proto="tcp"):
        host = (host or "").strip("[]").strip().lower()
        if not host or host in NOT_HOSTS or host.startswith("127.") or "$" in host or "{" in host or "%" in host:
            return
        if not re.search(r"[a-z0-9]", host) or not str(port).isdigit() or not 0 < int(port) < 65536:
            return
        if (host, int(port)) in seen:
            return
        seen.add((host, int(port)))
        connects.append({"host": host, "port": int(port), "proto": proto, "how": how, "line": i + 1,
                         "quote": lines[i].strip()[:300] if i < len(lines) else ""})

    for i, line in enumerate(lines):
        if re.match(r"\s*(#|//|;|<!--)", line):                  # comments say what was, or could be
            continue
        for m in re.finditer(r"\b([a-z][a-z0-9+.-]*)://(?:[^@/\s\"'<>]+@)?" + HOST_RE + r"(?::(\d{1,5}))?", line, re.I):
            scheme = m.group(1).lower().split("+")[-1].split(":")[-1]
            port = m.group(3) or DEFAULT_PORTS.get(scheme)
            if port and not scheme.startswith("file"):
                add(m.group(2), port, f"a {scheme} URL", i)
        for m in re.finditer(r"jdbc:oracle:thin:[^@\s]*@(?://)?" + HOST_RE + r":(\d{1,5})", line, re.I):
            add(m.group(1), m.group(2), "an Oracle JDBC string", i)
        for m in re.finditer(r"\(\s*HOST\s*=\s*" + HOST_RE + r"\s*\)\s*\(\s*PORT\s*=\s*(\d{1,5})\s*\)", line, re.I):
            add(m.group(1), m.group(2), "an Oracle TNS address", i)
        m = re.search(r"(?i)\b[\w.-]*(host|server|address|hostname|endpoint|target)\b[\w.-]*\s*[=:]\s*[\"']?"
                      + HOST_RE + r":(\d{1,5})\b", line)
        if m:
            add(m.group(2), m.group(3), "a host:port setting", i)
        m = (re.match(r"(?i)\s*listen\s+(?:\S+:)?(\d{2,5})\b[^;]*;", line)          # listen 443 ssl;
             or re.match(r"(?i)\s*(?:Listen|ListenAddress|server\.port|http\.port|https\.port|port)\s*[=:\s]\s*"
                         r"(?:[\d.]+:|\[[0-9a-f:]+\]:)?(\d{2,5})\b\s*;?\s*$", line))
        if m:
            listens.append({"port": int(m.group(1)), "how": "a listen directive", "line": i + 1, "quote": line.strip()[:300]})
        for m in re.finditer(r"(?i)<((?:ssl-)?listen-port|port)>\s*(\d{2,5})\s*</", line):
            listens.append({"port": int(m.group(2)), "how": f"<{m.group(1)}>", "line": i + 1, "quote": line.strip()[:300]})
    hostish = re.compile(r"(?i)^\s*<?([\w.-]*(?:host|server|hostname|address)[\w.-]*)>?\s*[=:>]?\s*[\"']?" + HOST_RE
                         + r"[\"']?\s*(?:</[^>]+>)?\s*;?\s*$")
    portish = re.compile(r"(?i)^\s*<?([\w.-]*port)>?\s*[=:>]?\s*[\"']?(\d{2,5})[\"']?\s*(?:</[^>]+>)?\s*;?\s*$")
    for i, line in enumerate(lines):                           # a host setting with a port setting near it
        m = hostish.match(line)
        if not m or re.fullmatch(r"\d+", m.group(2)):
            continue
        stem = re.sub(r"(?i)(host|server|hostname|address).*$", "", m.group(1))
        for j in range(max(0, i - 3), min(len(lines), i + 4)):
            pm = portish.match(lines[j])
            if pm and re.sub(r"(?i)port.*$", "", pm.group(1)) == stem:
                add(m.group(2), pm.group(2), f"settings {m.group(1)} and {pm.group(1)}", i)
                break
    for pat in patterns or []:                                 # the system spec's own, reviewed by a person
        try:
            rx = re.compile(pat["pattern"], re.M)
        except (re.error, KeyError, TypeError):
            continue
        for m in rx.finditer(text):
            g = m.groupdict()
            i = text.count("\n", 0, m.start())
            if g.get("host") and g.get("port"):
                add(g["host"], g["port"], pat.get("about") or "the system spec's pattern", i, pat.get("proto", "tcp"))
            elif g.get("port") and pat.get("listens"):
                listens.append({"port": int(g["port"]), "how": pat.get("about") or "the spec's pattern", "line": i + 1,
                                "quote": lines[i].strip()[:300] if i < len(lines) else ""})
    return {"connects": connects, "listens": listens}


def configured_endpoints(d: Path, spec: dict) -> list[dict]:
    """For each config file in the current evidence: what it says its host connects to and listens on."""
    pats = {}
    for c in spec.get("components") or []:
        for f in c.get("files") or []:
            if f.get("connects"):
                pats.setdefault(f.get("path"), []).extend(f["connects"])
    out = []
    for e in current_index(d):
        if e["kind"] != "file":
            continue
        rec = load_record(d, e) or {}
        text = rec.get("content") or ""
        if NOT_READ.match(text.strip()):
            continue
        mine = [p for glob_, ps in pats.items() for p in ps if fnmatch.fnmatch(e["source"], os.path.expanduser(glob_ or ""))]
        found = extract_endpoints(text, mine)
        if found["connects"] or found["listens"]:
            out.append({"host": e["host"], "file": e["source"], "evidence": e["id"], **found})
    return out


def aws_model(items: list[tuple[str, str, object]]) -> dict:  # noqa: C901 (a pass over each kind of AWS evidence)
    """What the AWS evidence says, put together: security groups; the resources that use them (instances, RDS
    databases, load balancers), each with its addresses and whether the internet can reach it (a public address in a
    subnet routed to an internet gateway, an internet-facing load balancer, a publicly accessible database); which
    groups anything is attached to (network interfaces); and what each load balancer sends where. `items`: (evidence
    id, source, its JSON) for each piece of AWS evidence."""
    groups, resources, attached, targets = {}, [], set(), []
    subnets_public, main_public, explicit = set(), {}, set()
    lbs, tgs, enis, health, listeners = [], [], [], {}, {}
    for eid, src, data in items:
        if not isinstance(data, dict):
            continue
        e = {"id": eid}
        for sg in data.get("SecurityGroups") or []:
            if "IpPermissions" in sg:
                groups[sg["GroupId"]] = {**sg, "_evidence": e["id"]}
        enis += data.get("NetworkInterfaces") or []
        for rt in data.get("RouteTables") or []:
            public = any((r.get("GatewayId") or "").startswith("igw-") and r.get("DestinationCidrBlock") == "0.0.0.0/0"
                         for r in rt.get("Routes") or [])
            for a in rt.get("Associations") or []:
                if a.get("SubnetId"):
                    explicit.add(a["SubnetId"])
                    if public:
                        subnets_public.add(a["SubnetId"])
                if a.get("Main"):
                    main_public[rt.get("VpcId")] = public
        for res in data.get("Reservations") or []:
            for inst in res.get("Instances") or []:
                tags = {t.get("Key"): t.get("Value") for t in inst.get("Tags") or []}
                resources.append({"kind": "instance", "aws_id": inst.get("InstanceId"), "name": tags.get("Name"),
                                  "addresses": [x for x in (inst.get("PrivateIpAddress"),) if x],
                                  "public_ip": inst.get("PublicIpAddress"), "subnet": inst.get("SubnetId"),
                                  "vpc": inst.get("VpcId"), "names": [x for x in (inst.get("PrivateDnsName"),) if x],
                                  "sgs": [g.get("GroupId") for g in inst.get("SecurityGroups") or []], "evidence": e["id"]})
        for db in data.get("DBInstances") or []:
            ep = db.get("Endpoint") or {}
            resources.append({"kind": "database", "aws_id": db.get("DBInstanceIdentifier"),
                              "name": db.get("DBInstanceIdentifier"), "addresses": [], "names": [x for x in (ep.get("Address"),) if x],
                              "port": ep.get("Port"), "public": bool(db.get("PubliclyAccessible")),
                              "sgs": [g.get("VpcSecurityGroupId") for g in db.get("VpcSecurityGroups") or []],
                              "evidence": e["id"]})
        lbs += [{**lb, "_evidence": e["id"]} for lb in data.get("LoadBalancers") or []]
        tgs += data.get("TargetGroups") or []
        if src.startswith("elbv2 describe-target-health"):
            health[src.split("(", 1)[-1].split(")")[0]] = data.get("TargetHealthDescriptions") or []
        if src.startswith("elbv2 describe-listeners"):
            listeners[src.split("(", 1)[-1].split(")")[0]] = data.get("Listeners") or []
    for lb in lbs:
        resources.append({"kind": "load balancer", "aws_id": lb.get("LoadBalancerArn"), "name": lb.get("LoadBalancerName"),
                          "addresses": [], "names": [x for x in (lb.get("DNSName"),) if x],
                          "public": lb.get("Scheme") == "internet-facing", "sgs": lb.get("SecurityGroups") or [],
                          "listens": [{"port": l.get("Port"), "protocol": l.get("Protocol")}
                                      for l in listeners.get(lb.get("LoadBalancerName"), [])], "evidence": lb["_evidence"]})
    for eni in enis:                                     # who uses which groups; and the addresses of RDS and LBs
        gids = [g.get("GroupId") for g in eni.get("Groups") or []]
        attached.update(gids)
        ip, desc = eni.get("PrivateIpAddress"), eni.get("Description") or ""
        if not ip:
            continue
        m = re.match(r"ELB (?:app|net)/([^/]+)/", desc)
        for r in resources:
            if (m and r["kind"] == "load balancer" and r["name"] == m.group(1)) or \
                    (r["kind"] == "database" and "RDS" in desc and set(gids) == set(r["sgs"])):
                if ip not in r["addresses"]:
                    r["addresses"].append(ip)
    for r in resources:
        attached.update(r["sgs"])
        if r["kind"] == "instance":                    # a subnet with no route table of its own uses the VPC's main one
            routed = r.get("subnet") in subnets_public or (r.get("subnet") not in explicit and main_public.get(r.get("vpc")))
            r["public"] = bool(r.get("public_ip")) and bool(routed)
    by_aws_id = {r["aws_id"]: r for r in resources}
    for tg in tgs:
        hs = health.get(tg.get("TargetGroupName"), [])
        for lb_arn in tg.get("LoadBalancerArns") or []:
            lb = by_aws_id.get(lb_arn)
            for h in hs:
                t = h.get("Target") or {}
                target = by_aws_id.get(t.get("Id")) or next((r for r in resources if t.get("Id") in r["addresses"]), None)
                targets.append({"lb": lb, "target": target, "target_id": t.get("Id"), "port": t.get("Port") or tg.get("Port"),
                                "protocol": (tg.get("Protocol") or "TCP").lower(), "group": tg.get("TargetGroupName"),
                                "health": (h.get("TargetHealth") or {}).get("State")})
    return {"groups": groups, "resources": resources, "attached": attached, "targets": targets,
            "public_subnets": sorted(subnets_public)}


ADMIN_PORTS = {22: "SSH", 3389: "RDP", 23: "telnet", 21: "FTP", 1521: "Oracle", 1433: "SQL Server", 3306: "MySQL",
               5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 5601: "Kibana",
               445: "SMB", 135: "RPC", 5985: "WinRM", 5986: "WinRM"}


def review_security_groups(model: dict, open_ports=(80, 443)) -> list[dict]:
    """What's wrong with the account's security groups, as findings: rules open to the whole internet (all traffic,
    or a port beyond `open_ports`; admin and database ports named), groups attached to nothing, rules that name a
    group that doesn't exist, and a default group that still allows anything. Each says whether what it opens can
    actually be reached from the internet now (a public address, an internet-facing load balancer)."""
    out = []
    users = {}
    for r in model["resources"]:
        for g in r["sgs"]:
            users.setdefault(g, []).append(r)
    for gid, sg in sorted(model["groups"].items()):
        name = sg.get("GroupName") or gid
        who = users.get(gid, [])
        reach = any(r.get("public") for r in who)

        def finding(sev, what, rule=""):
            out.append({"group": gid, "name": name, "severity": sev, "what": what, "rule": rule,
                        "used_by": [r.get("name") or r["aws_id"] for r in who], "reachable": reach,
                        "evidence": sg.get("_evidence")})
        for perm in sg.get("IpPermissions") or []:
            proto, lo, hi = perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort")
            world = [x.get("CidrIp") for x in perm.get("IpRanges") or [] if x.get("CidrIp") == "0.0.0.0/0"] + \
                [x.get("CidrIpv6") for x in perm.get("Ipv6Ranges") or [] if x.get("CidrIpv6") == "::/0"]
            rule = f"{_port_text(proto, lo, hi)} from {', '.join(world)}" if world else ""
            if world:
                if proto == "-1":
                    finding("high", "allows all traffic from anywhere", rule)
                else:
                    named = sorted({ADMIN_PORTS[p] for p in ADMIN_PORTS if lo is not None and lo <= p <= (hi or lo)})
                    if named:
                        finding("high", f"opens {', '.join(named)} to the whole internet", rule)
                    elif not (lo == hi and lo in open_ports):
                        finding("moderate", "opens a port to the whole internet that isn't one meant to be public "
                                            f"({', '.join(map(str, open_ports))})", rule)
            for pair in perm.get("UserIdGroupPairs") or []:
                if pair.get("GroupId") and pair["GroupId"] not in model["groups"] and not pair.get("UserId", "").startswith("amazon"):
                    finding("low", f"a rule names {pair['GroupId']}, which isn't in this account's groups (deleted, or "
                                   "another account's)", f"{_port_text(proto, lo, hi)} from {pair['GroupId']}")
        if name == "default" and (sg.get("IpPermissions") or [p for p in sg.get("IpPermissionsEgress") or []]):
            finding("moderate", "the VPC's default group allows traffic: it should allow none (anything launched without "
                                "a group gets it)")
        if gid not in model["attached"] and name != "default":
            finding("low", "attached to nothing: remove it, or say what it's for")
    return out


def _json_content(d: Path, e: dict):
    rec = load_record(d, e) or {}
    try:
        return json.loads(rec.get("content") or "null")
    except json.JSONDecodeError:
        return None


def _port_text(proto: str, lo, hi) -> str:
    if proto in ("-1", "all", None) or lo in (None, -1):
        return "all"
    return f"{proto}/{lo}" if lo == hi else f"{proto}/{lo}-{hi}"


def _port_in(port_text: str, proto: str, port: int) -> bool:
    if port_text == "all":
        return True
    p, _, rng = port_text.partition("/")
    lo, _, hi = rng.partition("-")
    return p == proto and int(lo) <= port <= int(hi or lo)


def build_graph(name: str) -> dict:
    """Nodes (hosts, and what's outside: the internet, address ranges, peers) and edges, each edge with the layers it
    appears in (actual, allowed, documented) and its class (EDGE_CLASSES). Inside the boundary: the spec's hosts and
    every host evidence was collected from."""
    import ipaddress
    d = system_dir(name)
    spec = read_json(d / "system.json", {})
    documented = read_json(d / "interfaces.json", []) or []
    index = current_index(d)
    nodes, addr, comp_of = {}, {}, {}

    def node(nid, label=None, kind="host", inside=None, component=None):
        n = nodes.setdefault(nid, {"id": nid, "label": label or nid, "kind": kind, "inside": bool(inside),
                                   "component": component, "addresses": []})
        if inside:
            n["inside"] = True
        if component and not n["component"]:
            n["component"] = component
        return n

    for c in spec.get("components") or []:
        for h in c.get("hosts") or []:
            comp_of.setdefault(h, c.get("name"))
    for h in spec.get("hosts") or []:
        hn = h if isinstance(h, str) else h.get("name")
        n = node(hn, inside=True, component=comp_of.get(hn))
        for a in ([] if isinstance(h, str) else h.get("addresses") or []):
            addr[a] = hn
            n["addresses"].append(a)
    listening = {}                                        # host -> {(proto, port)}
    for e in index:
        if e["kind"] == "listeners":
            node(e["host"], inside=True, component=comp_of.get(e["host"]))
            for r in _json_content(d, e) or []:
                ip, _, port = r["local"].rpartition(":")
                listening.setdefault(e["host"], set()).add((r["proto"], int(port)))
                if ip not in ("0.0.0.0", "::", "127.0.0.1", "::1") and not ip.startswith("127."):
                    addr.setdefault(ip, e["host"])
                    if ip not in nodes[e["host"]]["addresses"]:
                        nodes[e["host"]]["addresses"].append(ip)
    model = aws_model([(e["id"], e["source"], _json_content(d, e)) for e in index if e["kind"] == "aws"])
    groups = model["groups"]
    instances = []                                        # (node, [sg ids]) for everything with security groups
    for r in model["resources"]:
        ip = next(iter(r["addresses"]), None)
        hn = addr.get(ip) if ip else None
        hn = hn or (r["name"] if r["kind"] == "instance" and r["name"] else None) or r["name"] or r["aws_id"]
        n = node(hn, label=hn + ("" if r["kind"] == "instance" else f" ({r['kind']})"), inside=True,
                 component=comp_of.get(hn))
        n["aws"] = {"kind": r["kind"], "id": r["aws_id"], "public": bool(r.get("public"))}
        for a_ in r["addresses"]:
            addr.setdefault(a_, hn)
            if a_ not in n["addresses"]:
                n["addresses"].append(a_)
        for nm in r.get("names") or []:
            n.setdefault("names", []).append(nm)
        if r.get("listens"):
            n["configured_listens"] = sorted({l["port"] for l in r["listens"] if l.get("port")})
        r["node"] = hn
        instances.append((hn, r["sgs"]))
    members = {}
    for hn, sgs in instances:
        for g in sgs:
            members.setdefault(g, []).append(hn)
    edges = {}

    def edge(src, dst, port, layer, **extra):
        e = edges.setdefault((src, dst, port), {"from": src, "to": dst, "port": port, "layers": [], "evidence": [],
                                                "seen": 0})
        if layer not in e["layers"]:
            e["layers"].append(layer)
        if layer == "actual":
            e["seen"] += 1                                # in how many snapshots
        for k, v in extra.items():
            if k == "evidence":
                if v not in e["evidence"]:
                    e["evidence"].append(v)
            else:
                e.setdefault(k, v)

    def peer(ip: str) -> str:
        if ip in addr:
            return addr[ip]
        try:
            private = ipaddress.ip_address(ip).is_private
        except ValueError:
            private = False
        return node(ip, label=ip, kind="peer" if private else "internet-peer", inside=False)["id"]

    # allowed: the security groups' rules, in (ingress) and out (egress), for everything that has them
    egress_all = set()                                   # nodes whose groups let anything out (or don't say)
    egress = []                                          # (node, destination cidr or group, port text)

    def cidr_node(cidr):
        src = "internet" if cidr in ("0.0.0.0/0", "::/0") else cidr
        node(src, label="the internet" if src == "internet" else cidr,
             kind="internet" if src == "internet" else "range", inside=False)
        return src
    for hn, sgs in instances:
        public = (nodes[hn].get("aws") or {}).get("public")
        if not any("IpPermissionsEgress" in (groups.get(g) or {}) for g in sgs):
            egress_all.add(hn)                           # no egress rules in the evidence: not known to block anything
        for g in sgs:
            sg = groups.get(g) or {}
            why = f"{g} ({sg.get('GroupName', '')})"
            for perm in sg.get("IpPermissions") or []:
                port = _port_text(perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort"))
                for cidr in [r.get("CidrIp") for r in perm.get("IpRanges") or []] + \
                        [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges") or []]:
                    if not cidr:
                        continue
                    src = cidr_node(cidr)
                    edge(src, hn, port, "allowed", rule=why,
                         **({"reachable": bool(public)} if src == "internet" else {}))
                for pl in perm.get("PrefixListIds") or []:
                    src = node(pl.get("PrefixListId"), label=f"prefix list {pl.get('PrefixListId')}", kind="range")["id"]
                    edge(src, hn, port, "allowed", rule=why)
                for pair in perm.get("UserIdGroupPairs") or []:
                    for src in members.get(pair.get("GroupId"), []):
                        if src != hn:
                            edge(src, hn, port, "allowed", rule=f"{g} from {pair.get('GroupId')}")
            for perm in sg.get("IpPermissionsEgress") or []:
                port = _port_text(perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort"))
                dests = [r.get("CidrIp") for r in perm.get("IpRanges") or []] + \
                    [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges") or []]
                if port == "all" and any(x in ("0.0.0.0/0", "::/0") for x in dests):
                    egress_all.add(hn)
                    continue
                egress += [(hn, x, port) for x in dests if x] + \
                    [(hn, pair.get("GroupId"), port) for pair in perm.get("UserIdGroupPairs") or []]
    for hn in egress_all:
        nodes[hn]["egress"] = "anything"
    # load balancers: their listeners (an internet-facing one's are the intended way in) and their targets
    for r in model["resources"]:
        if r["kind"] == "load balancer":
            for l in r.get("listens") or []:
                if r.get("public") and l.get("port"):
                    cidr_node("0.0.0.0/0")
                    edge("internet", r["node"], f"tcp/{l['port']}", "configured", evidence=r["evidence"],
                         config={"file": f"load balancer {r['name']}", "line": 0, "quote": f"listener {l.get('protocol')} "
                                 f"{l['port']} (internet-facing)", "how": "an internet-facing load balancer's listener"})
    for t in model["targets"]:
        if t["lb"] and (t["target"] or t["target_id"]):
            dst = t["target"]["node"] if t["target"] else peer(t["target_id"])
            edge(t["lb"]["node"], dst, f"{'tcp' if t['protocol'] in ('http', 'https', 'tcp', 'tls') else t['protocol']}/{t['port']}",
                 "configured", evidence=t["lb"]["evidence"],
                 config={"file": f"target group {t['group']}", "line": 0, "quote": f"target {t['target_id']} port "
                         f"{t['port']} ({t['health'] or '?'})", "how": "a load balancer's target group"})
    # actual: the connections seen on each host (a set that grows in the codex). Where this machine has seen
    # collects, one last seen longer ago than fresh_days doesn't count as seen now (a fresh clone can't tell, so
    # everything in the codex counts)
    days = float(read_json(d / "atone.json", {}).get("fresh_days") or 30)
    conn_seen = read_json(d / "runs" / "connections-seen.json", {}) or {}
    for e in index:
        if e["kind"] != "flows":
            continue
        for r in _json_content(d, e) or []:
            if not isinstance(r, dict) or "direction" not in r:
                continue
            last = conn_seen.get(json.dumps([e["host"], r.get("proto"), r.get("direction"), r.get("local"),
                                             r.get("remote"), r.get("process")]))
            if last and time.time() - last > days * 86400:
                continue
            proto = r.get("proto", "tcp")
            if r["direction"] == "in":
                port = r["local"].rpartition(":")[2]
                edge(peer(r["remote"]), e["host"], f"{proto}/{port}", "actual", process=r.get("process"),
                     evidence=e["id"], first_seen=r.get("first_seen"))
            else:
                rip, _, rport = r["remote"].rpartition(":")
                edge(e["host"], peer(rip), f"{proto}/{rport}", "actual", process=r.get("process"), evidence=e["id"],
                     first_seen=r.get("first_seen"))
    # configured: what the hosts' config files say they connect to (and listen on): the intentional connections
    by_name = {}
    for nid, n in list(nodes.items()):
        if n["kind"] == "host":
            by_name[nid.lower()] = nid
            by_name.setdefault(nid.lower().split(".")[0], nid)
    for h in spec.get("hosts") or []:
        if isinstance(h, dict):
            for alias in h.get("names") or []:
                by_name[alias.lower()] = h.get("name")
    for nid, n in nodes.items():                         # AWS names: an RDS endpoint, a load balancer's DNS name
        for alias in n.get("names") or []:
            by_name[alias.lower()] = nid

    def resolve(target: str) -> str:
        t = target.lower()
        if t in addr:
            return addr[t]
        if t in by_name:
            return by_name[t]
        if t.split(".")[0] in by_name and not re.fullmatch(r"[\d.]+", t):
            return by_name[t.split(".")[0]]
        if re.fullmatch(r"[\d.]+|[0-9a-f:]+", t):
            return peer(t)
        return node(t, label=t, kind="peer", inside=False)["id"]
    configured = configured_endpoints(d, spec)
    for f in configured:
        src = f["host"]
        node(src, inside=True, component=comp_of.get(src))
        for c in f["connects"]:
            dst = resolve(c["host"])
            if dst == src:
                continue
            edge(src, dst, f"{c['proto']}/{c['port']}", "configured", evidence=f["evidence"],
                 config={"file": f["file"], "line": c["line"], "quote": c["quote"], "how": c["how"]})
        for l in f["listens"]:
            nodes[src].setdefault("configured_listens", [])
            if l["port"] not in nodes[src]["configured_listens"]:
                nodes[src]["configured_listens"].append(l["port"])
    # documented: the flows the SSP describes (interfaces.json, reviewed by a person)
    hosts_of = {c.get("name"): c.get("hosts") or [] for c in spec.get("components") or []}
    for f in documented:                                # a component stands for each of its hosts
        for src in hosts_of.get(f.get("from")) or [f.get("from")]:
            for dst in hosts_of.get(f.get("to")) or [f.get("to")]:
                for n in (src, dst):
                    if n not in nodes:
                        node(n, label="the internet" if n == "internet" else n,
                             kind="internet" if n == "internet" else "host", inside=n in comp_of)
                edge(src, dst, f.get("port") or "all", "documented", data=f.get("data"), about=f.get("about"))
    # classify: an actual edge matches allowed/documented ones whose port covers it and whose source covers its source
    allowed = [e for e in edges.values() if "allowed" in e["layers"]]

    def covered(e, among):
        proto, _, p = e["port"].partition("/")
        for a in among:
            if a["to"] != e["to"] or not (a["port"] == "all" or (p.isdigit() and _port_in(a["port"], proto, int(p)))):
                continue
            if a["from"] == e["from"] or a["from"] == "internet":
                return True
            try:
                if any(ipaddress.ip_address(x) in ipaddress.ip_network(a["from"], strict=False)
                       for x in ([e["from"]] if nodes[e["from"]]["kind"] != "host" else nodes[e["from"]]["addresses"])):
                    return True
            except ValueError:
                pass
        return False

    def egress_allows(e, specific=False) -> bool:
        """Whether the source's security groups let this connection out (`specific`: by a rule that names it, not a
        blanket allow-all, which says nothing about intent)."""
        if e["from"] in egress_all:
            return not specific
        proto, _, p = e["port"].partition("/")
        if not p.isdigit():
            return False
        dst_ips = [e["to"]] if nodes[e["to"]]["kind"] != "host" else nodes[e["to"]]["addresses"]
        try:
            [ipaddress.ip_address(x) for x in dst_ips]
        except ValueError:
            dst_ips = []
        if not dst_ips and not nodes[e["to"]].get("aws"):
            return not specific                          # a destination known only by name: can't tell, so not blocked
        for src, dest, port in egress:
            if src != e["from"] or not (port == "all" or _port_in(port, proto, int(p))):
                continue
            if dest in members and e["to"] in members[dest]:
                return True
            try:
                if any(ipaddress.ip_address(x) in ipaddress.ip_network(dest, strict=False) for x in dst_ips):
                    return True
            except ValueError:
                pass
        return False

    docs = [e for e in edges.values() if "documented" in e["layers"]]
    confs = [e for e in edges.values() if "configured" in e["layers"]]
    seen_edges = [e for e in edges.values() if "actual" in e["layers"]]
    for e in edges.values():
        L = e["layers"]
        seen = "actual" in L
        conf = "configured" in L or (seen and covered(e, confs))
        doc = "documented" in L or covered(e, docs)
        # allowed: in through the destination's groups (if it has any) and out through the source's (if it has any)
        inbound_ok = "allowed" in L or covered(e, allowed) or not nodes[e["to"]].get("aws")
        outbound_ok = egress_allows(e) or not nodes[e["from"]].get("aws")
        has_aws_end = bool(nodes[e["to"]].get("aws") or nodes[e["from"]].get("aws"))
        allowed_rule = bool(groups) and has_aws_end and inbound_ok and outbound_ok
        # explained by a rule: a rule that names this path (into an AWS destination; or out by a specific egress rule)
        by_rule = ("allowed" in L or covered(e, allowed)) if nodes[e["to"]].get("aws") else egress_allows(e, True)
        e.update(configured=conf, documented=doc, allowed_by_rule=allowed_rule, explained_by_rule=by_rule)
        if seen or "configured" in L:                # the most urgent first
            to_inside, from_outside = nodes[e["to"]]["inside"], not nodes[e["from"]]["inside"]
            if seen and not (conf or by_rule or doc):
                e["class"] = "unexpected"                # nothing explains it
            elif "configured" in L and groups and not allowed_rule and not seen and \
                    (nodes[e["to"]].get("aws") or nodes[e["from"]].get("aws")):
                e["class"] = "blocked"                   # it would fail
            elif seen and groups and not allowed_rule and (to_inside and from_outside or nodes[e["from"]].get("aws")):
                e["class"] = "unexpected"
            elif documented and not doc:
                e["class"] = "undocumented"
            else:
                e["class"] = "normal" if seen else "idle"
        elif "allowed" in L:
            used = any(x["to"] == e["to"] and covered(x, [e]) for x in seen_edges)
            wanted = any(x["to"] == e["to"] and covered(x, [e]) for x in confs)
            e["class"] = "normal" if used else "idle" if wanted else "unused"
        else:
            e["class"] = "documented only"
    out = {"system": name, "at": time.time(), "nodes": list(nodes.values()),
           "security_groups": review_security_groups(model, tuple(((spec.get("aws") or {}).get("public_ports")
                                                                   or [80, 443]))),
           "edges": sorted(edges.values(), key=lambda e: (e["from"], e["to"], e["port"])),
           "counts": {k: sum(1 for e in edges.values() if e["class"] == k) for k in EDGE_CLASSES},
           "crossing": [f"{e['from']} -> {e['to']} {e['port']}" for e in edges.values()
                        if nodes[e["from"]]["inside"] != nodes[e["to"]]["inside"]]}
    return out


def layout(graph: dict) -> dict[str, tuple[int, int]]:
    """Positions by tier: outside first, then each component in order of its distance from outside, hosts stacked."""
    nodes = {n["id"]: n for n in graph["nodes"]}
    # tiers follow the paths that are intended or used (never an allowed-only rule), by the longest way in from
    # outside, so a load balancer stands before what it sends to
    flow = [e for e in graph["edges"] if e.get("class") != "unused" and nodes[e["to"]]["inside"]]
    depth = {nid: 0 for nid, n in nodes.items() if not n["inside"]}
    for _ in range(len(nodes)):
        changed = False
        for e in flow:
            if e["from"] in depth and depth[e["from"]] + 1 > depth.get(e["to"], 0) and depth[e["from"]] < len(nodes):
                depth[e["to"]] = depth[e["from"]] + 1
                changed = True
        if not changed:
            break
    for nid, n in nodes.items():
        depth.setdefault(nid, 1)
    comp_depth = {}
    for nid, n in nodes.items():
        if n["inside"]:
            comp = n["component"] or nid
            comp_depth[comp] = max(comp_depth.get(comp, 0), depth[nid])
    last = max(comp_depth.values() or [1]) + 1
    sources = {e["from"] for e in graph["edges"]}
    cols: dict[int, list] = {}
    for nid, n in nodes.items():                     # outside: what reaches in on the left, what's reached out to on the right
        col = (0 if nid in sources else last) if not n["inside"] else comp_depth.get(n["component"] or nid, depth[nid]) or 1
        cols.setdefault(col, []).append(nid)
    pos = {}
    for col, ids in sorted(cols.items()):
        for i, nid in enumerate(sorted(ids, key=lambda x: (nodes[x]["component"] or "", x))):
            pos[nid] = (60 + col * 260, 80 + i * 110)
    return pos


EDGE_STYLE = {"normal": ("#333333", ""), "idle": ("#2ca02c", "dashed=1;dashPattern=8 3 2 3;"),
              "unused": ("#888888", "dashed=1;"), "undocumented": ("#d62728", "strokeWidth=2;"),
              "unexpected": ("#ff7f0e", "strokeWidth=2;"), "blocked": ("#9467bd", "dashed=1;strokeWidth=2;"),
              "documented only": ("#1f77b4", "dashed=1;dashPattern=1 4;")}


def edge_ends(pos: dict, e: dict, k: int, n: int) -> tuple[float, float, float, float]:
    """Where an edge leaves and arrives: the sides facing each other, parallel edges (same two ends) spread apart."""
    (x1, y1), (x2, y2) = pos[e["from"]], pos[e["to"]]
    off = (k - (n - 1) / 2) * 16
    if x2 > x1:
        return x1 + 180, y1 + 35 + off, x2, y2 + 35 + off
    if x2 < x1:
        return x1, y1 + 35 + off, x2 + 180, y2 + 35 + off
    return x1 + 90 + off, (y1 + 70 if y2 > y1 else y1), x2 + 90 + off, (y2 if y2 > y1 else y2 + 70)


def detours(graph: dict, pos: dict) -> dict[int, list[tuple[float, float]]]:
    """Waypoints for each edge whose straight line would cross a box: out of its source's side into the gap beside
    it, down to a lane of its own below every box, along to the gap beside its target, and in from the side. Lanes
    never shared, so no two detours run along each other."""
    out, bottom = {}, max([y for _, y in pos.values()] or [0]) + 70
    lane = 0
    for i, e in enumerate(graph["edges"]):
        (x1, y1), (x2, y2) = pos[e["from"]], pos[e["to"]]
        lo, hi = sorted((x1, x2))
        crossed = [nid for nid, (x, y) in pos.items() if nid not in (e["from"], e["to"])
                   and ((lo < x < hi) or (x == x2 and min(y1, y2) < y < max(y1, y2)))]
        if (abs(x2 - x1) <= 260 and not crossed) or (x1 == x2 and not crossed) or not crossed:
            continue
        lane += 1
        ly, g = bottom + 30 + lane * 16, 8 + 7 * (lane % 7)       # its own lane, and its own run up each gap
        if x2 >= x1:
            out[i] = [(x1 + 180, y1 + 35), (x1 + 180 + g, y1 + 35), (x1 + 180 + g, ly), (x2 - g, ly), (x2 - g, y2 + 35),
                      (x2, y2 + 35)]
        else:
            out[i] = [(x1, y1 + 35), (x1 - g, y1 + 35), (x1 - g, ly), (x2 + 180 + g, ly), (x2 + 180 + g, y2 + 35),
                      (x2 + 180, y2 + 35)]
    return out


def parallel(edges: list[dict]) -> list[tuple[int, int]]:
    """(index among edges with the same two ends, how many there are) for each edge."""
    groups: dict[tuple, list] = {}
    for i, e in enumerate(edges):
        groups.setdefault(tuple(sorted((e["from"], e["to"]))), []).append(i)
    out = [(0, 1)] * len(edges)
    for ids in groups.values():
        for k, i in enumerate(ids):
            out[i] = (k, len(ids))
    return out


def _x(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def drawio(graph: dict, title: str) -> str:
    """The graph as a draw.io file: the authorization boundary as a container, hosts inside it by tier, what's outside
    to its left, each path styled by its class (legend included). Editable: it's the engineers' to move about."""
    pos = layout(graph)
    nodes = {n["id"]: n for n in graph["nodes"]}
    cells, ids = [], {}
    inside = [n for n in graph["nodes"] if n["inside"]]
    if inside:
        xs = [pos[n["id"]][0] for n in inside]
        ys = [pos[n["id"]][1] for n in inside]
        bx, by = min(xs) - 40, min(ys) - 50
        cells.append(f'<mxCell id="boundary" value="{_x(title)}: authorization boundary" style="rounded=1;dashed=1;'
                     f'fillColor=none;strokeColor=#2ca02c;strokeWidth=2;verticalAlign=top;align=left;spacingLeft=8;" '
                     f'vertex="1" parent="1"><mxGeometry x="{bx}" y="{by}" width="{max(xs) - bx + 220}" '
                     f'height="{max(ys) - by + 110}" as="geometry"/></mxCell>')
    for i, (nid, n) in enumerate(nodes.items()):
        ids[nid] = f"n{i}"
        x, y = pos[nid]
        label = n["label"] + (f"<br><i>{_x(n['component'])}</i>" if n["component"] else "") + (
            "<br>" + _x(", ".join(n["addresses"][:3])) if n["addresses"] else "")
        style = ("ellipse;fillColor=#fdecea;strokeColor=#d62728;" if n["kind"] in ("internet", "internet-peer") else
                 "rounded=1;fillColor=#f5f5f5;strokeColor=#666666;" if not n["inside"] else
                 "rounded=1;fillColor=#dae8fc;strokeColor=#6c8ebf;")
        cells.append(f'<mxCell id="{ids[nid]}" value="{_x(label)}" style="{style}whiteSpace=wrap;html=1;" vertex="1" '
                     f'parent="1"><mxGeometry x="{x}" y="{y}" width="180" height="70" as="geometry"/></mxCell>')
    routes = detours(graph, pos)
    for i, (e, (k, n)) in enumerate(zip(graph["edges"], parallel(graph["edges"]))):
        color, extra = EDGE_STYLE[e["class"]]
        y = round(0.5 + (k - (n - 1) / 2) * 0.25, 2)            # parallel edges leave and arrive apart
        sides = (f"exitX=1;exitY={y};entryX=0;entryY={y};" if pos[e["to"]][0] > pos[e["from"]][0] else
                 f"exitX=0;exitY={y};entryX=1;entryY={y};" if pos[e["to"]][0] < pos[e["from"]][0] else "")
        way = routes.get(i, [])[1:-1]
        points = ('<Array as="points">' + "".join(f'<mxPoint x="{x}" y="{y}"/>' for x, y in way) + "</Array>") if way else ""
        if way:
            right = pos[e["to"]][0] >= pos[e["from"]][0]
            sides = f"exitX={1 if right else 0};exitY=0.5;entryX={0 if right else 1};entryY=0.5;"
        cells.append(f'<mxCell id="e{i}" value="{_x(e["port"] + (" (not reachable)" if e.get("reachable") is False else ""))}" style="endArrow=block;html=1;strokeColor={color};'
                     f'fontColor={color};labelBackgroundColor=#ffffff;{sides}{extra}" edge="1" parent="1" '
                     f'source="{ids[e["from"]]}" target="{ids[e["to"]]}"><mxGeometry relative="1" as="geometry">'
                     f'{points}</mxGeometry></mxCell>')
    ly = 80 + max([p[1] for p in pos.values()] or [0]) + 200 + 16 * len(routes)
    for i, (cls, about) in enumerate(EDGE_CLASSES.items()):
        color, extra = EDGE_STYLE[cls]
        y = ly + i * 30
        cells.append(f'<mxCell id="l{i}" value="" style="endArrow=block;html=1;strokeColor={color};{extra}" edge="1" '
                     f'parent="1"><mxGeometry relative="1" as="geometry"><mxPoint x="60" y="{y}" as="sourcePoint"/>'
                     f'<mxPoint x="120" y="{y}" as="targetPoint"/></mxGeometry></mxCell>')
        cells.append(f'<mxCell id="lt{i}" value="{_x(cls)}: {_x(about)}" style="text;html=1;align=left;" vertex="1" '
                     f'parent="1"><mxGeometry x="130" y="{y - 12}" width="700" height="24" as="geometry"/></mxCell>')
    return ('<mxfile host="atone" agent="atone ' + __version__ + '"><diagram name="' + _x(title) + '" id="network">'
            '<mxGraphModel grid="1" gridSize="10"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
            + "".join(cells) + "</root></mxGraphModel></diagram></mxfile>\n")


def svg(graph: dict, title: str) -> str:
    """The same picture as an SVG, to look at anywhere (the report shows it)."""
    pos = layout(graph)
    nodes = {n["id"]: n for n in graph["nodes"]}
    w = max([p[0] for p in pos.values()] or [0]) + 260
    lanes = len(detours(graph, pos))
    h = max([p[1] for p in pos.values()] or [0]) + 200 + 16 * lanes + 30 * len(EDGE_CLASSES) + 40
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
           f'style="max-width:100%;height:auto" font-family="sans-serif" font-size="12">',
           '<defs>' + "".join(f'<marker id="a{i}" markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto">'
                              f'<path d="M0,0 L10,4 L0,8 z" fill="{EDGE_STYLE[c][0]}"/></marker>'
                              for i, c in enumerate(EDGE_CLASSES)) + '</defs>',
           f'<text x="20" y="30" font-size="16" font-weight="bold">{_x(title)}</text>']
    cls_i = {c: i for i, c in enumerate(EDGE_CLASSES)}
    inside = [pos[n["id"]] for n in graph["nodes"] if n["inside"]]
    if inside:
        bx, by = min(p[0] for p in inside) - 30, min(p[1] for p in inside) - 30
        out.append(f'<rect x="{bx}" y="{by}" width="{max(p[0] for p in inside) - bx + 210}" height="'
                   f'{max(p[1] for p in inside) - by + 100}" rx="12" fill="none" stroke="#2ca02c" stroke-width="2" '
                   f'stroke-dasharray="8 4"/>')
    routes = detours(graph, pos)
    for i, (e, (k, n)) in enumerate(zip(graph["edges"], parallel(graph["edges"]))):
        if i in routes:                           # out of the side, along its own lane below, in from the side
            pts = routes[i]
        else:
            x1, y1, x2, y2 = edge_ends(pos, e, k, n)
            pts = [(x1, y1), (x2, y2)]
        color, extra = EDGE_STYLE[e["class"]]
        dash = ' stroke-dasharray="6 4"' if "dashed" in extra else ""
        out.append(f'<polyline points="{" ".join(f"{x},{y}" for x, y in pts)}" fill="none" stroke="{color}" '
                   f'stroke-width="1.5"{dash} marker-end="url(#a{cls_i[e["class"]]})"/>')
        mx, my = ((pts[2][0] + pts[3][0]) / 2, pts[2][1]) if len(pts) > 2 else ((pts[0][0] + pts[1][0]) / 2,
                                                                               (pts[0][1] + pts[1][1]) / 2)
        out.append(f'<text x="{mx}" y="{my - 4}" fill="{color}" text-anchor="middle" '
                   f'paint-order="stroke" stroke="#ffffff" stroke-width="3">{_x(e["port"])}</text>')
    for nid, n in nodes.items():
        x, y = pos[nid]
        fill, stroke = (("#fdecea", "#d62728") if n["kind"] in ("internet", "internet-peer") else
                        ("#f5f5f5", "#666666") if not n["inside"] else ("#dae8fc", "#6c8ebf"))
        out.append(f'<rect x="{x}" y="{y}" width="180" height="70" rx="8" fill="{fill}" stroke="{stroke}"/>')
        lines = [n["label"]] + ([n["component"]] if n["component"] else []) + ([", ".join(n["addresses"][:2])]
                                                                             if n["addresses"] else [])
        for j, line in enumerate(lines[:3]):
            out.append(f'<text x="{x + 90}" y="{y + 22 + j * 16}" text-anchor="middle"'
                       f'{" font-style=" + chr(34) + "italic" + chr(34) if j == 1 and n["component"] else ""}>'
                       f'{_x(clip_text(line, 28))}</text>')
    ly = max([p[1] for p in pos.values()] or [0]) + 200 + 16 * lanes
    for i, (c, about) in enumerate(EDGE_CLASSES.items()):
        color, extra = EDGE_STYLE[c]
        dash = ' stroke-dasharray="6 4"' if "dashed" in extra else ""
        out.append(f'<line x1="20" y1="{ly + i * 30}" x2="70" y2="{ly + i * 30}" stroke="{color}" stroke-width="1.5"{dash}/>'
                   f'<text x="80" y="{ly + i * 30 + 4}">{_x(c)}: {_x(about)}</text>')
    out.append("</svg>\n")
    return "\n".join(out)


def draw_system(name: str, out: Path, log=print) -> dict:
    """The architecture: graph.json, network.drawio and network.svg in `out`, and what changed since the last
    drawing (paths added, gone, or changed class) in graph.changes.json."""
    d = system_dir(name)
    g = build_graph(name)
    out.mkdir(parents=True, exist_ok=True)
    prev = read_json(d / "runs" / "graph-latest.json", None)
    key = lambda e: f"{e['from']} -> {e['to']} {e['port']}"
    changes = {}
    if prev:
        old = {key(e): e["class"] for e in prev.get("edges") or []}
        new = {key(e): e["class"] for e in g["edges"]}
        changes = {"added": sorted(k for k in new if k not in old), "gone": sorted(k for k in old if k not in new),
                   "changed": sorted(f"{k}: {old[k]} -> {new[k]}" for k in new if k in old and old[k] != new[k])}
    title = f"{name}: network"
    (out / "network.drawio").write_text(drawio(g, title))
    (out / "network.svg").write_text(svg(g, title))
    write_json(out / "graph.json", g)
    write_json(out / "graph.changes.json", changes)
    write_json(d / "runs" / "graph-latest.json", g)
    log(f"{len(g['nodes'])} nodes, {len(g['edges'])} paths: " + ", ".join(f"{v} {k}" for k, v in g["counts"].items() if v)
        + f" -> {out / 'network.drawio'}")
    return g


# ---- plan: the engagement plan (what's left, who does it), what's due, the report people read

GUIDANCE = {      # guidance worth a lore (lorewell build, then lorewell review): help, never cited as a control
    "sp800-37": ("NIST SP 800-37 Rev 2: the Risk Management Framework", "guidance/sp800-37r2.txt"),
    "sp800-18": ("NIST SP 800-18 Rev 1: writing a system security plan", "guidance/sp800-18r1.txt"),
    "sp800-137": ("NIST SP 800-137: continuous monitoring", "guidance/sp800-137.txt"),
    "stigs": ("STIG and CIS content for what the system runs: the SCAP Security Guide on the hosts "
              "(/usr/share/xml/scap/ssg/content), or DISA's STIG files someone brings in", None),
}
CADENCE = {"collect": "24h", "check": "7d", "conmon": "30d"}


def duration(text: str) -> float:
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhd])\s*", str(text))
    if not m:
        raise AtoneError(f"not a duration: {text!r} (e.g. 24h, 7d)")
    return float(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def plan(name: str) -> dict:
    """The engagement plan: every piece of the effort, each with who can do it (the hobkin, access it needs, or a
    person), what it's waiting on and whether it's done. Worked out from the system's folder every time, so it's
    never out of date: doing a thing (or recording a person's answer in a file) ticks it."""
    d = system_dir(name)
    spec = read_json(d / "system.json", {})
    tail = read_json(d / "tailoring.json", {})
    index = current_index(d)
    checks = load_controls(d)
    items = []

    def item(iid, who, what, done, unblocks="", control=None):
        items.append({"id": iid, "who": who, "what": what, "done": bool(done), "unblocks": unblocks,
                      "control": control})

    wbs = sorted((d / "workbooks").glob("*.xlsx"))
    item("documents", "person", "the working documents (SSP matrix, POA&M, inventories...), blank or partly done, "
         f"in {d / 'workbooks'}", wbs, "filling them in")
    for wb in wbs:
        item(f"mapping:{wb.name}", "hobkin", f"a template mapping for {wb.name} (atone workbook inspect), confirmed "
             "by the ISSE", any(fnmatch.fnmatch(wb.name, (read_json(m, {}) or {}).get("match") or "")
                                for m in (d / "mappings" / "workbooks").glob("*.mapping.json")), f"filling {wb.name}")
    item("baseline", "person", f"confirm the baseline ({tail.get('baseline', 'moderate')}) and tailoring: controls "
         "added or removed, parameter values (tailoring.json: set \"confirmed\" to who and when)",
         tail.get("confirmed"), "checks against the right controls")
    item("inherited", "person", "the inherited and shared controls, from the provider's responsibility matrix "
         "(there almost always are some)", tail.get("inherited") or tail.get("shared") or tail.get("no_inherited"),
         "drafting inherited controls as inherited")
    item("examples", "person", f"examples of implementation statements the ISSO accepted, and any sent back, in "
         f"{d / 'drafts' / 'examples'}", any((d / "drafts" / "examples").glob("*")) if (d / "drafts" / "examples").is_dir()
         else False, "narratives that sound like theirs")
    item("spec", "hobkin", "the system spec (system.json) from `atone discover`: hosts, components, the config files "
         "that define their connections; reviewed by the ISSE", spec.get("hosts") and spec.get("reviewed"),
         "collecting the right evidence")
    item("documented", "hobkin", "the intended flows (interfaces.json), from the SSP's boundary and data flow "
         "sections; reviewed by the ISSE", bool(read_json(d / "interfaces.json", [])), "the architecture's documented layer")
    seen_hosts = {e["host"] for e in index if e["kind"] in LOCAL_KINDS}
    for h in spec.get("hosts") or []:
        hn = h if isinstance(h, str) else h.get("name")
        item(f"access:{hn}", "access", f"read access to {hn}: an account that can ssh in (keys, no password) and read "
             f"config and logs; root only for /etc/sudoers and audit config (atone collect --ssh USER@{hn})",
             hn in seen_hosts, f"evidence from {hn}")
    if "aws" in (spec.get("collect") or []):
        item("access:aws", "access", "read-only AWS access where atone runs (the SecurityAudit managed policy is the "
             "least that covers it)", any(e["kind"] == "aws" and not e["source"].startswith("aws") for e in index),
             "the security groups, routes and instances")
    item("scans", "person", f"the latest scan results (OpenSCAP, the vulnerability scanner, the endpoint tool) in "
         f"{d / 'imports'}", any(e["kind"] == "scan" for e in index), "CM-6, RA-5, SI-2, SI-3 and the POA&M")
    for cid, r in checks.items():
        if r["status"] == "unknown" and not r.get("mapping"):
            item(f"map:{cid}", "hobkin", f"a control mapping for {r['label']} {r['title']}", False,
                 f"checking {r['label']}", cid)
        elif r["status"] == "unknown":
            item(f"evidence:{cid}", "hobkin", f"evidence for {r['label']}: its checks found none ("
                 + "; ".join(f"{c['check']}: {c['detail']}" for c in r.get("checks") or [])[:200] + ")", False,
                 f"checking {r['label']}", cid)
        elif r["status"] in ("not met", "partly"):
            failing = [c for c in r.get("checks") or [] if c["status"] == "fail"]
            if failing:
                item(f"fix:{cid}", "hobkin", f"{r['label']}: investigate what failed ("
                     + "; ".join(f"{c['check']}: {c['detail']}" for c in failing)[:200] + ") and propose the fix, to "
                     "the system or the paperwork, for a person to choose", False, f"{r['label']}", cid)
        for need in r.get("needs_person") or []:
            item(f"person:{cid}:{hashlib.sha1(need.encode()).hexdigest()[:6]}", "person", f"{r['label']}: {need}",
                 False, f"{r['label']}'s narrative", cid)
        if r["status"] != "inherited" and r["status"] != "unknown":
            item(f"narrative:{cid}", "hobkin", f"{r['label']}: a narrative, every claim cited (atone verify)",
                 bool(r.get("statement")), f"{r['label']} in the SSP", cid)
            if r.get("statement") and not r["statement"].get("reviewed_by"):
                item(f"review:{cid}", "person", f"{r['label']}: review the drafted statement (atone review "
                     f"{name} {cid} --by NAME)", False, f"{r['label']} in the SSP", cid)
    if any(r["status"] in ("not met", "partly") for r in checks.values()) or any(e["kind"] == "scan" for e in index):
        item("schedule", "hobkin", "a proposed POA&M schedule (drafts/poam-schedule.json): realistic dates, with margin "
             "for the ISSE and DevOps to review and do the work", (d / "drafts" / "poam-schedule.json").exists()
             or bool(approved_schedule(d)), "dates on the POA&M")
        if (d / "drafts" / "poam-schedule.json").exists():
            item("schedule-approved", "person", f"approve the POA&M schedule (atone decide {name} poam-schedule "
                 "--from drafts/poam-schedule.json --by NAME)", bool(approved_schedule(d)), "dates on the POA&M")
    out = {"system": name, "at": time.time(), "items": items,
           "open": {w: sum(1 for i in items if i["who"] == w and not i["done"]) for w in ("hobkin", "access", "person")},
           "done": sum(1 for i in items if i["done"])}
    write_json(d / "plan.json", out)
    md = [f"# The plan for {name}\n", f"Worked out by `atone plan {name}`: {out['done']} done, "
          + ", ".join(f"{v} open for {k}" for k, v in out["open"].items()) + ".\n"]
    for who, title in (("person", "Needs a person"), ("access", "Needs access"), ("hobkin", "The hobkin's")):
        md.append(f"\n## {title}\n")
        md += [f"- [{'x' if i['done'] else ' '}] {i['what']}" + (f" (for {i['unblocks']})" if i["unblocks"] else "")
               for i in items if i["who"] == who]
    (d / "PLAN.md").write_text("\n".join(md) + "\n")
    return out


def due(name: str) -> list[str]:
    """What's due, by the system's cadence (atone.json "cadence": collect 24h, check 7d, conmon 30d): one line each,
    nothing when nothing is. The chore's watch: a quiet day costs no model calls."""
    d = system_dir(name)
    cad = {**CADENCE, **(read_json(d / "atone.json", {}).get("cadence") or {})}
    now = time.time()
    newest = int(max([e["at"] for e in current_index(d)] or [0]))        # whole seconds, as git's commit times are
    checks = d / "runs" / "checks-latest.json"
    committed = git(d, "log", "-1", "--format=%ct", "--grep=^checks: ", check=False).stdout.strip()
    checked = max(checks.stat().st_mtime if checks.exists() else 0, float(committed or 0))   # here, or any machine
    conmon = d / "runs" / "conmon-latest"
    out = []
    if now - newest > duration(cad["collect"]):
        out.append(f"collect: the newest evidence is {'never' if not newest else f'{(now - newest) / 3600:.0f}h old'} "
                   f"(every {cad['collect']}): atone collect {name}, and import new scans")
    if now - checked > duration(cad["check"]) or (checked and newest > checked):
        out.append(f"check: {'new evidence since the last check' if checked and newest > checked else 'due'}: "
                   f"atone check {name}, then atone plan {name}")
    tagged = git(d, "for-each-ref", "--sort=-creatordate", "--format=%(creatordate:unix)", "refs/tags/conmon*",
                 check=False).stdout.split()
    last_conmon = max([conmon.stat().st_mtime if conmon.exists() else 0] + [float(t) for t in tagged[:1]])
    if now - last_conmon > duration(cad["conmon"]):
        out.append(f"conmon: the monthly continuous monitoring package (every {cad['conmon']}): your atone-conmon skill")
    return out


def _h(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def report(name: str, out: Path, conmon: bool = False, log=print) -> Path:
    """report.html: what changed and what's open, for people. Coverage first (what's verified, what's from a person's
    word, what's unknown), then what needs a person, drift, the architecture, and every control with its checks and
    evidence a click away. Everything in it is escaped: it shows evidence. --conmon marks the monthly package done."""
    d = system_dir(name)
    out.mkdir(parents=True, exist_ok=True)
    p = plan(name)
    ctl = load_controls(d)
    checks = {"counts": {st: sum(1 for c in ctl.values() if c.get("status") == st) for st in STATUSES}}
    index = current_index(d)
    by_id = {e["id"]: e for e in index}
    verified = {cid: {"statement": c["statement"]["text"], "coverage": c["statement"]["coverage"],
                      "reviewed_by": c["statement"].get("reviewed_by")} for cid, c in ctl.items() if c.get("statement")}
    graph = read_json(d / "runs" / "graph-latest.json", None)
    fills = [read_json(f, {}) for f in sorted((d / "runs").glob("fill-*.changes.json"))]
    cov = {k: sum(v.get("coverage", {}).get(k, 0) for v in verified.values()) for k in ("evidence", "person", "dropped")}
    css = ("body{font:14px/1.5 system-ui,sans-serif;margin:0;color:#1d1d1f;background:#fff}main{max-width:1100px;"
           "margin:auto;padding:24px 16px}h1{font-size:24px}h2{margin-top:32px;border-bottom:1px solid #ddd}"
           "table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #eee;padding:6px;text-align:left;"
           "vertical-align:top}.met{color:#1a7f37}.partly{color:#9a6700}.not.met,.not-met{color:#cf222e}.unknown{color:#6e7781}"
           ".inherited{color:#0969da}.pill{display:inline-block;padding:0 8px;border-radius:10px;background:#f2f2f2}"
           "pre{white-space:pre-wrap;background:#f6f8fa;padding:8px;max-height:320px;overflow:auto}"
           ".svg{overflow-x:auto;border:1px solid #eee}@media(prefers-color-scheme:dark){body{background:#0d1117;"
           "color:#e6edf3}pre,.pill{background:#161b22}td,th{border-color:#30363d}.svg{background:#fff}}")
    h = [f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>atone: {_h(name)}</title><style>{css}</style><main>",
         f"<h1>{_h(name)}: where the authorization stands</h1>",
         f"<p>atone {__version__}, {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}. {len(index)} pieces of current "
         "evidence. Drafts: nothing here declares the system compliant; people decide.</p>",
         "<h2>Coverage</h2><p>" + " ".join(f"<span class='pill {k.replace(' ', '-')}'>{v} {k}</span>"
                                          for k, v in (checks.get("counts") or {}).items()) + "</p>",
         f"<p>Narratives: {cov['evidence']} claims on evidence, {cov['person']} on a person's word, {cov['dropped']} "
         f"dropped by verify. Evidence from a person's site commands: "
         f"{sum(1 for e in index if e.get('site'))}.</p>",
         "<h2>Needs a person</h2><ul>" + "".join(f"<li>{_h(i['what'])}</li>" for i in p["items"]
                                                 if i["who"] in ("person", "access") and not i["done"]) + "</ul>"]
    flags = [f for r in fills for f in r.get("flags") or []]
    if flags:
        h.append("<h2>Drift: the paperwork and the evidence disagree</h2><table><tr><th>Cell</th><th>Says</th>"
                 "<th>Evidence says</th><th>Why</th></tr>" + "".join(
                     f"<tr><td>{_h(f['cell'])}</td><td>{_h(f['has'])}</td><td>{_h(f['atone'])}</td><td>{_h(f['why'])}</td></tr>"
                     for f in flags) + "</table>")
    if graph:
        svg_file = out / "network.svg"
        svg_file.write_text(svg(graph, f"{name}: network"))
        h.append("<h2>Architecture</h2><p>" + ", ".join(f"{v} {k}" for k, v in graph["counts"].items() if v)
                 + "</p><div class=svg>" + svg_file.read_text().split("?>")[-1] + "</div><ul>" + "".join(
                     f"<li><b>{_h(e['class'])}</b>: {_h(e['from'])} &rarr; {_h(e['to'])} {_h(e['port'])}</li>"
                     for e in graph["edges"] if e["class"] != "normal") + "</ul>")
    if graph and graph.get("security_groups"):
        h.append("<h2>Security groups</h2><table><tr><th>Group</th><th>Finding</th><th>Rule</th><th>Used by</th>"
                 "<th>Reachable from the internet</th></tr>" + "".join(
                     f"<tr><td>{_h(f['group'])} ({_h(f['name'])})</td><td><b>{_h(f['severity'])}</b>: {_h(f['what'])}</td>"
                     f"<td>{_h(f['rule'])}</td><td>{_h(', '.join(f['used_by']) or 'nothing')}</td>"
                     f"<td>{'yes' if f['reachable'] else 'no'}</td></tr>"
                     for f in sorted(graph["security_groups"], key=lambda f: ("high", "moderate", "low").index(f["severity"])))
                 + "</table>")
    h.append("<h2>Controls</h2><table><tr><th>Control</th><th>Status</th><th>Checks</th><th>Narrative</th></tr>")
    for c in ctl.values():
        checks_html = "".join(f"<div>{_h(x['check'])}: <b>{_h(x['status'])}</b> {_h(x['detail'])}" + "".join(
            f"<details><summary>{_h(q['evidence'])}</summary><pre>{_h(q['quote'])}</pre>"
            f"<small>{_h((by_id.get(q['evidence']) or {}).get('source', ''))}, sha256 "
            f"{_h((by_id.get(q['evidence']) or {}).get('sha256', '')[:16])}</small></details>"
            for q in x.get("quotes") or []) + "</div>" for x in c.get("checks") or []) or _h(c.get("why", ""))
        v = verified.get(c["control"])
        narr = (_h(v["statement"]) + "<br><small>" + (f"reviewed by {_h(v['reviewed_by'])}" if v.get("reviewed_by")
                                                       else "<b>not yet reviewed</b>")
                + (f"; {v['coverage']['dropped']} claims dropped" if v["coverage"]["dropped"] else "") + "</small>") if v else ""
        h.append(f"<tr><td><b>{_h(c['label'])}</b><br>{_h(c['title'])}</td><td class='{c['status'].replace(' ', '-')}'>"
                 f"{_h(c['status'])}</td><td>{checks_html}</td><td>{narr}</td></tr>")
    h.append("</table>")
    hist = history(d, n=25)
    if hist:
        h.append("<h2>Recent history</h2><table><tr><th>When</th><th>Who</th><th>What</th></tr>" + "".join(
            f"<tr><td>{_h(c['at'][:16].replace('T', ' '))}</td><td>{_h(c['author'])}</td><td>{_h(c['subject'])}"
            + "".join(f"<br><small>{_h(t)}</small>" for t in c["trailers"][:6]) + "</td></tr>" for c in hist) + "</table>")
    h.append("</main>")
    dest = out / "report.html"
    dest.write_text("\n".join(h))
    if conmon:
        (d / "runs" / "conmon-latest").write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "\n")
    log(f"{dest}")
    return dest


# ---- oscal: the SSP, assessment results and POA&M as OSCAL (1.1.2), for whoever takes machine-readable packages

OSCAL_VERSION = "1.1.2"
ATONE_NS = "https://github.com/frank-lynam/atone"
IMPL_STATE = {"met": "implemented", "partly": "partial", "not met": "planned"}   # unknown, inherited: no claim


def _uuid(*parts) -> str:
    """The same thing gets the same uuid every time, so two runs diff cleanly."""
    import uuid
    return str(uuid.uuid5(uuid.UUID("6f1a3c2e-8b1d-4e7a-9c55-0a7d2f1e9b40"), "/".join(map(str, parts))))


def _iso(t: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t or time.time()))


def _meta(title: str) -> dict:
    return {"title": title, "last-modified": _iso(), "version": __version__, "oscal-version": OSCAL_VERSION,
            "remarks": "Drafted by atone from the system's evidence; people review and decide. Nothing here declares "
                       "the system compliant."}


def _tbd(what: str) -> str:
    return f"(to be described by a person: {what})"


def oscal_ssp(name: str) -> dict:
    """The system security plan: the system's characteristics and boundary (from the spec and the architecture),
    its components and inventory, and each control's implementation (verified narratives; status only where the
    checks give one; inherited controls said so)."""
    d = system_dir(name)
    spec = read_json(d / "system.json", {})
    tail = read_json(d / "tailoring.json", {})
    checks = load_controls(d)
    graph = read_json(d / "runs" / "graph-latest.json", None)
    this = _uuid(name, "this-system")
    comps = [{"uuid": this, "type": "this-system", "title": name, "description": spec.get("description") or
              _tbd("what the system is for"), "status": {"state": "operational"}}]
    comp_ids = {}
    for c in spec.get("components") or []:
        comp_ids[c.get("name")] = _uuid(name, "component", c.get("name"))
        comps.append({"uuid": comp_ids[c.get("name")], "type": "software", "title": c.get("name"),
                      "description": c.get("about") or f"the {c.get('name')} component", "status": {"state": "operational"}})
    inventory = []
    for h in spec.get("hosts") or []:
        hn = h if isinstance(h, str) else h.get("name")
        props = [{"name": "fqdn", "value": hn}] + [{"name": "ipv4-address", "value": a}
                                                   for a in ([] if isinstance(h, str) else h.get("addresses") or [])
                                                   if re.fullmatch(r"[\d.]+", a)]
        impl = [{"component-uuid": comp_ids[c.get("name")]} for c in spec.get("components") or []
                if hn in (c.get("hosts") or [])]
        inventory.append({"uuid": _uuid(name, "host", hn), "description": f"host {hn}", "props": props,
                          **({"implemented-components": impl} if impl else {})})
    reqs = []
    for cid, r in checks.items():
        st = r.get("statement") or {}
        v = {"statement": st.get("text")} if st else None
        req = {"uuid": _uuid(name, "req", cid), "control-id": cid}
        props = [{"name": "atone-status", "ns": ATONE_NS, "value": r["status"].replace(" ", "-")}]
        if r["status"] == "inherited":
            props.append({"name": "inherited-from", "ns": ATONE_NS, "value": (r.get("provider") or {}).get("from") or "?"})
        req["props"] = props
        bc = {"component-uuid": this, "uuid": _uuid(name, "by", cid),
              "description": (v or {}).get("statement") or (f"Inherited from {(r.get('provider') or {}).get('from')}."
                                                            if r["status"] == "inherited" else _tbd("how it's implemented"))}
        if r["status"] in IMPL_STATE:
            bc["implementation-status"] = {"state": IMPL_STATE[r["status"]]}
        req["by-components"] = [bc]
        reqs.append(req)
    boundary = "Inside the boundary: " + (", ".join(n["id"] for n in (graph or {}).get("nodes") or [] if n["inside"])
                                          or _tbd("the hosts")) + "."
    if graph and graph.get("crossing"):
        boundary += " Paths that cross it: " + "; ".join(graph["crossing"]) + "."
    return {"system-security-plan": {
        "uuid": _uuid(name, "ssp"), "metadata": _meta(f"{name}: system security plan"),
        "import-profile": {"href": source_info(tail.get("baseline", "moderate")).get("url")
                           or f"#{tail.get('baseline', 'moderate')}"},
        "system-characteristics": {
            "system-ids": [{"identifier-type": ATONE_NS, "id": name}], "system-name": name,
            "description": spec.get("description") or _tbd("the system's purpose"),
            "system-information": {"information-types": [{
                "uuid": _uuid(name, "info-type"), "title": _tbd("the information types (FIPS 199 categorization)"),
                "description": "The system owner categorizes the information the system handles; atone can't."}]},
            "status": {"state": "operational"},
            "authorization-boundary": {"description": boundary, **({"diagrams": [{
                "uuid": _uuid(name, "boundary-diagram"), "description": "computed from the evidence (atone draw)",
                "links": [{"href": "network.svg", "rel": "diagram"}]}]} if graph else {})}},
        "system-implementation": {
            "users": [{"uuid": _uuid(name, "users"), "title": _tbd("the system's user types and roles")}],
            "components": comps, **({"inventory-items": inventory} if inventory else {})},
        "control-implementation": {"description": f"The {tail.get('baseline', 'moderate')} baseline, tailored "
                                                  "(tailoring.json).", "implemented-requirements": reqs}}}


def oscal_results(name: str) -> dict:
    """Assessment results: one result for the latest checks, an observation per check (with the evidence it read:
    ids and hashes) and a finding per control that has checks."""
    d = system_dir(name)
    res = {"controls": load_controls(d), "at": (read_json(d / "runs" / "checks-latest.json", {}) or {}).get("at")}
    by_id = {e["id"]: e for e in current_index(d)}
    obs, finds = [], []
    for cid, r in (res.get("controls") or {}).items():
        related = []
        for c in r.get("checks") or []:
            ou = _uuid(name, "obs", cid, c["check"])
            related.append({"observation-uuid": ou})
            obs.append({"uuid": ou, "title": f"{r['label']}: {c['check']}", "description": f"{c.get('what') or c['check']} "
                        f"(the check: {c['status']}; {c['detail']})", "methods": ["TEST"], "collected": _iso(res.get("at")),
                        **({"relevant-evidence": [{"href": f"#{e}", "description": f"{(by_id.get(e) or {}).get('source', e)} "
                                                  f"(sha256 {(by_id.get(e) or {}).get('sha256', '?')})"}
                                                 for e in c.get("evidence") or []]} if c.get("evidence") else {})})
        if not related:
            continue
        state = {"met": "satisfied", "not met": "not-satisfied"}.get(r["status"])
        finds.append({"uuid": _uuid(name, "finding", cid), "title": f"{r['label']} {r['title']}",
                      "description": f"atone's checks: {r['status']}",
                      "target": {"type": "objective-id", "target-id": f"{cid}_obj",
                                 "status": {"state": state or "not-satisfied",
                                            **({} if state else {"reason": r["status"].replace(" ", "-")})}},
                      "related-observations": related})
    return {"assessment-results": {
        "uuid": _uuid(name, "ar"), "metadata": _meta(f"{name}: assessment results (atone's checks)"),
        "import-ap": {"href": "#" + _uuid(name, "ap")},
        "results": [{"uuid": _uuid(name, "result", res.get("at")), "title": "atone's checks",
                     "description": "Each control's checks against the current evidence.", "start": _iso(res.get("at")),
                     "reviewed-controls": {"control-selections": [{"include-all": {}}]},
                     **({"observations": obs} if obs else {}), **({"findings": finds} if finds else {})}]}}


def oscal_poam(name: str) -> dict:
    """The POA&M: an item per open finding (imported findings, failed OpenSCAP rules), each with its observation and
    the evidence it came from."""
    d = system_dir(name)
    schedule = approved_schedule(d)
    by_id = {e["id"]: e for e in current_index(d)}
    items, obs = [], []
    for it in poam_items(d):
        ou = _uuid(name, "poam-obs", it["key"])
        ev = by_id.get(it["evidence"]) or {}
        obs.append({"uuid": ou, "description": f"{it['weakness']} on {it['asset']} ({it['source']}, {it['severity']})",
                    "methods": ["TEST"], "collected": _iso(), "relevant-evidence": [{
                        "href": f"#{it['evidence']}",
                        "description": f"{ev.get('source', it['evidence'])} (sha256 {ev.get('sha256', '?')})"}]})
        items.append({"uuid": _uuid(name, "poam", it["key"]), "title": it["weakness"],
                      "description": f"{it['description'] or it['weakness']} (control {it['control']}; detected "
                                     f"{it['detected'] or '?'})",
                      "props": [{"name": "severity", "ns": ATONE_NS, "value": str(it["severity"] or "unknown")}]
                      + ([{"name": "scheduled-completion", "ns": ATONE_NS, "value": schedule[it["key"]]}]
                         if it["key"] in schedule else []),
                      "related-observations": [{"observation-uuid": ou}]})
    return {"plan-of-action-and-milestones": {
        "uuid": _uuid(name, "poam"), "metadata": _meta(f"{name}: plan of action and milestones"),
        "system-id": {"identifier-type": ATONE_NS, "id": name},
        **({"observations": obs} if obs else {}), "poam-items": items}}


def write_oscal(name: str, out: Path, log=print) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    for fname, doc in (("ssp.json", oscal_ssp(name)), ("assessment-results.json", oscal_results(name)),
                       ("poam.json", oscal_poam(name))):
        write_json(out / fname, doc)
        paths.append(out / fname)
    log(f"OSCAL {OSCAL_VERSION}: " + ", ".join(str(p) for p in paths))
    return paths


# ---- pack: atone as an expert pack for hobkin (a chore and its skills), served through the hobkin.packs entry point

CHORE_JSON = {
    "name": "atone",
    "description": "Keep a system's authorization (ATO) true to the system: evidence, checks, cited narratives, the "
                   "customer's workbooks, the architecture, continuous monitoring.",
    "settings": {
        "system": {"about": "the system's name: atone's folder for it", "env": "ATONE_SYSTEM"},
        "store": {"default": "", "about": "where its evidence goes: s3://bucket/prefix or a folder (empty: ~/atone/store)",
                  "env": "ATONE_STORE"},
        "baseline": {"default": "moderate", "about": "its 800-53 baseline: low, moderate, high or privacy",
                     "env": "ATONE_BASELINE"}},
    "config": {"idle_prompt": None, "wake": {"command": "atone due {{system}}", "every": "1h"}},
    "given": ("You've been given the atone chore for the system {{system}}: keeping its authorization true to the "
              "system. Read CHORE-atone.md, then start: atone init {{system}} (if it isn't set up), atone plan "
              "{{system}}, and tell your people what you need from them first."),
}
CHORE_MD = """# Your chore: atone, for {{system}}

You keep the authorization of the system **{{system}}** true to the system. Assessors mostly take what the package
says on trust, so being right matters more than being complete: when in doubt, say less, and say why.

## How it works

- **atone is your toolkit; you are its apprentice.** `atone` (run it like any command; `atone --help`) collects
  evidence, imports scans, checks controls, verifies citations, fills the workbooks and draws the architecture. It
  never calls a model. You do the judgement work: drafting the system spec, the mappings and the narratives,
  investigating drift, and explaining to people what you need.
- **Evidence is never yours to write.** Only atone collects or imports evidence. You read it (`atone evidence
  {{system}} search WORDS`, `show ID`).
- **No citation, no claim.** Every claim in a narrative cites evidence and quotes it (your atone-narratives skill);
  `atone verify` drops what doesn't hold. A claim from a person cites who and when.
- **The customer's words, never yours.** Status values come from their workbook; what's filled in is kept, and where
  the evidence disagrees, atone flags it for a person.
- **People decide.** The ISSE owns the system spec and the mappings; the ISSO owns the package. You draft, prove,
  and propose.
- **Only the access you're given.** A key, token or password you come across on a host isn't yours to use, even
  to unblock yourself (and it's a finding: tell the ISSE where it is, never what it is). Ask for what you need.

## The codex

Everything about {{system}} lives in its codex, a git repository at `~/atone/systems/{{system}}` (its CODEX.md says
what's where), and its history is the system's security history. So:

- **atone commits what it does** (evidence, checks, the POA&M, verified statements, packages), with trailers saying
  what and why. Commit your own edits (the system spec, mappings, interfaces, drafts) with `atone commit {{system}}
  "what and why"`: it marks them as yours (Drafted-by) and refuses anything secret.
- **Draft on a branch:** `git -C ~/atone/systems/{{system}} switch -c drafts/WHAT` before drafting statements,
  mappings or a schedule; push it to the team's git server and ask for a review. Merging is approval: never merge
  your own work into main.
- **People review and decide through atone:** `atone review {{system}} CONTROL --by NAME`, `atone decide {{system}}
  KIND "what and why" --by NAME`. Tell them the exact command; never run these for them.
- **Keep it in step:** `git pull` before you start, push when you're done (on a branch).

## The plan comes first

`atone plan {{system}}` works out every piece of the effort, and who can do it: you, access you need, or a person.
Make it your checklist (copy PLAN.md into your goal's CHECKLIST.md, and re-run it as things change). Start on yours,
in the order that unblocks the most. For the rest, tell the people exactly what you need and why: the account or
permission (the least that works), the file, the decision. The first things to ask for are always the working
documents, the inherited-controls matrix, example narratives, and access.

Their documents are Word and Excel files: `atone doc FILE --out runs/NAME.txt` turns one into text you can read and
search (headings, lists and tables kept; runs/ stays on this machine, so it's never committed).

## The cadence

Your watch runs `atone due {{system}}` every hour and wakes you only when something's due: collecting (daily),
checking (weekly, and after new evidence), and the monthly continuous monitoring package (your atone-conmon skill:
it ends with `atone package {{system}} --tag conmon-YYYY-MM`, which is how the next month knows it's done).
After each: `atone plan {{system}}`, and tell your people what changed and what you need.

## Your skills

atone-become-expert (the lores), atone-system-spec, atone-mappings, atone-narratives, atone-drift, atone-conmon.
Open the one for the step you're on, and follow it.
"""
SKILLS = {
    "atone-become-expert": ("Build the lores you need to be the expert for a system: NIST's controls exactly, public "
                            "guidance, and the customer's own documents.", """
1. The controls, word for word (NIST's files ship with atone: no internet needed): `atone controls lore`, then
   `lorewell install` the lore it writes. This is what you cite and quote for a control's text: never a paraphrase.
2. Guidance (help for you, never cited as a control): `atone sources` lists it, with the paths of the texts atone
   ships. They're plain text: grep them as they are. A lore of one is better (ranked search, an outline), but
   building one takes a model: `lorewell build NAME FILE` reads LORE_BASE_URL, LORE_MODEL and LORE_API_KEY, and your
   own model's key isn't yours to use, so ask your people for those (in your secrets.env). Then `lorewell review
   packs/NAME` (the ISSE looks it over), `lorewell compile packs/NAME`, and `lorewell install NAME.lore.db`. For
   STIGs, use the SCAP Security Guide content on the hosts, for the components the system spec names.
3. The customer's own documents (policies, procedures, past packages, interconnection agreements), as they come up:
   ask which to use; read them with `atone doc FILE` (or `lorewell build` them into a private lore here, the same
   way), and never send them anywhere else.
4. What you learn about the system and its people (voice, quirks, owners) goes in your field lore; the mappings
   don't: they're files the ISSE reviews."""),
    "atone-system-spec": ("Draft the system spec (system.json) and the intended flows (interfaces.json) for the "
                          "ISSE to review.", """
1. `atone discover {{system}}` (with `--ssh USER@HOST` for each host you have access to). Read discovery.json.
2. In system.json: the hosts (name, addresses, other `names` it's known by), the components (which hosts run them;
   every config file that defines what they connect to or listen on, and their audit settings, from discovery's
   config list: `{"path": ...}`; never credential files), what to collect (`collect`: kinds from atone's menu), and,
   if it runs in AWS, `aws.regions` (or `aws.region`) and `aws.public_ports`: the ports meant to be open to the whole
   internet (default 80 and 443; anything else open to the world is a finding). Keep the generic linux component's
   files.
3. The intentional connections come from those files: after `atone collect`, `atone connections {{system}}` shows
   what atone's generic readers found in each (URLs, JDBC and TNS strings, host and port settings, listen
   directives), with the line. Where a product's format hides a connection from them, add a pattern to that file's
   entry: `"connects": [{"pattern": "a regex with named groups host and port", "about": "what it is"}]` (or
   `"listens": true` with a port group), and check it finds what it should.
4. In interfaces.json: the flows the SSP describes (`atone doc SSP.docx --out runs/ssp.txt` to read it): `{"from", "to", "port": "tcp/443", "data", "about"}`, by
   component name (or "internet"). Quote the SSP's section for each in "about".
5. Commit them on a branch (`atone commit {{system}} "the system spec, from discovery"`) and ask the ISSE to review
   them; when they have, they set `"reviewed": "who, when"` in system.json and merge."""),
    "atone-mappings": ("Draft control mappings, scanner mappings and workbook template mappings: data the ISSE "
                       "owns, run by atone's code.", """
Each kind's format (its keys, what each means, an example) is `atone mappings --example KIND`: the definitions atone's
readers check mappings against, so it's always current. How a mapping is used is in the code beside it
(`python3 -c "import atone; help(atone.import_mapped)"`, or `grep -n '^# ----'` in atone's file for its sections).
- **Control mappings** (mappings/controls/*.json; `--example controls`): for each control, the evidence that bears
  on it, checks as data, and `needs_person` (what only a person can supply). Start from mappings/controls/starter.json;
  look the control up in the controls lore (its objective says what to check).
- **Scanner mappings** (mappings/scanners/TOOL.mapping.json; `--example scanner`): `atone import {{system}} --sample
  FILE` shows the export's columns; map them to atone's fields, severity in the customer's words.
- **Template mappings** (mappings/workbooks/NAME.mapping.json; `--example ssp`, `--example poam`): `atone workbook
  inspect FILE` shows the sheets, header rows and drop-downs; `status_values` are the workbook's own words, exactly.
- `atone mappings {{system}}` checks every mapping against its format: a misspelt key is caught, never ignored.
- Commit them on a branch (`atone commit {{system}} "..."`) and ask the ISSE to confirm each; mappings are drafts
  until they're merged."""),
    "atone-narratives": ("Write implementation statements as cited claims, and verify them.", """
1. `atone check {{system}} CONTROL` for its results and the quotes its checks found; `atone evidence {{system}}
   search ...` for more. The controls lore for what the control asks; the customer's examples for their voice.
2. Write drafts/CONTROL.json: `{"control": "au-11", "claims": [{"text": "...", "cites": [{"evidence": ID, "quote":
   "the exact words"}]}]}`. One fact per claim; quote words that are really in the evidence. A fact from the
   customer's own documents (a policy, the SSP, a workbook's existing text) cites the document:
   `{"document": "workbooks/SSP.docx", "quote": "the exact words"}`; it's the document's claim, not proof, so say
   whose it is ("The SSP states..."). A fact a person told you: `{"text": "...", "person": "who, when"}`, only for
   what they said themselves: never put a document's words in a person's mouth.
   Evidence counts only from the system's own hosts (system.json): a scan of another host isn't this system's.
3. `atone verify {{system}} drafts/CONTROL.json`: what holds goes into controls/CONTROL.json, committed, as a draft.
   Dropped claims say why: fix the claim or drop it; never re-word a claim so it says more than its evidence.
   Ask a person to review it (`atone review {{system}} CONTROL --by NAME`; `atone review {{system}}` lists what's
   waiting).
4. For many controls, hand families to brownies (each: these controls, these steps), then read what they wrote.
5. Never write that a control is met, implemented or compliant: say what the system does, and let the status come
   from the checks."""),
    "atone-drift": ("Investigate where the paperwork and the system disagree, and propose the fix.", """
- Sources: flags in the fill's NAME.changes.json, failing checks (`atone plan` lists them), and the architecture
  (`atone draw`): unexpected paths (seen, and nothing explains them: first), blocked ones (configured, no rule allows
  them: they'll fail), undocumented ones (the SSP or the system is wrong), unused rules (attack surface to tighten),
  idle ones (intended but quiet: worth a word in the SSP), documented-only ones.
- For each: what the paperwork says, what the evidence shows (cite it), the likely cause, and two fixes: to the
  system (the exact change) and to the paperwork (the exact words). People choose.
- Never change the system or the workbooks yourself to make them agree."""),
    "atone-conmon": ("The monthly continuous monitoring package.", """
1. Ask for this month's scan exports if they aren't in imports/; `atone import {{system}}`; `atone collect
   {{system}}`; `atone check {{system}}`.
2. The POA&M (poam/ in the codex: atone opens items as findings appear): propose a schedule in
   drafts/poam-schedule.json (`{item key: "YYYY-MM-DD"}`), realistic dates with margin for the ISSE and DevOps to
   review and do the work, by severity; commit it and ask a person to approve it (`atone decide {{system}}
   poam-schedule "..." --by NAME`). Where there's a hard deadline, say plainly what can't fit. Items atone marks as
   looking closed: ask a person to close them (`atone decide {{system}} poam-close "why" --item KEY --by NAME`).
3. `atone package {{system}} --tag conmon-YYYY-MM --note "..."`: the workbooks, diagrams, OSCAL and the report into
   packages/conmon-YYYY-MM/, committed and tagged.
4. Tell your people what changed this month (`atone history {{system}} --since "1 month ago"`), what's open, and
   what you need, with the report's path."""),
}


def hobkin_pack() -> str:
    """The hobkin.packs entry point: atone's chore and skills as a folder (written once per version), for hobkin to
    find with --chore atone."""
    root = Path(os.environ.get("XDG_CACHE_HOME") or "~/.cache").expanduser() / "atone" / f"pack-{__version__}"
    chore = root / "chores" / "atone"
    if not (chore / "chore.json").exists():
        (chore / "skills").mkdir(parents=True, exist_ok=True)
        (chore / "CHORE.md").write_text(CHORE_MD)
        for name, (desc, body) in SKILLS.items():
            (chore / "skills" / name).mkdir(parents=True, exist_ok=True)
            (chore / "skills" / name / "SKILL.md").write_text(
                f"---\nname: {name}\ndescription: \"{desc}\"\n---\n\n# {name}\n{body.strip()}\n")
        write_json(chore / "chore.json", CHORE_JSON)
    return str(root)


# ---- command line: argument parsing, main

def cmd_evidence(args) -> str:
    d = system_dir(args.system)
    idx = current_index(d)
    if args.what in (None, "list"):
        return "\n".join(f"{e['id']}  {e['host']}  {e['source']}" + (", SITE" if e.get("site") else "")
                         for e in idx) or "no evidence yet: atone collect " + args.system
    if args.what == "show":
        e = next((e for e in idx if e["id"] == (args.words or [""])[0]), None)
        if not e:
            raise AtoneError(f"no evidence {(args.words or [''])[0]!r} in that run")
        rec = load_record(d, e)
        ok = "verified" if rec and not rec.get("tampered") and check_record(rec) else "DOES NOT MATCH ITS HASH"
        return f"{rec['id']} ({rec['path']}, {rec['source']}, first seen " \
               f"{time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(rec['first_seen']))}, sha256 {rec['sha256'][:16]}... " \
               f"{ok})\n\n{rec['content']}"
    if args.what == "search":
        hits = search_evidence(d, " ".join(args.words or []))
        return "\n".join(f"{h['id']}  {h['source']}\n    {' '.join(h['snippet'].split())[:240]}" for h in hits) \
            or f"no evidence with {' '.join(args.words or [])!r}"
    raise AtoneError("evidence SYSTEM [list | show ID | search WORDS]")


def cmd_controls(args) -> str:
    if args.what == "fetch":
        fetch_sources(args.from_dir)
        return f"in {HOME / 'sources'}, used instead of the shipped copy (what each is, with hashes: lock.json)"
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
    p = sub.add_parser("init", help="a system's codex (a git repository), or a clone of one (--from)")
    p.add_argument("system")
    p.add_argument("--from", dest="from_url", help="clone the system's codex from here (a fresh machine)")
    p.add_argument("--remote", help="the internal git server's URL for it (origin)")
    p.add_argument("--store", help="where raw scanner exports are archived by hash: s3://bucket/prefix or a folder")
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
    p.add_argument("--eaveswatch", metavar="STORE", help="evidence about logging from an eaveswatch store (s3://... or a folder)")
    p.add_argument("--ew-system", help="its system name there (default: this system's)")
    p.add_argument("--env", help="only this eaveswatch env")
    p = sub.add_parser("check", help="every control against its mapping and the current evidence")
    p.add_argument("system")
    p.add_argument("control", nargs="?", help="one control's results, in full")
    p = sub.add_parser("verify", help="check the citations in drafted narratives (drafts/*.json)")
    p.add_argument("system")
    p.add_argument("drafts", nargs="*", help="default: every draft in drafts/")
    p = sub.add_parser("mappings", help="a system's mappings and anything wrong with them; --example KIND: a format")
    p.add_argument("system", nargs="?")
    p.add_argument("--example", nargs="?", const="", metavar="KIND",
                   help="a mapping format (controls, scanner, ssp, poam): its keys, what each means, an example")
    p = sub.add_parser("workbook", help="inspect FILE: a workbook's sheets, headers and drop-downs (for its mapping)")
    p.add_argument("what", choices=["inspect"])
    p.add_argument("file")
    p = sub.add_parser("doc", help="a .docx or .xlsx as plain text (headings, lists, tables), to read or search")
    p.add_argument("file")
    p.add_argument("--out", help="write it here (else it's printed)")
    p = sub.add_parser("fill", help="fill copies of the working documents from the checks and verified narratives")
    p.add_argument("system")
    p.add_argument("files", nargs="*", help="default: the system's workbooks/*.xlsx")
    p.add_argument("--out", required=True, help="the folder for the filled copies and their change reports")
    p = sub.add_parser("connections", help="what each config file says its host connects to and listens on")
    p.add_argument("system")
    p = sub.add_parser("draw", help="the architecture: actual, allowed and documented paths, as draw.io and SVG")
    p.add_argument("system")
    p.add_argument("--out", required=True)
    p = sub.add_parser("plan", help="the engagement plan: every piece of the effort, and who can do it")
    p.add_argument("system")
    p = sub.add_parser("due", help="what's due by the cadence (prints nothing when nothing is)")
    p.add_argument("system")
    p = sub.add_parser("report", help="report.html: coverage, what needs a person, drift, the architecture, controls")
    p.add_argument("system")
    p.add_argument("--out", required=True)
    p.add_argument("--conmon", action="store_true", help="this is the monthly package: mark it done")
    sub.add_parser("sources", help="public guidance worth a lore (lorewell build), and NIST's OSCAL files")
    p = sub.add_parser("oscal", help="the SSP, assessment results and POA&M as OSCAL 1.1.2")
    p.add_argument("system")
    p.add_argument("--out", required=True)
    p = sub.add_parser("review", help="a person reviews drafted statements (or, alone, lists those unreviewed)")
    p.add_argument("system")
    p.add_argument("controls", nargs="*")
    p.add_argument("--by", help="who reviewed them (name and role)")
    p = sub.add_parser("decide", help="a person's decision, recorded: " + ", ".join(DECISION_KINDS))
    p.add_argument("system")
    p.add_argument("kind", choices=DECISION_KINDS)
    p.add_argument("what", nargs="?", default="", help="what was decided, and why")
    p.add_argument("--by", required=True, help="who decided (name and role)")
    p.add_argument("--control", action="append", default=[], help="a control it concerns (repeatable)")
    p.add_argument("--until", help="when it's to be looked at again (YYYY-MM-DD)")
    p.add_argument("--from", dest="from_file", help="poam-schedule: the proposed schedule to approve")
    p.add_argument("--item", action="append", default=[], help="poam-close: the POA&M item (key or file name)")
    p = sub.add_parser("package", help="the package, generated into packages/TAG/, committed and tagged")
    p.add_argument("system")
    p.add_argument("--tag", required=True)
    p.add_argument("--note", default="")
    p = sub.add_parser("history", help="the system's security history, from the codex")
    p.add_argument("system")
    p.add_argument("--control")
    p.add_argument("--path", help="e.g. evidence/app01 (a host's evidence), poam, decisions")
    p.add_argument("--since")
    p.add_argument("-n", type=int, default=50)
    sub.add_parser("guard", help="(the codex's pre-commit hook) refuse staged changes the redaction floor catches")
    p = sub.add_parser("commit", help="commit edits to the codex (the spec, mappings, interfaces, drafts) with trailers")
    p.add_argument("system")
    p.add_argument("message")
    p.add_argument("--path", action="append", default=[], help="only these (default: everything changed)")
    p.add_argument("--control", action="append", default=[], help="a control it concerns (a Control trailer)")
    p = sub.add_parser("evidence", help="the current evidence: list, show ID, search WORDS")
    p.add_argument("system")
    p.add_argument("what", nargs="?", choices=["list", "show", "search"])
    p.add_argument("words", nargs="*")
    p = sub.add_parser("controls", help="lore | fetch [--from DIR] | SYSTEM [list | show ID]")
    p.add_argument("what")
    p.add_argument("rest", nargs="*")
    p.add_argument("--out")
    p.add_argument("--from", dest="from_dir", help="fetch: NIST's files from this folder (no internet needed)")
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
            d = init_system(args.system, args.store, args.remote, args.from_url)
            print(f"{args.system}: the codex is {d} (a git repository; CODEX.md says what's in it)")
        elif args.cmd == "guard":
            bad = guard_staged(Path.cwd())
            if bad:
                print("atone: not committed: these would add what the redaction floor catches (keys, tokens, "
                      "passwords):\n  " + "\n  ".join(bad[:20]), file=sys.stderr)
                return 1
        elif args.cmd == "commit":
            print(codex_commit(system_dir(args.system), args.message, trailers=[("Control", c.lower()) for c in args.control],
                               paths=args.path or None) or "nothing to commit")
        elif args.cmd == "review":
            d = system_dir(args.system)
            if not args.controls:
                todo = [(c.get("label", cid), c["statement"]["drafted_by"]) for cid, c in load_controls(d).items()
                        if c.get("statement") and not c["statement"].get("reviewed_by")]
                print("\n".join(f"{lbl}: drafted by {who}" for lbl, who in todo) or "nothing waiting for review")
            else:
                if not args.by:
                    raise AtoneError("say who reviewed them: --by \"Name (role)\"")
                print(review_statements(d, [c.lower() for c in args.controls], args.by) or "nothing changed")
        elif args.cmd == "decide":
            print(decide(system_dir(args.system), args.kind, args.what, args.by, [c.lower() for c in args.control],
                         args.until, args.from_file, args.item) or "nothing changed")
        elif args.cmd == "package":
            package(args.system, args.tag, args.note)
        elif args.cmd == "history":
            for c in history(system_dir(args.system), args.control and args.control.lower(), args.path, args.since, args.n):
                print(f"{c['at'][:16].replace('T', ' ')}  {c['commit']}  {c['author']}: {c['subject']}"
                      + "".join(f"\n      {t}" for t in c["trailers"][:8])
                      + (f"\n      ... and {len(c['trailers']) - 8} more (git show {c['commit']})" if len(c["trailers"]) > 8 else ""))
        elif args.cmd == "discover":
            d = system_dir(args.system)
            found = [over_ssh(t, ["__discover"]) for t in args.ssh] if args.ssh else [discover_here()]
            out = d / "discovery.json"
            write_json(out, {"at": time.time(), "hosts": found})
            print(f"{len(found)} host{'s' if len(found) != 1 else ''}: "
                  + ", ".join(f"{h['host']} ({sum(p['count'] for p in h['processes'])} processes, "
                              f"{len(h['listeners'])} listeners, {len(h['configs']['named by running processes'])} "
                              f"config files named by them, {sum(map(len, h['configs']['in /etc, by directory'].values()))}"
                              " more in /etc)" for h in found) + f"\n  in {out} ({out.stat().st_size // 1024} KB)")
        elif args.cmd == "doc":
            t = doc_text(args.file)
            if args.out:
                Path(args.out).write_text(t)
                print(f"{args.file}: {len(t.splitlines())} lines, {len(t) // 1024} KB -> {args.out}")
            else:
                sys.stdout.write(t)
        elif args.cmd == "collect":
            collect(args.system, args.kind, args.ssh)
        elif args.cmd == "import":
            if args.sample:
                print(sample(Path(args.sample)))
            else:
                import_results(args.system, args.files, eaveswatch=args.eaveswatch, ew_system=args.ew_system,
                               env=args.env)
        elif args.cmd == "check":
            if args.control:
                want = args.control.lower()
                hit = next((r for r in load_controls(system_dir(args.system)).values()
                            if want in (r["control"], r.get("label", "").lower())), None)
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
                save_statement(d, v)
                cov = v["coverage"]
                print(f"{p.name}: {cov['evidence']} claims on evidence, {cov['document']} on documents, "
                      f"{cov['person']} on a person's word, "
                      f"{cov['dropped']} dropped" + "".join(f"\n  dropped: {x['text'][:80]} ({x['why']})"
                                                          for x in v["dropped"]))
        elif args.cmd == "mappings":
            if args.example is not None:
                print(describe_format(args.example))
            elif not args.system:
                raise AtoneError("which system? (or --example KIND for a mapping format)")
            else:
                d = system_dir(args.system)
                maps = load_mappings(d)
                for cid, m in maps.items():
                    probs = mapping_problems(m)
                    print(f"{cid:<10} {m.get('about', '')[:60]:<60} {m['_file']}" + "".join(f"\n  ! {x}" for x in probs))
                print(f"{len(maps)} control mappings")
                for kind, folder in (("scanner", "scanners"), ("workbook", "workbooks")):
                    for f in sorted((d / "mappings" / folder).glob("*.mapping.json")):
                        m = read_json(f, {})
                        fmt = SCANNER_MAPPING if kind == "scanner" else POAM_MAPPING if m.get("kind") == "poam" else SSP_MAPPING
                        probs = format_problems(fmt, m)
                        print(f"{kind:<10} {f.relative_to(d)}" + ("".join(f"\n  ! {x}" for x in probs) or "  ok"))
        elif args.cmd == "workbook":
            print(inspect_workbook(Path(args.file)))
        elif args.cmd == "fill":
            fill_workbooks(args.system, Path(args.out), args.files)
        elif args.cmd == "connections":
            d = system_dir(args.system)
            found = configured_endpoints(d, read_json(d / "system.json", {}))
            for f in found:
                print(f"{f['host']}  {f['file']}  ({f['evidence']})")
                for c in f["connects"]:
                    print(f"  -> {c['host']}:{c['port']}  line {c['line']}, {c['how']}: {c['quote'][:100]}")
                for l in f["listens"]:
                    print(f"  listens {l['port']}  line {l['line']}, {l['how']}")
            print(f"{len(found)} config files with connections" if found else
                  "no connections found in the collected config files (does the system spec name them?)")
        elif args.cmd == "draw":
            draw_system(args.system, Path(args.out))
        elif args.cmd == "plan":
            p = plan(args.system)
            print(f"{p['done']} done; open: " + ", ".join(f"{v} for {k}" for k, v in p["open"].items())
                  + f"\n  {system_dir(args.system) / 'PLAN.md'}")
        elif args.cmd == "due":
            for line in due(args.system):
                print(line)
        elif args.cmd == "report":
            report(args.system, Path(args.out), args.conmon)
        elif args.cmd == "oscal":
            write_oscal(args.system, Path(args.out))
        elif args.cmd == "sources":
            print(f"NIST's controls, compiled exactly (atone controls lore), from {sources_dir()}:\n" + "\n".join(
                f"  {k}: sha256 {source_info(k).get('sha256', '?')[:16]}... ({source_info(k).get('url', '?')})"
                for k in SOURCES) + "\n\nGuidance (lorewell build NAME FILE, then lorewell review; help, never cited "
                  "as a control):\n" + "\n".join(f"  {k}: {t}" + (f"\n    {DATA / rel}" if rel else "")
                                                for k, (t, rel) in GUIDANCE.items()))
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
