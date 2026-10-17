#!/usr/bin/env python3
"""Fixed root worker for independent PQTunnel Gateway/Dialer pairing."""
import base64
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

STATE = Path("/var/lib/pqtunnel-manager")
ENV_FILE = STATE / "node-setup.env"
STATE_FILE = STATE / "node-setup-state"
LOG_FILE = STATE / "node-setup.log"
RAW_LOG = STATE / "node-setup-raw.log"
BUNDLE_FILE = STATE / "node-setup-bundle.tar.gz"
UPLOAD_FILE = STATE / "node-setup-upload.tar.gz"
META_FILE = STATE / "node-setup-meta.json"
PKI = Path("/etc/pqtunnel/pki")
CREATED = []
LOGS = []

def log(msg):
    LOGS.append(str(msg)[:500])

def write_atomic(path, data, mode=0o600, refuse_existing=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if refuse_existing and (path.exists() or path.is_symlink()):
        raise RuntimeError("refusing to overwrite existing file: " + str(path))
    fd, tmp_name = tempfile.mkstemp(prefix=".node-setup-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(tmp_name, 0, 0)
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
    if refuse_existing:
        CREATED.append(path)

def write_state(value):
    write_atomic(STATE_FILE, (value + "\n").encode(), 0o600)

def clean_created():
    for path in reversed(CREATED):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

def run_checked(args):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, check=False, timeout=60)
    output = proc.stdout.strip()
    if output:
        # The PKI CLI reports filenames and operations, never private-key data.
        log(output)
    if proc.returncode:
        raise RuntimeError("required local command failed: " + Path(args[0]).name)
    return output

def manager_role():
    path = Path("/etc/default/pqtunnel-manager")
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("manager configuration is unavailable")
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("PQTUNNEL_MANAGER_ROLE="):
            values["role"] = line.split("=", 1)[1]
    if values.get("role") not in {"gateway", "dialer"}:
        raise RuntimeError("manager role is invalid")
    return values["role"]

def valid_host(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        return False
    if any(c in value for c in "/\\\x00 \t\r\n'\";$&|<>"):
        return False
    try:
        addr = ipaddress.ip_address(value)
        return not addr.is_unspecified and not addr.is_multicast
    except ValueError:
        pass
    value = value.rstrip(".")
    return bool(value) and all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
        for part in value.split(".")
    )

def valid_allow(value):
    if value == "":
        return True
    items = value.split(",")
    seen = set()
    for item in items:
        if not re.fullmatch(r"(tcp|udp):[0-9]+", item):
            return False
        port = int(item.split(":", 1)[1], 10)
        if not 1 <= port <= 65535 or item in seen:
            return False
        seen.add(item)
    return True

def create_bundle(path, members):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tarfile.open(tmp, "w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            import io
            archive.addfile(info, io.BytesIO(data))
    os.chown(tmp, 0, 0)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def parse_profile(kind, destination):
    if not UPLOAD_FILE.is_file() or UPLOAD_FILE.is_symlink():
        raise RuntimeError("upload the matching public profile bundle first")
    expected = {"gateway": {"gateway-ca.crt", "gateway.json"},
                "dialer": {"dialer-ca.crt", "dialer.json"}}[kind]
    destination.mkdir(mode=0o700)
    extracted = {}
    with tarfile.open(UPLOAD_FILE, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) != len(expected) or {m.name for m in members} != expected:
            raise RuntimeError("profile bundle contains unexpected entries")
        for member in members:
            if not member.isfile() or member.issym() or member.islnk() or member.size < 1 or member.size > 262144:
                raise RuntimeError("profile bundle contains an unsafe or oversized entry")
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError("cannot read profile bundle")
            data = source.read(262145)
            if len(data) != member.size or len(data) > 262144:
                raise RuntimeError("profile entry size is invalid")
            extracted[member.name] = data
    cert_name = "gateway-ca.crt" if kind == "gateway" else "dialer-ca.crt"
    if not extracted[cert_name].startswith(b"-----BEGIN CERTIFICATE-----"):
        raise RuntimeError("public CA certificate is not valid PEM")
    meta_name = "gateway.json" if kind == "gateway" else "dialer.json"
    meta = json.loads(extracted[meta_name].decode("utf-8"))
    if not isinstance(meta, dict) or meta.get("schema") != 1:
        raise RuntimeError("unsupported profile schema")
    if kind == "gateway":
        if not valid_host(meta.get("server_name")):
            raise RuntimeError("Gateway server name in the profile is invalid")
        port = meta.get("listen_port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise RuntimeError("Gateway listener port in the profile is invalid")
        if not valid_allow(meta.get("allowed_dst_ports", "")):
            raise RuntimeError("Gateway port allowlist in the profile is invalid")
    else:
        if meta.get("peer_identity") != "10.66.0.2":
            raise RuntimeError("Dialer peer identity in the profile is invalid")
        if not valid_allow(meta.get("allowed_dst_ports", "")):
            raise RuntimeError("Dialer port allowlist in the profile is invalid")
    for name, data in extracted.items():
        write_atomic(destination / name, data, 0o600, refuse_existing=True)
    return meta

def install_pki_file(source, destination, mode):
    data = Path(source).read_bytes()
    write_atomic(destination, data, mode, refuse_existing=True)

def gateway_init(req):
    if manager_role() != "gateway":
        raise RuntimeError("generate a Gateway profile from a Gateway panel")
    name = req.get("PublicName", "")
    port = req.get("ListenPort", 0)
    if not valid_host(name):
        raise RuntimeError("enter a valid IPv4 address or DNS name for the Gateway certificate")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise RuntimeError("listener port must be between 1 and 65535")
    def normalize_ports(value):
        if not isinstance(value, str):
            raise RuntimeError("port list must be text")
        value = value.strip().lower()
        if value in {"", "none", "-"}:
            return []
        if not re.fullmatch(r"[0-9]+(?:,[0-9]+)*", value):
            raise RuntimeError("ports must be comma-separated numbers or none")
        nums, seen = [], set()
        for item in value.split(","):
            number = int(item, 10)
            if not 1 <= number <= 65535 or number in seen:
                raise RuntimeError("port list contains an invalid or duplicate port")
            seen.add(number)
            nums.append(number)
        return nums
    tcp = normalize_ports(req.get("TCPPorts", "443"))
    udp = normalize_ports(req.get("UDPPorts", "53,123"))
    if not tcp and not udp:
        raise RuntimeError("select at least one TCP or UDP destination port")
    allowed = [f"tcp:{n}" for n in tcp] + [f"udp:{n}" for n in udp]
    allow_text = ",".join(allowed)
    if Path("/etc/default/pqtunneld").exists():
        raise RuntimeError("an existing /etc/default/pqtunneld was found; refusing to overwrite it")
    for path in (PKI / "server.key", PKI / "server.crt", PKI / "gateway-ca.crt", META_FILE):
        if path.exists():
            raise RuntimeError("existing Gateway setup artifacts detected; inspect them before retrying")
    if shutil.which("ss"):
        proc = subprocess.run(["ss", "-ltnH"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if proc.returncode == 0 and any(line.split()[3].endswith(":" + str(port)) for line in proc.stdout.splitlines() if len(line.split()) >= 4):
            raise RuntimeError("the selected TCP listener port is already in use")
    work = Path(tempfile.mkdtemp(prefix="gateway-pki-", dir=str(STATE)))
    os.chmod(work, 0o700)
    try:
        pki_work = work / "pki"
        run_checked(["/usr/local/bin/pqtunnel-pki", "init", "--server-name", name, "--out", str(pki_work)])
        PKI.mkdir(parents=True, exist_ok=True)
        os.chown(PKI, 0, 0)
        os.chmod(PKI, 0o700)
        install_pki_file(pki_work / "server.crt", PKI / "server.crt", 0o644)
        install_pki_file(pki_work / "server.key", PKI / "server.key", 0o600)
        install_pki_file(pki_work / "ca.crt", PKI / "gateway-ca.crt", 0o644)
        meta = {"schema": 1, "role": "gateway", "server_name": name,
                "listen_port": port, "allowed_dst_ports": allow_text,
                "peer_identity": "10.66.0.2"}
        public_meta = {"schema": 1, "server_name": name, "listen_port": port,
                       "allowed_dst_ports": allow_text, "peer_identity": "10.66.0.2"}
        write_atomic(META_FILE, (json.dumps(meta, sort_keys=True) + "\n").encode(), 0o600, refuse_existing=True)
        create_bundle(BUNDLE_FILE, {
            "gateway-ca.crt": (PKI / "gateway-ca.crt").read_bytes(),
            "gateway.json": (json.dumps(public_meta, sort_keys=True) + "\n").encode(),
        })
    finally:
        shutil.rmtree(work, ignore_errors=True)
    log("Gateway server certificate and public profile generated.")
    log("The endpoint is still stopped; no host routing, forwarding, NAT, or firewall rules were changed.")

def dialer_import_gateway():
    if manager_role() != "dialer":
        raise RuntimeError("import a Gateway profile from a Dialer panel")
    if Path("/etc/default/pqtunnel-client").exists():
        raise RuntimeError("an existing /etc/default/pqtunnel-client was found; refusing to overwrite it")
    for path in (PKI / "client.key", PKI / "client.crt", META_FILE):
        if path.exists():
            raise RuntimeError("existing Dialer setup artifacts detected; inspect them before retrying")
    work = Path(tempfile.mkdtemp(prefix="dialer-pki-", dir=str(STATE)))
    os.chmod(work, 0o700)
    try:
        imported = work / "import"
        meta = parse_profile("gateway", imported)
        name = meta["server_name"]
        port = meta["listen_port"]
        allow = meta.get("allowed_dst_ports", "")
        PKI.mkdir(parents=True, exist_ok=True)
        os.chown(PKI, 0, 0)
        os.chmod(PKI, 0o700)
        install_pki_file(imported / "gateway-ca.crt", PKI / "ca.crt", 0o644)
        local_pki = work / "pki"
        run_checked(["/usr/local/bin/pqtunnel-pki", "init", "--server-name", "dialer.local", "--out", str(local_pki)])
        run_checked(["/usr/local/bin/pqtunnel-pki", "issue-client", "--ip", "10.66.0.2", "--out", str(local_pki)])
        install_pki_file(local_pki / "ca.crt", PKI / "dialer-ca.crt", 0o644)
        install_pki_file(local_pki / "client-10_66_0_2.crt", PKI / "client.crt", 0o644)
        install_pki_file(local_pki / "client-10_66_0_2.key", PKI / "client.key", 0o600)
        app_cfg = (
            "# Managed by PQTunnel node setup; tunnel service remains stopped until explicitly started.\n"
            f"PQTUNNEL_SERVER={name}:{port}\n"
            f"PQTUNNEL_SERVER_NAME={name}\n"
            "PQTUNNEL_LOCAL_PREFIXES=10.66.0.2/32,fd42:7061:7475::2/128\n"
            "PQTUNNEL_REMOTE_PREFIXES=10.66.0.1/32,fd42:7061:7475::1/128\n"
            f"PQTUNNEL_ALLOWED_DST_PORTS={allow}\n"
        )
        write_atomic("/etc/default/pqtunnel-client", app_cfg.encode(), 0o600, refuse_existing=True)
        dialer_meta = {"schema": 1, "role": "dialer", "server_name": name,
                       "listen_port": port, "allowed_dst_ports": allow,
                       "peer_identity": "10.66.0.2"}
        write_atomic(META_FILE, (json.dumps(dialer_meta, sort_keys=True) + "\n").encode(), 0o600, refuse_existing=True)
        dialer_public = {"schema": 1, "peer_identity": "10.66.0.2",
                         "allowed_dst_ports": allow}
        create_bundle(BUNDLE_FILE, {
            "dialer-ca.crt": (PKI / "dialer-ca.crt").read_bytes(),
            "dialer.json": (json.dumps(dialer_public, sort_keys=True) + "\n").encode(),
        })
    finally:
        shutil.rmtree(work, ignore_errors=True)
    try:
        UPLOAD_FILE.unlink()
    except FileNotFoundError:
        pass
    run_checked(["systemctl", "daemon-reload"])
    log("Dialer configuration and local private keys generated. No private key was exported.")
    log("The tunnel is still stopped; no host routing, forwarding, NAT, or firewall rules were changed.")

def gateway_import_dialer():
    if manager_role() != "gateway":
        raise RuntimeError("import a Dialer profile from a Gateway panel")
    if not META_FILE.is_file() or not (PKI / "server.key").is_file() or not (PKI / "server.crt").is_file():
        raise RuntimeError("generate the Gateway public profile first")
    if Path("/etc/default/pqtunneld").exists():
        raise RuntimeError("an existing /etc/default/pqtunneld was found; refusing to overwrite it")
    work = Path(tempfile.mkdtemp(prefix="gateway-peer-", dir=str(STATE)))
    os.chmod(work, 0o700)
    try:
        imported = work / "import"
        peer = parse_profile("dialer", imported)
        meta = json.loads(META_FILE.read_text(encoding="utf-8"))
        if meta.get("schema") != 1 or meta.get("role") != "gateway":
            raise RuntimeError("saved Gateway profile metadata is invalid")
        if peer.get("allowed_dst_ports", "") != meta.get("allowed_dst_ports", ""):
            raise RuntimeError("port allowlists differ; regenerate the Dialer profile from the current Gateway profile")
        if peer.get("peer_identity") != "10.66.0.2":
            raise RuntimeError("Dialer peer identity is not the expected tunnel identity")
        install_pki_file(imported / "dialer-ca.crt", PKI / "dialer-ca.crt", 0o644)
        port = meta["listen_port"]
        allow = meta.get("allowed_dst_ports", "")
        app_cfg = (
            "# Managed by PQTunnel node setup; tunnel service remains stopped until explicitly started.\n"
            f"PQTUNNEL_LISTEN=0.0.0.0:{port}\n"
            "PQTUNNEL_TLS_CERT=/etc/pqtunnel/pki/server.crt\n"
            "PQTUNNEL_TLS_KEY=/etc/pqtunnel/pki/server.key\n"
            "PQTUNNEL_CLIENT_CA=/etc/pqtunnel/pki/dialer-ca.crt\n"
            "PQTUNNEL_MAX_CLIENTS=1\n"
            "PQTUNNEL_PEER_PREFIXES=10.66.0.2/32,fd42:7061:7475::2/128\n"
            "PQTUNNEL_LOCAL_PREFIXES=10.66.0.1/32,fd42:7061:7475::1/128\n"
            "PQTUNNEL_PEER_NAME=10.66.0.2\n"
            f"PQTUNNEL_ALLOWED_DST_PORTS={allow}\n"
        )
        write_atomic("/etc/default/pqtunneld", app_cfg.encode(), 0o600, refuse_existing=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    try:
        UPLOAD_FILE.unlink()
    except FileNotFoundError:
        pass
    run_checked(["systemctl", "daemon-reload"])
    log("Gateway now trusts the Dialer public CA and local endpoint configuration is ready.")
    log("The service remains stopped; starting it does not apply host routes, forwarding, NAT, or firewall rules.")

def main():
    STATE.mkdir(parents=True, exist_ok=True)
    os.chown(STATE, 0, 0)
    os.chmod(STATE, 0o700)
    RAW_LOG.write_text("", encoding="utf-8")
    os.chown(RAW_LOG, 0, 0)
    os.chmod(RAW_LOG, 0o600)
    write_state("running")
    raw = os.environ.get("PQTUNNEL_NODE_SETUP_INPUT_B64", "")
    if not raw or not re.fullmatch(r"[A-Za-z0-9+/=]+", raw):
        raise RuntimeError("setup request is missing or invalid")
    req = json.loads(base64.b64decode(raw, validate=True).decode("utf-8"))
    if not isinstance(req, dict):
        raise RuntimeError("setup request format is invalid")
    operation = req.get("Operation", "")
    if operation == "gateway-init":
        gateway_init(req)
        write_state("waiting-for-peer")
    elif operation == "dialer-import-gateway":
        dialer_import_gateway()
        write_state("ready")
    elif operation == "gateway-import-dialer":
        gateway_import_dialer()
        write_state("ready")
    else:
        raise RuntimeError("unsupported node setup operation")
    LOG_FILE.write_text("\n".join(LOGS) + "\n", encoding="utf-8")
    os.chown(LOG_FILE, 0, 0)
    os.chmod(LOG_FILE, 0o600)
    print("\n".join(LOGS))
    return 0

try:
    rc = main()
except Exception as exc:
    clean_created()
    try:
        ENV_FILE.unlink()
    except FileNotFoundError:
        pass
    log("ERROR: " + str(exc))
    LOG_FILE.write_text("\n".join(LOGS) + "\n", encoding="utf-8")
    os.chown(LOG_FILE, 0, 0)
    os.chmod(LOG_FILE, 0o600)
    write_state("failed")
    print("Node setup failed: " + str(exc), file=sys.stderr)
    sys.exit(1)
finally:
    try:
        ENV_FILE.unlink()
    except FileNotFoundError:
        pass
sys.exit(rc)
