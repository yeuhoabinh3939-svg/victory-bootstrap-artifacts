"""Bounded, signed-gateway transport primitives. No shell, network or credentials.

The caller must verify its root-owned config, signature, identity and live lease
before receive(). This module does not grant authority or provision accounts.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import time

MAGIC = b"VDEV1\n"
MAX_HEADER = 65536
MAX_PACKET = 2 * 1024**2
MAX_FILES = 32
SFTP_COMMANDS = {"internal-sftp", "/usr/lib/openssh/sftp-server"}
PHASES = ("upload", "native", "install", "discovery", "health")


class Stop(Exception):
    def __init__(self, code):
        if not re.fullmatch(r"[A-Z0-9_]{1,80}", code):
            code = "UNCLASSIFIED_STOP"
        self.code = code
        super().__init__(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def loads(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise Stop("DUPLICATE_JSON_KEY")
            out[key] = value
        return out
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise Stop("INVALID_JSON") from None


def canonical_subsystem(command):
    # OpenSSH assembles subsystem executable + one space + its arguments.
    # Only trailing horizontal whitespace is accepted, never arguments/shell.
    if not isinstance(command, str) or len(command) > 128 or any(c in command for c in "\r\n\x00"):
        raise Stop("FIXED_COMMAND_ONLY")
    value = command.rstrip(" \t")
    if value not in SFTP_COMMANDS:
        raise Stop("FIXED_COMMAND_ONLY")
    return "sftp"


def command_metadata(command):
    raw = command.encode("utf-8", errors="replace")
    kind = command if command in {"deploy-v1", "receipt-v1", "health-v1"} else "rejected"
    if kind == "rejected":
        try:
            kind = canonical_subsystem(command)
        except Stop:
            pass
    return {"request_type": kind, "original_command_bytes": len(raw), "original_command_sha256": sha(raw)}


def manifest(data):
    if not isinstance(data, dict) or set(data) != {"files"} or not isinstance(data["files"], dict):
        raise Stop("MANIFEST_SCHEMA")
    entries = data["files"]
    if not 1 <= len(entries) <= MAX_FILES:
        raise Stop("MEMBER_COUNT")
    total = 0
    for name, pin in entries.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}", name):
            raise Stop("BASENAME_REQUIRED")
        if not isinstance(pin, dict) or set(pin) != {"bytes", "sha256"}:
            raise Stop("MEMBER_SCHEMA")
        if type(pin["bytes"]) is not int or not 0 < pin["bytes"] <= MAX_PACKET:
            raise Stop("MEMBER_BOUND")
        if not isinstance(pin["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]):
            raise Stop("MEMBER_HASH_SCHEMA")
        total += pin["bytes"]
    if total > MAX_PACKET:
        raise Stop("TOTAL_BOUND")
    return data


def read_exact(stream, length):
    parts = bytearray()
    while len(parts) < length:
        chunk = stream.read(length - len(parts))
        if not chunk:
            raise Stop("TRUNCATED_FRAME")
        parts.extend(chunk)
    return bytes(parts)


def encode(envelope, files):
    header = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    if len(header) > MAX_HEADER:
        raise Stop("HEADER_BOUND")
    expected = manifest(envelope["manifest"])["files"]
    if set(files) != set(expected):
        raise Stop("EXACT_PACKET_SET")
    for name, pin in expected.items():
        if len(files[name]) != pin["bytes"] or sha(files[name]) != pin["sha256"]:
            raise Stop("LOCAL_PACKET_HASH")
    return MAGIC + struct.pack(">I", len(header)) + header + b"".join(files[name] for name in sorted(files))


def header(stream):
    if read_exact(stream, len(MAGIC)) != MAGIC:
        raise Stop("FRAME_MAGIC")
    length = struct.unpack(">I", read_exact(stream, 4))[0]
    if not 1 <= length <= MAX_HEADER:
        raise Stop("HEADER_BOUND")
    data = loads(read_exact(stream, length))
    if not isinstance(data, dict) or set(data) != {"document", "signature", "manifest"}:
        raise Stop("ENVELOPE_SCHEMA")
    if not isinstance(data["document"], str) or not isinstance(data["signature"], str):
        raise Stop("SIGNATURE_SCHEMA")
    if len(data["document"].encode()) > 32768 or len(data["signature"].encode()) > 8192:
        raise Stop("SIGNATURE_BOUND")
    manifest(data["manifest"])
    return data


def body(stream, data):
    # Read/hash the entire bounded payload before any filesystem write.
    result = {}
    for name, pin in sorted(data["manifest"]["files"].items()):
        raw = read_exact(stream, pin["bytes"])
        if sha(raw) != pin["sha256"]:
            raise Stop("PAYLOAD_HASH")
        result[name] = raw
    if stream.read(1):
        raise Stop("TRAILING_FRAME_DATA")
    return result


def sync_directory(path):
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_new(path, raw, mode=0o600):
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise Stop("DURABLE_READBACK")
    sync_directory(path.parent)


def safe_directory(path, uid=None):
    path = Path(path)
    for current in (path, *path.parents):
        meta = current.lstat()
        if not stat.S_ISDIR(meta.st_mode) or stat.S_ISLNK(meta.st_mode):
            raise Stop("UNSAFE_DIRECTORY")
        if uid is not None and (meta.st_uid not in (0, uid) or meta.st_mode & 0o022):
            raise Stop("DIRECTORY_AUTHORITY")


def verify_packet(path, data, uid=None):
    path = Path(path)
    safe_directory(path, uid)
    pins = manifest(data)["files"]
    if {p.name for p in path.iterdir()} != set(pins):
        raise Stop("EXACT_PACKET_SET")
    for name, pin in pins.items():
        item = path / name
        meta = item.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size != pin["bytes"]:
            raise Stop("PACKET_METADATA")
        if uid is not None and (meta.st_uid != uid or meta.st_mode & 0o022):
            raise Stop("PACKET_AUTHORITY")
        descriptor = os.open(item, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                actual = sha(stream.read(MAX_PACKET + 1))
        finally:
            os.close(descriptor)
        if actual != pin["sha256"]:
            raise Stop("PACKET_HASH")
    return {"files_verified": len(pins), "manifest_sha256": sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())}


def commit_packet(path, data, contents, uid=None):
    path = Path(path)
    if path.exists() or path.is_symlink():
        return verify_packet(path, data, uid)
    safe_directory(path.parent, uid)
    path.mkdir(mode=0o700)
    sync_directory(path.parent)
    # Any interrupted write is guarded by the caller's STARTED checkpoint.
    for name in sorted(manifest(data)["files"]):
        durable_new(path / name, contents[name])
    return verify_packet(path, data, uid)


def lease(document, config, now=None):
    now = time.time() if now is None else now
    data = loads(document)
    required = {"id", "actor", "uid", "packet_sha256", "not_before", "expires", "action", "model_calls", "paid_usd"}
    if not isinstance(data, dict) or set(data) != required:
        raise Stop("LEASE_SCHEMA")
    if not isinstance(data["id"], str) or not re.fullmatch(r"[0-9a-f]{64}", data["id"]):
        raise Stop("LEASE_ID")
    if data["actor"] != config["actor"] or type(data["uid"]) is not int or data["uid"] != config["uid"]:
        raise Stop("LEASE_ACTOR")
    if data["packet_sha256"] != config["packet_sha256"] or data["action"] not in {"deploy-v1", "receipt-v1", "health-v1"}:
        raise Stop("LEASE_SCOPE")
    if type(data["not_before"]) is not int or type(data["expires"]) is not int or not data["not_before"] <= now < data["expires"] - 30:
        raise Stop("LEASE_EXPIRED")
    if not 60 <= data["expires"] - data["not_before"] <= 3000 or data["expires"] > config["access_expires"]:
        raise Stop("LEASE_TIME_BOUND")
    if type(data["model_calls"]) is not int or data["model_calls"] != 0 or type(data["paid_usd"]) is not int or data["paid_usd"] != 0:
        raise Stop("NO_MODEL_OR_COST_AUTHORITY")
    return data


def sanitize(raw):
    # Never record a credential-bearing line or private-key block. Hashes/counts
    # refer to original bytes; retained text is explicitly sanitized/truncated.
    text = raw.decode("utf-8", errors="replace")
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)", "[REDACTED_PRIVATE_KEY]", text, flags=re.S)
    lines = []
    for line in text.splitlines():
        if re.search(r"password|passphrase|authorization|credential|secret|token|private.?key|(?:gh[pousr]_\w{20})|(?:sk-\w{20})", line, re.I):
            line = "[REDACTED_CREDENTIAL_LINE]"
        lines.append(line)
    return "\n".join(lines)[:16384]


def process_evidence(returncode, stderr, request, cleanup="NOT_REQUESTED"):
    return {"returncode": returncode, "stderr_bytes": len(stderr), "stderr_sha256": sha(stderr),
            "stderr_sanitized": sanitize(stderr), "stderr_truncated": len(stderr) > 16384,
            "cleanup": cleanup, **command_metadata(request)}


class Checkpoints:
    def __init__(self, root):
        self.root = Path(root)
        safe_directory(self.root)

    def read(self, name):
        path = self.root / name
        if path.is_symlink():
            raise Stop("CHECKPOINT_SYMLINK")
        meta = path.lstat()
        allowed_links = 2 if name == "FINAL.json" else 1
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != allowed_links or meta.st_size > 65536:
            raise Stop("CHECKPOINT_METADATA")
        if name == "FINAL.json":
            pending = (self.root / "FINAL.pending.json").lstat()
            if stat.S_ISLNK(pending.st_mode) or (pending.st_dev, pending.st_ino) != (meta.st_dev, meta.st_ino):
                raise Stop("FINAL_ATOMIC_COMMIT_BINDING")
            if self.read("CLOSED.json").get("grant_closed") is not True:
                raise Stop("FINAL_CLOSE_MARKER_REQUIRED")
        return loads(path.read_bytes())

    def put(self, name, value):
        durable_new(self.root / name, (json.dumps(value, sort_keys=True) + "\n").encode())

    def phase(self, name, operation, verify):
        if name not in PHASES:
            raise Stop("PHASE_NOT_ALLOWED")
        if (self.root / "CLOSED.json").exists() and not (self.root / "FINAL.json").exists():
            raise Stop("CLOSED_WITHOUT_FINAL_UNKNOWN_NO_RETRY")
        if (self.root / "FAILED.json").exists():
            raise Stop("FAILED_RUN_NO_RETRY")
        done = self.root / (name + ".done.json")
        if done.exists() or done.is_symlink():
            result = self.read(done.name)
            if not verify(result):
                raise Stop("CHECKPOINT_RESULT_DRIFT")
            return result
        started = self.root / (name + ".started.json")
        if started.exists() or started.is_symlink():
            raise Stop("INCOMPLETE_PHASE_UNKNOWN_NO_RETRY")
        self.put(started.name, {"phase": name, "state": "STARTED", "time": time.time()})
        try:
            result = operation()
            if not verify(result):
                raise Stop("PHASE_POSTCONDITION_FAILED")
            self.put(done.name, result)
            return result
        except Exception as error:
            code = error.code if isinstance(error, Stop) else "PHASE_OS_OR_PROCESS_ERROR"
            self.put("FAILED.json", {"phase": name, "state": "FAILED", "gateway_code": code, "retry": False})
            raise

    def final(self, context):
        values = {name: self.read(name + ".done.json") for name in PHASES}
        if (self.root / "FAILED.json").exists():
            raise Stop("FAILED_RUN_NO_PASS")
        if set(context) != {"run_id", "actor", "uid", "packet_sha256", "grant_expires"}:
            raise Stop("FINAL_CONTEXT_BINDING")
        result = {"status": "DEPLOYMENT_PASS", **context, "phases": values, "production": False, "model_calls": 0}
        self.put("FINAL.pending.json", result)
        self.put("CLOSED.json", {"run_id": context["run_id"], "grant_closed": True})
        # Exclusive publication is the final fallible filesystem operation.
        os.link(self.root / "FINAL.pending.json", self.root / "FINAL.json")
        return result
