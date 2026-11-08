"""Root-configured nonroot forced command for one signed bounded DEV deployment.

No provisioning, shell, sudo, model invocation, downloads or SSH policy edits.
Production selection is impossible. Native/install/discovery sources are pinned
by the administrator and passed as data, never chosen by the SSH client.
"""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dev_transport as wire


def trusted(path, uid=0):
    for node in (Path(path), *Path(path).parents):
        value = node.lstat()
        if stat.S_ISLNK(value.st_mode) or value.st_uid not in (0, uid) or value.st_mode & 0o022:
            raise wire.Stop("ROOT_CONFIG_OR_SOURCE_AUTHORITY")


def socket_denial():
    # Linux x86_64; deny creation/use of sockets and io_uring, preserving ordinary
    # child-process cleanup. No credential is supplied to discovery in any case.
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise wire.Stop("LINUX_X86_64_REQUIRED")
    class Ins(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]
    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(Ins))]
    rows = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, 0x80000000),
            (0x20, 0, 0, 0), (0x35, 0, 1, 0x40000000), (0x06, 0, 0, 0x00050001)]
    for number in (41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 53, 288, 299, 307, 425, 426, 427):
        rows.extend([(0x15, 0, 1, number), (0x06, 0, 0, 0x00050001)])
    rows.append((0x06, 0, 0, 0x7FFF0000))
    array = (Ins * len(rows))(*(Ins(*row) for row in rows))
    program = Program(len(array), array)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise wire.Stop("NATIVE_NETWORK_DENIAL_FAILED")


def identity(config):
    import pwd
    import resource
    if sys.platform != "linux" or os.geteuid() == 0:
        raise wire.Stop("LINUX_NONROOT_ONLY")
    account = pwd.getpwuid(os.geteuid())
    if (account.pw_name != config["actor"] or account.pw_uid != config["uid"] or account.pw_gid != config["gid"]
            or account.pw_dir != config["home"] or set(os.getgroups()) != {account.pw_gid}):
        raise wire.Stop("DEDICATED_IDENTITY_REQUIRED")
    home = Path(config["home"])
    trusted(home)
    if not home.is_mount() or os.access(home, os.W_OK):
        raise wire.Stop("ROOT_OWNED_MOUNTED_HOME_REQUIRED")
    group = "user-" + str(account.pw_uid) + ".slice"
    if group not in Path("/proc/self/cgroup").read_text():
        raise wire.Stop("DEV_SLICE_REQUIRED")
    cg = Path("/sys/fs/cgroup/user.slice") / group
    memory, tasks = (cg / "memory.max").read_text().strip(), (cg / "pids.max").read_text().strip()
    quota, period = (cg / "cpu.max").read_text().split()
    if not (memory.isdigit() and int(memory) <= 1024**3 and tasks.isdigit() and int(tasks) <= 64
            and quota.isdigit() and int(quota) <= int(period)):
        raise wire.Stop("AGGREGATE_LIMITS_REQUIRED")
    for number, bound in ((resource.RLIMIT_CPU, 120), (resource.RLIMIT_AS, 512 * 1024**2),
                          (resource.RLIMIT_FSIZE, 4 * 1024**2), (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 64)):
        soft, hard = resource.getrlimit(number)
        resource.setrlimit(number, (bound if soft == resource.RLIM_INFINITY else min(soft, bound), hard))


def signature(envelope, config, state):
    signers = Path(config["allowed_signers"])
    trusted(signers)
    temp = state / ("signature-" + str(os.getpid()) + "-" + str(time.time_ns()) + ".pubsig")
    wire.durable_new(temp, envelope["signature"].encode())
    result = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", "victory-owner",
                             "-n", "victory-dev-deploy-v2", "-s", str(temp)],
                            input=envelope["document"].encode(), capture_output=True, timeout=10,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    if result.returncode:
        raise wire.Stop("OWNER_SIGNATURE_DENIED")


def load_pinned(path, pin):
    path = Path(path)
    trusted(path)
    if wire.sha(path.read_bytes()) != pin:
        raise wire.Stop("ROOT_SCRIPT_PIN")
    return path


def run_pinned(path, pin, args, env, log, label, timeout):
    load_pinned(path, pin)
    try:
        result = subprocess.run(["/usr/bin/python3", "-I", "-B", str(path), *args], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout, env=env, preexec_fn=socket_denial)
    except subprocess.TimeoutExpired as error:
        log.put(label + ".process.json", wire.process_evidence(None, error.stderr or b"", "deploy-v1", "CHILD_TIMEOUT_STOP"))
        raise wire.Stop("PHASE_TIMEOUT_NO_RETRY") from None
    log.put(label + ".process.json", wire.process_evidence(result.returncode, result.stderr, "deploy-v1"))
    if len(result.stdout) > 65536 or len(result.stderr) > 1024**2:
        raise wire.Stop("PHASE_OUTPUT_BOUND")
    log.put(label + ".stdout.json", {"sha256": wire.sha(result.stdout), "bytes": len(result.stdout),
                                    "sanitized": wire.sanitize(result.stdout)})
    if result.returncode:
        raise wire.Stop("PHASE_PROCESS_NONZERO")
    return wire.loads(result.stdout)


def verify_install(config, packet):
    spec = importlib.util.spec_from_file_location("frozen_s1", packet / "install_skills.py")
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    binding = wire.loads((packet / "PAYLOAD_MANIFEST.json").read_bytes())
    layout = app.plan(binding)
    uid = config["uid"]
    root = Path(layout["release_root"])
    if {p.relative_to(root).as_posix() for p in root.rglob("*") if not p.is_dir()} != set(binding["files"]):
        raise wire.Stop("INSTALLED_EXACT_SET_CHANGED")
    for name, pin in binding["files"].items():
        path = Path(layout["release_root"]) / name
        trusted(path, uid)
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or wire.sha(path.read_bytes()) != pin["sha256"]:
            raise wire.Stop("INSTALLED_MEMBER_CHANGED")
    for name, target in layout["discovery_links"].items():
        path = Path(name)
        trusted(path.parent, uid)
        if not path.is_symlink() or path.lstat().st_uid != uid or os.readlink(path) != target:
            raise wire.Stop("SKILL_LINK_CHANGED")
    if len(binding["files"]) != 83 or len(layout["discovery_links"]) != 7:
        raise wire.Stop("S1_EXPECTED_FILE_LINK_COUNT")
    return {"files_verified": 83, "links_verified": 7, "release_root": layout["release_root"]}


def install(config, packet, grant):
    # Packet bytes were verified before importing this frozen, approved installer.
    spec = importlib.util.spec_from_file_location("frozen_s1", packet / "install_skills.py")
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    binding = wire.loads((packet / "PAYLOAD_MANIFEST.json").read_bytes())
    files = app.check_payload((packet / "skills-payload.tar").read_bytes(), binding)
    layout = app.plan(binding)
    if Path(layout["release_root"]).exists() or Path(layout["receipt_path"]).exists():
        receipt = Path(layout["receipt_path"])
        trusted(receipt, config["uid"])
        prior = wire.loads(receipt.read_bytes())
        if (prior.get("status") != "FILES_INSTALLED_NOT_CODEX_DISCOVERY_OR_ACTIVE_PASS"
                or prior.get("uid") != config["uid"] or prior.get("payload_sha256") != binding["payload_sha256"]):
            raise wire.Stop("EXISTING_INSTALL_RECONCILIATION_REQUIRED")
        return verify_install(config, packet)
    app_grant = {"owner_approved": True, "action": "install", "packet_sha256": config["s1_manifest_sha256"],
                 "not_before_epoch": grant["not_before"], "until_epoch": grant["expires"],
                 "account": config["actor"], "home": config["home"], "maximum_model_calls": 0,
                 "paid_usd_authorized": 0, "verified_uid": config["uid"], "verified_gid": config["gid"],
                 "dev_account_inventory_verified": True, "codex_inventory_verified": True}
    grant_path = packet.parent / "s1-grant.json"
    wire.durable_new(grant_path, json.dumps(app_grant).encode())
    app.authorize(grant_path, binding, "install")
    import resource
    previous = {number: resource.getrlimit(number) for number in (resource.RLIMIT_CPU, resource.RLIMIT_AS, resource.RLIMIT_FSIZE)}
    try:
        result = app.apply(binding, files, app_grant)
    finally:
        # The frozen installer lowers soft limits. Restore only the already
        # granted gateway ceilings before starting the bounded discovery child.
        for number, limits in previous.items():
            resource.setrlimit(number, limits)
    if result.get("status") != "FILES_INSTALLED_NOT_CODEX_DISCOVERY_OR_ACTIVE_PASS":
        raise wire.Stop("S1_INSTALL_RECEIPT")
    return verify_install(config, packet)


def main():
    signal.alarm(240)
    config_path = Path(__file__).resolve().with_name("GATEWAY_CONFIG.json")
    trusted(config_path)
    config = wire.loads(config_path.read_bytes())
    identity(config)
    for path, pin in config["root_source_pins"].items():
        load_pinned(path, pin)
    request = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if request not in {"deploy-v1", "receipt-v1", "health-v1"}:
        raise wire.Stop("FIXED_EXEC_ACTION_ONLY")
    state = Path(config["state"])
    trusted(state, config["uid"])
    envelope = wire.header(sys.stdin.buffer)
    signature(envelope, config, state)
    grant = wire.lease(envelope["document"], config)
    if grant["action"] != request:
        raise wire.Stop("REQUEST_ACTION_BINDING")
    canonical = json.dumps(envelope["manifest"], sort_keys=True, separators=(",", ":")).encode()
    if wire.sha(canonical) != config["packet_sha256"]:
        raise wire.Stop("ROOT_PACKET_MANIFEST_PIN")
    contents = wire.body(sys.stdin.buffer, envelope)
    run = state / grant["id"]
    if not run.exists():
        if request != "deploy-v1":
            raise wire.Stop("READONLY_RUN_ABSENT")
        run.mkdir(mode=0o700)
        wire.sync_directory(state)
    trusted(run, config["uid"])
    import fcntl
    lock = os.open(run / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock)
        raise wire.Stop("RUN_ALREADY_IN_PROGRESS_NO_RETRY") from None
    # Descriptor remains open until process exit, covering every phase/receipt.
    journal = wire.Checkpoints(run)
    packet = run / "packet"
    if request == "receipt-v1":
        for name in ("FINAL.json", "FAILED.json"):
            if (run / name).exists():
                print(json.dumps(journal.read(name)))
                return
        raise wire.Stop("RUN_INCOMPLETE_UNKNOWN")
    if request == "health-v1":
        wire.verify_packet(packet, envelope["manifest"], config["uid"])
        print(json.dumps(verify_install(config, packet)))
        return
    journal.phase("upload", lambda: wire.commit_packet(packet, envelope["manifest"], contents, config["uid"]),
                  lambda result: result == wire.verify_packet(packet, envelope["manifest"], config["uid"]))
    env = {"PATH": "/usr/bin:/bin", "HOME": config["home"], "LANG": "C.UTF-8", "VICTORY_P2_PACKET": str(packet),
           "SUPERPOWERS_DISABLE_TELEMETRY": "1", "VICTORY_DISCOVERY_RECEIPT": str(run / "discovery.actual.json")}
    def gate():
        wire.lease(envelope["document"], config)
        wire.verify_packet(packet, envelope["manifest"], config["uid"])
    gate()
    native = config["native"]
    journal.phase("native", lambda: run_pinned(native["path"], native["sha256"], [], env, journal, "native", 75),
                  lambda result: result.get("status") == "NATIVE_FIXTURE_PASS" and result.get("tests_run") == 8
                  and result.get("real_uid") == config["uid"] and result.get("failures") == 0 and result.get("errors") == 0)
    gate()
    journal.phase("install", lambda: install(config, packet, grant), lambda result: result == verify_install(config, packet))
    gate()
    discovery = config["discovery"]
    journal.phase("discovery", lambda: run_pinned(discovery["path"], discovery["sha256"], [], env, journal, "discovery", 75),
                  lambda result: result.get("status") == "DISCOVERY_PASS_RUNTIME_ACTIVE_UNVERIFIED"
                  and result.get("fresh_sessions") == 2 and result.get("non_inference_cli_processes") == 3
                  and result.get("model_calls") == 0)
    gate()
    journal.phase("health", lambda: verify_install(config, packet), lambda result: result == verify_install(config, packet))
    if (run / "FINAL.json").exists():
        print(json.dumps(journal.read("FINAL.json")))
    else:
        print(json.dumps(journal.final({"run_id": grant["id"], "actor": config["actor"], "uid": config["uid"],
                                        "packet_sha256": config["packet_sha256"], "grant_expires": grant["expires"]})))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = error.code if isinstance(error, wire.Stop) else "GATEWAY_OS_OR_PROCESS_ERROR"
        print(json.dumps({"status": "FAIL_OR_UNKNOWN_NO_RETRY", "gateway_code": code,
                          "request": wire.command_metadata(os.environ.get("SSH_ORIGINAL_COMMAND", "")),
                          "cleanup": "NO_ACCOUNT_KEY_MOUNT_OR_SERVICE_ACTION_PRESERVE_EVIDENCE", "model_calls": 0}), file=sys.stderr)
        raise SystemExit(1)
