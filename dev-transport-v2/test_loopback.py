"""Run once as root on an ephemeral Linux CI VM. Never target a remote host.

Only listens on 127.0.0.1; the config/keys/account are disposable test artifacts.
No existing sshd configuration, firewall, service or credential is modified.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dev_transport as wire

if os.geteuid() != 0 or sys.platform != "linux":
    raise SystemExit("EPHEMERAL_CI_LINUX_ROOT_ONLY")
home = Path(tempfile.mkdtemp(prefix="vdev-ci-", dir="/run"))
home.chmod(0o755)
username = "vdev" + home.name.rsplit("-", 1)[-1][:8]
created, server = False, None
evidence = {"scope": "ISOLATED_LOOPBACK_NOT_VPS", "steps": [], "model_calls": 0}


def command(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=40, **kwargs)


def required(args, **kwargs):
    result = command(args, **kwargs)
    if result.returncode:
        raise RuntimeError("FIXTURE_COMMAND_FAILED: " + args[0] + ": " + wire.sanitize(result.stderr))
    return result


try:
    try:
        pwd.getpwnam(username)
    except KeyError:
        pass
    else:
        raise RuntimeError("FIXTURE_ACCOUNT_ALREADY_EXISTS_STOP")
    required(["/usr/sbin/useradd", "--no-create-home", "--user-group", "--home-dir", str(home / "home"), "--shell", "/bin/sh", "--password", "x", username])
    created = True
    account = pwd.getpwnam(username)
    (home / "home").mkdir(mode=0o755)
    for name in ("logs", "inbox", "outside"):
        path = home / name; path.mkdir(mode=0o700); os.chown(path, account.pw_uid, account.pw_gid)
    for name in ("host", "client"):
        required(["/usr/bin/ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(home / name)])
    public = (home / "client.pub").read_text().strip()
    (home / "allowed_signers").write_text("victory-owner " + public + "\n")
    here = Path(__file__).resolve().parent
    entry = home / "code"; shutil.copytree(here, entry)
    for path in entry.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    entry.chmod(0o755)
    config_path = home / "config.json"
    config = {"root": str(home), "mode": "legacy", "actor": username, "uid": account.pw_uid,
              "packet_sha256": "a" * 64, "access_expires": int(time.time()) + 1000}
    def update(mode):
        config["mode"] = mode
        config_path.write_text(json.dumps(config)); config_path.chmod(0o644)
    update("legacy")
    forced = '/usr/bin/python3 -I -B ' + str(entry / "loopback_gateway.py") + ' ' + str(config_path)
    (home / "authorized_keys").write_text('restrict,command="' + forced + '" ' + public + '\n')
    (home / "authorized_keys").chmod(0o644)
    with socket.socket() as bind:
        bind.bind(("127.0.0.1", 0)); port = bind.getsockname()[1]
    (home / "known_hosts").write_text("[127.0.0.1]:" + str(port) + " " + (home / "host.pub").read_text())
    (home / "sshd.conf").write_text("\n".join([
        "Port " + str(port), "ListenAddress 127.0.0.1", "HostKey " + str(home / "host"),
        "PidFile " + str(home / "sshd.pid"), "AuthorizedKeysFile " + str(home / "authorized_keys"),
        "UsePAM no", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
        "PermitRootLogin no", "StrictModes yes", "AllowUsers " + username, "PermitUserEnvironment no",
        "AllowAgentForwarding no", "AllowTcpForwarding no", "PermitTunnel no", "X11Forwarding no", "PermitTTY no",
        "LogLevel VERBOSE", "Subsystem sftp /usr/lib/openssh/sftp-server", ""]))
    Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
    required(["/usr/sbin/sshd", "-t", "-f", str(home / "sshd.conf")])
    server = subprocess.Popen(["/usr/sbin/sshd", "-D", "-E", str(home / "sshd.log"), "-f", str(home / "sshd.conf")])
    time.sleep(0.3)
    if server.poll() is not None:
        raise RuntimeError("ISOLATED_SSHD_START_FAILED_NO_RETRY")
    options = ["-F", "/dev/null", "-i", str(home / "client"), "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
               "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(home / "known_hosts"),
               "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1"]
    target = username + "@127.0.0.1"
    sftp = ["/usr/bin/sftp", *options, "-P", str(port), "-b", str(home / "batch"), target]
    payload = b"binary\x00fixture\xff" * 1024
    (home / "local.bin").write_bytes(payload)
    (home / "batch").write_text('put "' + str(home / "local.bin") + '" "payload.bin"\nget "payload.bin" "' + str(home / "readback.bin") + '"\n')
    legacy = command(sftp)
    rows = [json.loads(p.read_bytes()) for p in (home / "logs").glob("*.json")]
    assert legacy.returncode == 255, (legacy.returncode, wire.sanitize(legacy.stderr))
    assert rows[-1]["gateway_code"] == "FIXED_COMMAND_ONLY", rows
    assert rows[-1]["subsystem_original_repr"].endswith(" '") or rows[-1]["subsystem_original_repr"].endswith(' "'), rows
    evidence["steps"].append({"step": "LEGACY_EXACT_MATCH_REPRODUCED", "client_returncode": legacy.returncode,
                              "client_stderr": wire.sanitize(legacy.stderr), "gateway": rows[-1]})
    update("fixed")
    fixed = required(sftp)
    assert (home / "readback.bin").read_bytes() == payload
    required(["/usr/sbin/runuser", "-u", username, "--", "/usr/bin/test", "-w", str(home / "outside")])
    (home / "batch").write_text('-put "' + str(home / "local.bin") + '" "' + str(home / "outside/escape.bin") + '"\n')
    denied = required(sftp)
    assert not (home / "outside/escape.bin").exists()
    assert b"Permission denied" in denied.stderr, wire.sanitize(denied.stderr)
    evidence["steps"].append({"step": "FIXED_SFTP_REAL_PUT_GET_LANDLOCK_DENIAL_PASS", "payload_sha256": wire.sha(payload)})
    update("frame")
    files = {"a.bin": payload, "manifest.txt": b"fixture"}
    pins = {"files": {n: {"bytes": len(b), "sha256": wire.sha(b)} for n, b in files.items()}}
    config["packet_sha256"] = wire.sha(json.dumps(pins, sort_keys=True, separators=(",", ":")).encode())
    update("frame")
    lease = {"id": "b" * 64, "actor": username, "uid": account.pw_uid, "packet_sha256": config["packet_sha256"],
             "not_before": int(time.time()) - 1, "expires": int(time.time()) + 300, "action": "deploy-v1", "model_calls": 0, "paid_usd": 0}
    raw = (json.dumps(lease, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (home / "document").write_bytes(raw)
    required(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(home / "client"), "-n", "victory-dev-deploy-v2", str(home / "document")])
    envelope = {"document": raw.decode(), "signature": (home / "document.sig").read_text(), "manifest": pins}
    frame = wire.encode(envelope, files)
    ssh = ["/usr/bin/ssh", *options, "-T", "-p", str(port), target]
    first = required([*ssh, "deploy-v1"], input=frame)
    assert json.loads(first.stdout)["status"] == "FIXTURE_PACKET_VERIFIED_NOT_DEPLOYMENT_PASS"
    times = {p.name: p.stat().st_mtime_ns for p in (home / "frame-packet").iterdir()}
    second = required([*ssh, "deploy-v1"], input=frame)
    assert times == {p.name: p.stat().st_mtime_ns for p in (home / "frame-packet").iterdir()}
    invalid = dict(envelope); invalid["document"] = raw.decode().replace('"model_calls":0', '"model_calls":1')
    bad = command([*ssh, "deploy-v1"], input=wire.encode(invalid, files))
    assert bad.returncode != 0 and b"OWNER_SIGNATURE_DENIED" in bad.stderr
    arbitrary = command([*ssh, "id"], input=b"")
    assert arbitrary.returncode != 0 and b"FIXED_EXEC_ACTION_ONLY" in arbitrary.stderr
    evidence["steps"].append({"step": "SIGNED_EXEC_UPLOAD_REAL_SSH_IDEMPOTENCE_TAMPER_SHELL_DENIAL_PASS",
                              "uid": account.pw_uid, "files_verified": len(files)})
    # Actual kernel socket denial, without preventing child cleanup.
    probe = "import sys,socket;sys.path.insert(0,sys.argv[1]);from dev_gateway import socket_denial;socket_denial();\ntry: socket.socket()\nexcept PermissionError: print('DENIED')\nelse: raise SystemExit(1)"
    check = required(["/usr/bin/python3", "-I", "-B", "-c", probe, str(entry)])
    assert check.stdout.strip() == b"DENIED"
    evidence["steps"].append({"step": "REAL_KERNEL_SOCKET_DENIAL_PASS"})
    evidence["status"] = "LOOPBACK_PROTOCOL_PASS_NOT_VPS_DEPLOYMENT"
except Exception as error:
    evidence["status"] = "LOOPBACK_FIXTURE_FAIL_STOP_NO_RETRY"
    evidence["error_type"] = type(error).__name__
    evidence["error"] = wire.sanitize(str(error).encode())
    if (home / "sshd.log").exists():
        evidence["isolated_sshd_log"] = wire.sanitize((home / "sshd.log").read_bytes())
    raise
finally:
    if server is not None:
        server.terminate(); server.wait(timeout=10)
    if created:
        assert pwd.getpwnam(username).pw_dir == str(home / "home")
        required(["/usr/sbin/userdel", username])
    # Keep no ephemeral private key in CI logs/artifacts. Test data is ephemeral.
    output = Path(__file__).resolve().parent / "LOOPBACK_RESULT.json"
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))
    shutil.rmtree(home)
