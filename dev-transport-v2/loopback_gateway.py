"""CI-only forced gateway; disposable nonroot identity and ephemeral signing key.

Never installed on the VPS. Exercises legacy and corrected SFTP plus the signed
exec framing against a real isolated sshd. Does not claim deployment acceptance.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dev_transport as wire

child_mode = sys.argv[1] == "--sftp-child"
config_path = Path(sys.argv[2] if child_mode else sys.argv[1])
config = json.loads(config_path.read_bytes())
root = Path(config["root"])
request = os.environ.get("SSH_ORIGINAL_COMMAND", "")
record = {**wire.command_metadata(request), "uid": os.geteuid(), "mode": config["mode"]}


def save(value):
    name = root / "logs" / (str(time.time_ns()) + ".json")
    wire.durable_new(name, json.dumps(value).encode())


if child_mode:
    stage = "LANDLOCK_IMPORT"
    try:
        spec = importlib.util.spec_from_file_location("landlock", Path(__file__).with_name("landlock.py"))
        sandbox = importlib.util.module_from_spec(spec); spec.loader.exec_module(sandbox)
        stage = "LANDLOCK_RESTRICT"
        abi = sandbox.restrict(root / "inbox")
        os.write(2, (json.dumps({"stage": "LANDLOCK_APPLIED", "abi": abi, "uid": os.geteuid()}) + "\n").encode())
        stage = "SFTP_EXEC"
        os.execve("/usr/lib/openssh/sftp-server", ["sftp-server", "-e", "-l", "INFO", "-u", "0077", "-d", str(root / "inbox"),
                  "-p", "realpath,stat,lstat,open,write,close,fstat,read,opendir,readdir,limits,expand-path,fsync"],
                  {"PATH": "/usr/bin:/bin", "HOME": str(root / "home"), "LANG": "C.UTF-8"})
    except Exception as error:
        os.write(2, (json.dumps({"stage": stage, "error_type": type(error).__name__, "errno": getattr(error, "errno", None),
                                "code": str(error) if isinstance(error, ValueError) else "CHILD_OS_FAILURE"}) + "\n").encode())
        raise SystemExit(1)


try:
    if os.geteuid() == 0:
        raise wire.Stop("FIXTURE_NONROOT_REQUIRED")
    if config["mode"] in ("legacy", "fixed"):
        # Persist this known subsystem string only in this isolated CI fixture.
        record["subsystem_original_repr"] = repr(request)
        if config["mode"] == "legacy":
            import legacy_policy
            try:
                if legacy_policy.command(request) != "sftp":
                    raise wire.Stop("FIXED_COMMAND_ONLY")
            except ValueError:
                raise wire.Stop("FIXED_COMMAND_ONLY") from None
        else:
            wire.canonical_subsystem(request)
        child = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--sftp-child", str(config_path)],
                               stdin=sys.stdin.buffer, stdout=sys.stdout.buffer, stderr=subprocess.PIPE, timeout=40)
        record.update(wire.process_evidence(child.returncode, child.stderr, request))
        save(record)
        raise SystemExit(child.returncode)
    if request != "deploy-v1":
        raise wire.Stop("FIXED_EXEC_ACTION_ONLY")
    envelope = wire.header(sys.stdin.buffer)
    signature = root / "logs" / (str(time.time_ns()) + ".pubsig")
    wire.durable_new(signature, envelope["signature"].encode())
    check = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(root / "allowed_signers"),
                            "-I", "victory-owner", "-n", "victory-dev-deploy-v2", "-s", str(signature)],
                           input=envelope["document"].encode(), capture_output=True, timeout=10)
    if check.returncode:
        raise wire.Stop("OWNER_SIGNATURE_DENIED")
    grant = wire.lease(envelope["document"], config)
    if grant["action"] != request:
        raise wire.Stop("REQUEST_ACTION_BINDING")
    manifest_raw = json.dumps(envelope["manifest"], sort_keys=True, separators=(",", ":")).encode()
    if wire.sha(manifest_raw) != config["packet_sha256"]:
        raise wire.Stop("ROOT_PACKET_MANIFEST_PIN")
    contents = wire.body(sys.stdin.buffer, envelope)
    result = wire.commit_packet(root / "frame/packet", envelope["manifest"], contents, os.geteuid())
    record.update(returncode=0, status="FIXTURE_PACKET_VERIFIED_NOT_DEPLOYMENT_PASS", packet=result)
    save(record)
    print(json.dumps(record))
except Exception as error:
    code = error.code if isinstance(error, wire.Stop) else "FIXTURE_OS_OR_PROCESS_ERROR"
    record.update(returncode=1, gateway_code=code, error_type=type(error).__name__, errno=getattr(error, "errno", None), cleanup="PRESERVE_FIXTURE_NO_RETRY")
    save(record)
    print(json.dumps({"gateway_code": code}), file=sys.stderr)
    raise SystemExit(1)
