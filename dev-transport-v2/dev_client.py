"""Explicitly authorized single-attempt DEV exec upload. Defaults to offline check.

No root access, retry, remote shell, model, key export or secret in logs.
Existing OpenSSH performs private-key operations; Python never opens the key.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dev_transport as wire


def final_receipt(result, grant):
    if (result.get("status") != "DEPLOYMENT_PASS" or result.get("run_id") != grant["id"]
            or result.get("actor") != grant["actor"] or result.get("uid") != grant["uid"]
            or result.get("packet_sha256") != grant["packet_sha256"] or result.get("grant_expires") != grant["expires"]
            or result.get("production") is not False or result.get("model_calls") != 0):
        raise wire.Stop("FINAL_RECEIPT_BINDING")
    phases = result.get("phases", {})
    if set(phases) != set(wire.PHASES):
        raise wire.Stop("FINAL_PHASE_SET")
    if phases["upload"].get("manifest_sha256") != grant["packet_sha256"]:
        raise wire.Stop("UPLOAD_RECEIPT_MANIFEST_BINDING")
    native = phases["native"]
    if (native.get("status") != "NATIVE_FIXTURE_PASS" or native.get("tests_run") != 8 or native.get("failures") != 0
            or native.get("errors") != 0 or native.get("real_uid") != grant["uid"]):
        raise wire.Stop("NATIVE_RECEIPT_NOT_ACCEPTED")
    for phase in ("install", "health"):
        if phases[phase].get("files_verified") != 83 or phases[phase].get("links_verified") != 7:
            raise wire.Stop("S1_HEALTH_NOT_ACCEPTED")
    discovery = phases["discovery"]
    if (discovery.get("status") != "DISCOVERY_PASS_RUNTIME_ACTIVE_UNVERIFIED" or discovery.get("fresh_sessions") != 2
            or discovery.get("non_inference_cli_processes") != 3 or discovery.get("model_calls") != 0):
        raise wire.Stop("DISCOVERY_RECEIPT_NOT_ACCEPTED")
    return result


def options(config):
    if not config["actor"].replace("-", "").isalnum() or not 1 <= int(config["port"]) <= 65535:
        raise wire.Stop("SSH_DESTINATION_SCHEMA")
    return ["-F", "NUL" if os.name == "nt" else "/dev/null", "-T", "-i", config["private_key_path"],
            "-p", str(config["port"]), "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + config["host_pin_file"],
            "-o", "GlobalKnownHostsFile=" + ("NUL" if os.name == "nt" else "/dev/null"),
            "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "UpdateHostKeys=no", "-o", "ConnectionAttempts=1",
            "-o", "ConnectTimeout=20", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "CertificateFile=none", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
            "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "PermitLocalCommand=no"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--run-directory", type=Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    config = wire.loads(args.config.read_bytes())
    for name in ("ssh_path", "ssh_keygen_path"):
        if wire.sha(Path(config[name]).read_bytes()) != config[name + "_sha256"]:
            raise wire.Stop("LOCAL_OPENSSH_PIN")
    if wire.sha(Path(config["host_pin_file"]).read_bytes()) != config["host_pin_sha256"]:
        raise wire.Stop("LOCAL_HOST_PIN_CHANGED")
    packet = wire.loads((args.packet / "TRANSPORT_MANIFEST.json").read_bytes())
    canonical = json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
    if wire.sha(canonical) != config["packet_sha256"]:
        raise wire.Stop("LOCAL_PACKET_MANIFEST_PIN")
    wire.verify_packet(args.packet / "files", packet)
    contents = {name: (args.packet / "files" / name).read_bytes() for name in packet["files"]}
    if not args.execute:
        print(json.dumps({"status": "OFFLINE_CLIENT_PINS_PASS_NO_SSH", "packet_sha256": config["packet_sha256"]}))
        return
    if not config.get("dev_execution_authorized") or not config.get("gateway_native_install_verified"):
        raise wire.Stop("VALID_DEV_AUTHORITY_AND_INSTALLED_GATEWAY_REQUIRED")
    if args.run_directory is None:
        raise wire.Stop("EXCLUSIVE_RUN_DIRECTORY_REQUIRED")
    now = int(time.time())
    if now + 300 >= config["access_expires"]:
        raise wire.Stop("ACCOUNT_OR_KEY_EXPIRY_RESERVE")
    args.run_directory.mkdir(mode=0o700)
    journal = wire.Checkpoints(args.run_directory)
    grant = {"id": wire.sha(os.urandom(32)), "actor": config["actor"], "uid": config["uid"],
             "packet_sha256": config["packet_sha256"], "not_before": now, "expires": min(now + 1200, config["access_expires"]),
             "action": "deploy-v1", "model_calls": 0, "paid_usd": 0}
    document = json.dumps(grant, sort_keys=True, separators=(",", ":")) + "\n"
    path = args.run_directory / "lease.json"
    wire.durable_new(path, document.encode())
    signed = subprocess.run([config["ssh_keygen_path"], "-Y", "sign", "-f", config["private_key_path"], "-n",
                             "victory-dev-deploy-v2", str(path)], stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    journal.put("signing.process.json", wire.process_evidence(signed.returncode, signed.stderr, "deploy-v1"))
    if signed.returncode:
        raise wire.Stop("LOCAL_SIGNING_FAILED_NO_SSH_NO_RETRY")
    frame = wire.encode({"document": document, "signature": Path(str(path) + ".sig").read_text(), "manifest": packet}, contents)
    journal.put("CONNECTION_STARTED.json", {"connections_consumed": 1, "retry": False, "run_id": grant["id"]})
    try:
        result = subprocess.run([config["ssh_path"], *options(config), config["actor"] + "@" + config["host"], "deploy-v1"],
                                input=frame, capture_output=True, timeout=270)
    except subprocess.TimeoutExpired as error:
        journal.put("FAILED.json", {"gateway_code": "SSH_TIMEOUT_UNKNOWN_NO_RETRY",
                                   "process": wire.process_evidence(None, error.stderr or b"", "deploy-v1")})
        raise wire.Stop("SSH_TIMEOUT_UNKNOWN_NO_RETRY") from None
    journal.put("ssh.process.json", wire.process_evidence(result.returncode, result.stderr, "deploy-v1"))
    wire.durable_new(args.run_directory / "ssh.stdout", result.stdout)
    if result.returncode:
        journal.put("FAILED.json", {"gateway_code": "SSH_NONZERO_STOP_NO_RETRY", "returncode": result.returncode})
        raise wire.Stop("SSH_NONZERO_STOP_NO_RETRY")
    try:
        accepted = final_receipt(wire.loads(result.stdout), grant)
    except Exception:
        journal.put("FAILED.json", {"gateway_code": "FINAL_RECEIPT_NOT_ACCEPTED_NO_RETRY"})
        raise
    journal.put("FINAL_VERIFIED.json", accepted)
    print(json.dumps({"status": "DEPLOYMENT_PASS", "run_id": grant["id"], "production": False, "model_calls": 0}))


if __name__ == "__main__":
    main()
