import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import dev_transport as wire
import dev_client


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.files = {"one.txt": b"one", "two.bin": b"\x00\x01\xff"}
        self.manifest = {"files": {n: {"bytes": len(b), "sha256": wire.sha(b)} for n, b in self.files.items()}}
        self.envelope = {"document": "signed document fixture", "signature": "public signature fixture", "manifest": self.manifest}

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_round_trip_binary(self):
        stream = io.BytesIO(wire.encode(self.envelope, self.files))
        value = wire.header(stream)
        self.assertEqual(wire.body(stream, value), self.files)

    def test_all_truncations_rejected(self):
        frame = wire.encode(self.envelope, self.files)
        for length in range(len(frame)):
            stream = io.BytesIO(frame[:length])
            with self.assertRaises(wire.Stop):
                wire.body(stream, wire.header(stream))

    def test_trailing_bytes_rejected(self):
        stream = io.BytesIO(wire.encode(self.envelope, self.files) + b"x")
        with self.assertRaisesRegex(wire.Stop, "TRAILING_FRAME_DATA"):
            wire.body(stream, wire.header(stream))

    def test_corrupt_body_rejected_before_write(self):
        frame = bytearray(wire.encode(self.envelope, self.files)); frame[-1] ^= 1
        stream = io.BytesIO(frame)
        with self.assertRaisesRegex(wire.Stop, "PAYLOAD_HASH"):
            wire.body(stream, wire.header(stream))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_header_length_bound(self):
        with self.assertRaisesRegex(wire.Stop, "HEADER_BOUND"):
            wire.header(io.BytesIO(wire.MAGIC + struct.pack(">I", wire.MAX_HEADER + 1)))

    def test_duplicate_json_key(self):
        with self.assertRaisesRegex(wire.Stop, "DUPLICATE_JSON_KEY"):
            wire.loads(b'{"files":{},"files":{}}')

    def test_path_and_shell_names_rejected(self):
        for name in ("../x", "/tmp/x", "x/y", "x\\y", ".", "..", "x\nx", "$(id)", "x:y"):
            with self.assertRaises(wire.Stop):
                wire.manifest({"files": {name: {"bytes": 1, "sha256": "a" * 64}}})

    def test_bool_and_oversized_member_rejected(self):
        for size in (True, 0, -1, wire.MAX_PACKET + 1):
            with self.assertRaises(wire.Stop):
                wire.manifest({"files": {"x": {"bytes": size, "sha256": "a" * 64}}})

    def test_packet_limit(self):
        with self.assertRaisesRegex(wire.Stop, "TOTAL_BOUND"):
            wire.manifest({"files": {n: {"bytes": wire.MAX_PACKET, "sha256": "a" * 64} for n in ("x", "y")}})

    def test_commit_durable_idempotent(self):
        target = self.root / "packet"
        first = wire.commit_packet(target, self.manifest, self.files)
        times = {p.name: p.stat().st_mtime_ns for p in target.iterdir()}
        self.assertEqual(wire.commit_packet(target, self.manifest, self.files), first)
        self.assertEqual(times, {p.name: p.stat().st_mtime_ns for p in target.iterdir()})

    def test_modified_existing_packet_stops(self):
        target = self.root / "packet"; wire.commit_packet(target, self.manifest, self.files)
        (target / "one.txt").write_bytes(b"bad")
        with self.assertRaisesRegex(wire.Stop, "PACKET_HASH"):
            wire.commit_packet(target, self.manifest, self.files)
        self.assertEqual((target / "one.txt").read_bytes(), b"bad")

    def test_unknown_existing_file_preserved(self):
        target = self.root / "packet"; wire.commit_packet(target, self.manifest, self.files)
        (target / "owner").write_bytes(b"preserve")
        with self.assertRaisesRegex(wire.Stop, "EXACT_PACKET_SET"):
            wire.verify_packet(target, self.manifest)
        self.assertEqual((target / "owner").read_bytes(), b"preserve")

    @unittest.skipIf(os.name == "nt", "Real Linux symlink fixture runs in CI")
    def test_symlink_never_followed(self):
        outside = self.root / "outside"; outside.mkdir()
        (self.root / "packet").symlink_to(outside)
        with self.assertRaisesRegex(wire.Stop, "UNSAFE_DIRECTORY"):
            wire.commit_packet(self.root / "packet", self.manifest, self.files)
        self.assertFalse(list(outside.iterdir()))

    @unittest.skipIf(os.name == "nt", "Real Linux hardlink fixture runs in CI")
    def test_shared_packet_file_rejected(self):
        target = self.root / "packet"; wire.commit_packet(target, self.manifest, self.files)
        os.link(target / "one.txt", self.root / "shared")
        with self.assertRaisesRegex(wire.Stop, "PACKET_METADATA"):
            wire.verify_packet(target, self.manifest)

    def test_legacy_exact_command_rejects_openssh_trailing_space(self):
        import legacy_policy
        original = "/usr/lib/openssh/sftp-server "
        with self.assertRaisesRegex(ValueError, "FIXED_COMMAND_ONLY"):
            legacy_policy.command(original)
        self.assertEqual(wire.canonical_subsystem(original), "sftp")

    def test_canonical_subsystem_keeps_security_boundary(self):
        for original in ("/usr/lib/openssh/sftp-server;id", "internal-sftp -d /", "internal-sftp\n", " internal-sftp", "sh", "sftp", "internal-sftp\x00"):
            with self.assertRaises(wire.Stop):
                wire.canonical_subsystem(original)

    def test_request_logging_never_records_raw_command(self):
        value = wire.command_metadata("password=fixture-secret")
        self.assertEqual(value["request_type"], "rejected")
        self.assertNotIn("fixture-secret", json.dumps(value))

    def test_stderr_sanitization(self):
        raw = b"normal error\npassword=fixture\nAuthorization: Bearer example\n-----BEGIN OPENSSH PRIVATE KEY-----\nexample\n-----END OPENSSH PRIVATE KEY-----\nnormal tail"
        value = wire.process_evidence(255, raw, "deploy-v1")
        self.assertEqual(value["stderr_sha256"], wire.sha(raw))
        self.assertEqual(value["stderr_bytes"], len(raw))
        self.assertNotIn("fixture", value["stderr_sanitized"])
        self.assertNotIn("example", value["stderr_sanitized"])
        self.assertIn("normal tail", value["stderr_sanitized"])

    def test_stderr_bounded(self):
        value = wire.process_evidence(-9, b"a" * 100000, "deploy-v1")
        self.assertEqual(len(value["stderr_sanitized"]), 16384)
        self.assertTrue(value["stderr_truncated"])

    def test_lease_boundaries_and_denied_cost(self):
        config = {"actor": "fixture", "uid": 1000, "packet_sha256": "a" * 64, "access_expires": 2000}
        data = {"id": "b" * 64, "actor": "fixture", "uid": 1000, "packet_sha256": "a" * 64,
                "not_before": 1000, "expires": 1300, "action": "deploy-v1", "model_calls": 0, "paid_usd": 0}
        self.assertEqual(wire.lease(json.dumps(data), config, 1050), data)
        for change, now in (({}, 999), ({}, 1270), ({"paid_usd": 1}, 1050), ({"uid": True}, 1050),
                            ({"model_calls": True}, 1050), ({"expires": 5000}, 1050), ({"action": "shell"}, 1050),
                            ({"packet_sha256": "c" * 64}, 1050)):
            with self.assertRaises(wire.Stop):
                wire.lease(json.dumps({**data, **change}), config, now)


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.journal = wire.Checkpoints(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_done_phase_is_verified_and_not_reexecuted(self):
        calls = []
        function = lambda: calls.append(1) or {"verified": True}
        self.journal.phase("upload", function, lambda r: r == {"verified": True})
        self.journal.phase("upload", function, lambda r: r == {"verified": True})
        self.assertEqual(calls, [1])

    def test_completed_output_drift_stops(self):
        self.journal.phase("upload", lambda: {}, lambda r: True)
        with self.assertRaisesRegex(wire.Stop, "CHECKPOINT_RESULT_DRIFT"):
            self.journal.phase("upload", lambda: self.fail("must not retry"), lambda r: False)

    def test_started_without_done_is_unknown_no_retry(self):
        self.journal.put("native.started.json", {"state": "STARTED"})
        with self.assertRaisesRegex(wire.Stop, "INCOMPLETE_PHASE_UNKNOWN_NO_RETRY"):
            self.journal.phase("native", lambda: self.fail("must not retry"), lambda r: True)

    def test_phase_failure_closes_run(self):
        def fail():
            raise wire.Stop("INJECTED_FAILURE")
        with self.assertRaises(wire.Stop):
            self.journal.phase("upload", fail, lambda r: True)
        self.assertEqual(self.journal.read("FAILED.json")["gateway_code"], "INJECTED_FAILURE")
        with self.assertRaisesRegex(wire.Stop, "FAILED_RUN_NO_RETRY"):
            self.journal.phase("upload", lambda: self.fail("must not retry"), lambda r: True)

    def test_no_final_before_every_phase_complete(self):
        with self.assertRaises(FileNotFoundError):
            self.journal.final({})
        self.assertFalse((self.root / "FINAL.json").exists())

    def test_injected_failure_at_each_phase_never_publishes_pass(self):
        for index, failing in enumerate(wire.PHASES):
            case = self.root / str(index); case.mkdir(); journal = wire.Checkpoints(case)
            for name in wire.PHASES[:index]:
                journal.phase(name, lambda: {}, lambda r: True)
            with self.assertRaises(wire.Stop):
                journal.phase(failing, lambda: (_ for _ in ()).throw(wire.Stop("INJECTED_FAILURE")), lambda r: True)
            self.assertFalse((case / "FINAL.json").exists())

    def test_close_failure_never_publishes_final(self):
        for name in wire.PHASES:
            self.journal.phase(name, lambda: {}, lambda r: True)
        context = {"run_id": "a" * 64, "actor": "fixture", "uid": 1000, "packet_sha256": "b" * 64, "grant_expires": 2000}
        original = wire.durable_new
        def failure(path, raw, mode=0o600):
            if Path(path).name == "CLOSED.json":
                raise OSError("INJECTED_CLOSE_FAILURE")
            return original(path, raw, mode)
        with patch.object(wire, "durable_new", side_effect=failure):
            with self.assertRaises(OSError):
                self.journal.final(context)
        self.assertFalse((self.root / "FINAL.json").exists())

    def test_closed_without_final_blocks_resume(self):
        self.journal.put("CLOSED.json", {"grant_closed": True})
        with self.assertRaisesRegex(wire.Stop, "CLOSED_WITHOUT_FINAL_UNKNOWN_NO_RETRY"):
            self.journal.phase("upload", lambda: self.fail("must not run"), lambda r: True)

    @unittest.skipIf(os.name == "nt", "Atomic POSIX commit verified in Linux CI")
    def test_atomic_final_is_bound_to_pending_and_close(self):
        for name in wire.PHASES:
            self.journal.phase(name, lambda: {}, lambda r: True)
        context = {"run_id": "a" * 64, "actor": "fixture", "uid": 1000, "packet_sha256": "b" * 64, "grant_expires": 2000}
        result = self.journal.final(context)
        self.assertEqual(self.journal.read("FINAL.json"), result)
        with self.assertRaises(FileExistsError):
            self.journal.final(context)


class FinalReceiptTests(unittest.TestCase):
    def test_status_word_alone_never_accepted(self):
        with self.assertRaises(wire.Stop):
            dev_client.final_receipt({"status": "DEPLOYMENT_PASS"}, {"id": "a" * 64})

    def test_client_options_disable_password_agent_and_forwarding(self):
        values = dev_client.options({"actor": "fixture", "port": 2222, "private_key_path": "not-opened", "host_pin_file": "public-pin"})
        for value in ("IdentityAgent=none", "BatchMode=yes", "StrictHostKeyChecking=yes", "ConnectionAttempts=1", "ForwardAgent=no", "PasswordAuthentication=no"):
            self.assertIn(value, values)


if __name__ == "__main__":
    unittest.main(verbosity=2)
