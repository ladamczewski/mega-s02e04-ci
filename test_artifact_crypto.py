import json
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import remote_worker as worker

from artifact_crypto import decrypt_artifact, encrypt_artifact


class ArtifactTests(unittest.TestCase):
    def test_round_trip_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key, cert = root / "key.pem", root / "cert.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                            "-nodes", "-subj", "/CN=test", "-days", "1",
                            "-keyout", str(key), "-out", str(cert)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proof = json.dumps({"receipt": "secret-proof", "result": "private"}).encode()
            (root / "job-1-result.json").write_bytes(proof)
            (root / "audit.jsonl").write_text("private audit")
            (root / "excluded.txt").write_text("not included")
            target = root / "artifact.cms"
            encrypt_artifact(root, cert, target)
            encrypted = target.read_bytes()
            self.assertNotIn(b"secret-proof", encrypted)
            files = decrypt_artifact(encrypted, key)
            self.assertEqual(files["job-1-result.json"], proof)
            self.assertEqual(set(files), {"job-1-result.json", "audit.jsonl"})
            encrypt_artifact(root, cert, target)
            checkpoint = target.read_bytes()
            self.assertEqual(decrypt_artifact(checkpoint, key), files)
            with self.assertRaises(ValueError):
                encrypt_artifact(root, root / "missing.pem", target)
            self.assertEqual(target.read_bytes(), checkpoint)
            self.assertEqual(list(root.glob(".cms-*")), [])
            for damaged in (encrypted[:-1], encrypted[:-1] + bytes([encrypted[-1] ^ 1])):
                with self.assertRaises(ValueError):
                    decrypt_artifact(damaged, key)
            # Exercise the entrypoint/export boundary without running the job.
            (root / "artifact-recipient.pem").write_bytes(cert.read_bytes())
            stdout = io.StringIO()
            with patch.object(worker, "ROOT", root), patch.object(worker, "OUTPUT", root), \
                    patch.object(worker, "main", side_effect=RuntimeError("private-raw-receipt")), \
                    contextlib.redirect_stdout(stdout):
                self.assertEqual(worker.run(), 1)
            self.assertNotIn("private-raw-receipt", stdout.getvalue())
            exported = decrypt_artifact((root / "encrypted/job-1.cms").read_bytes(), key)
            self.assertIn(b"private-raw-receipt", exported["audit.jsonl"])

    def test_encryption_failure_creates_no_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "out.cms"
            with self.assertRaises(ValueError):
                encrypt_artifact(root, root / "missing.pem", target)
            self.assertFalse(target.exists())

    def test_entrypoint_never_falls_back_to_plaintext(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(worker, "ROOT", root), patch.object(worker, "OUTPUT", root), \
                    patch.object(worker, "main", return_value=None), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(worker.run(), 1)
            self.assertFalse((root / "encrypted/job-1.cms").exists())
