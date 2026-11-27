import io
import json
import os
import signal
import unittest
from unittest.mock import patch

import remote_worker as worker


class FakeResponse(io.BytesIO):
    def __init__(self, content, content_type="application/json", status=200):
        super().__init__(content)
        self.status = status
        self.headers = {"Content-Type": content_type}


class WorkerTests(unittest.TestCase):
    def test_model_is_pinned_to_approved_free_tier_candidate(self):
        self.assertEqual(worker.MODEL, "gemini-3.6-flash")

    def test_json_rpc(self):
        response = FakeResponse(b'{"id":1,"result":{"ok":true}}')
        self.assertEqual(worker.parse_rpc(response, 1)["result"], {"ok": True})

    def test_sse_ignores_notifications(self):
        response = FakeResponse(
            b'data: {"method":"notifications/message"}\n\n'
            b'data: {"id":7,"result":{"ok":true}}\n\n', "text/event-stream")
        self.assertEqual(worker.parse_rpc(response, 7)["result"], {"ok": True})

    def test_accepted_notification_has_no_body(self):
        self.assertEqual(worker.parse_rpc(FakeResponse(b"", status=202), None), {})

    def test_receipt_is_preserved(self):
        proof = {"status": "accepted", "receipt": "EXACT.opaque.proof", "result": "The record"}
        wrapped = {"content": [{"type": "text", "text": json.dumps(proof)}]}
        self.assertEqual(worker.extract_proof(wrapped), proof)

    def test_rejected_proof_is_not_success(self):
        self.assertIsNone(worker.extract_proof({"structuredContent": {
            "accepted": False, "receipt": "not-valid", "result": "not-accepted"}}))

    def test_nested_json_log_masks_proof(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key", "JOB_MCP_URL": "https://hq.mega.dev/mcp/job/test"}):
            encoded = json.dumps(worker.redact({"content": [{"text": json.dumps({
                "receipt": "do-not-log", "ticket": "secret-ticket", "result": "test-key"})}]}))
        for secret in ("do-not-log", "secret-ticket", "test-key"):
            self.assertNotIn(secret, encoded)

    def test_invalid_submissions(self):
        good = {"status": "accepted", "receipt": "proof", "result": "record"}
        for changes in ({"status": "rejected"}, {"status": "unknown"},
                        {"status": None}, {"receipt": ""}, {"result": ""},
                        {"accepted": False}, {"ok": False}):
            with self.subTest(changes=changes):
                self.assertIsNone(worker.extract_proof({"structuredContent": good | changes}))
        self.assertIsNone(worker.extract_proof({"isError": True, "structuredContent": good}))

    def test_http_error_does_not_expose_body(self):
        import urllib.error
        error = urllib.error.HTTPError("https://example.test", 400, "bad", {},
                                       io.BytesIO(b"receipt=do-not-expose"))
        with patch.object(worker.OPENER, "open", side_effect=error), patch.object(worker, "audit"):
            with self.assertRaises(worker.WorkerError) as caught:
                worker.open_request(None)
        self.assertNotIn("do-not-expose", str(caught.exception))

    def test_gemini_transient_failures_have_bounded_backoff(self):
        import urllib.error
        def unavailable():
            return urllib.error.HTTPError("https://example.test", 503, "busy", {}, io.BytesIO(b"busy"))
        response = FakeResponse(b'{}')
        with patch.object(worker.OPENER, "open", side_effect=[unavailable(), unavailable(), unavailable(), response]) as opened, \
                patch.object(worker, "audit"), patch.object(worker.time, "sleep") as sleep:
            self.assertIs(worker.open_request(None, retry_delays=(10, 25, 60)), response)
        self.assertEqual(opened.call_count, 4)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [10, 25, 60])

    def test_quota_failure_never_retries(self):
        import urllib.error
        error = urllib.error.HTTPError("https://example.test", 429, "quota", {}, io.BytesIO(b"quota"))
        with patch.object(worker.OPENER, "open", side_effect=error) as opened, \
                patch.object(worker, "audit"), patch.object(worker.time, "sleep") as sleep:
            with self.assertRaises(worker.WorkerError):
                worker.open_request(None, retry_delays=(10, 25, 60))
        self.assertEqual(opened.call_count, 1)
        sleep.assert_not_called()

    def test_course_network_failure_keeps_single_retry(self):
        import urllib.error
        with patch.object(worker.OPENER, "open", side_effect=urllib.error.URLError("offline")) as opened, \
                patch.object(worker, "audit") as audit, patch.object(worker.time, "sleep") as sleep:
            with self.assertRaises(worker.WorkerError):
                worker.open_request(None)
        self.assertEqual(opened.call_count, 2)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [3])
        self.assertEqual(audit.call_count, 2)

    def test_deadline_exports_audit_and_restores_signal_handlers(self):
        import contextlib
        previous = signal.getsignal(signal.SIGALRM)
        with patch.object(worker, "main", side_effect=lambda: signal.raise_signal(signal.SIGALRM)), \
                patch.object(worker, "audit") as audit, \
                patch.object(worker, "encrypt_artifact") as encrypt, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(worker.run(), 1)
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        self.assertEqual(audit.call_args.args[0], "worker-failure")
        self.assertIn("time limit", audit.call_args.args[1]["message"])
        encrypt.assert_called_once()

    def test_credentials_reject_untrusted_host(self):
        with self.assertRaises(worker.WorkerError):
            worker.MCP("https://untrusted.example/mcp/job/test")

    def test_no_local_execution(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}):
            with self.assertRaisesRegex(worker.WorkerError, "must run remotely"):
                worker.main()


if __name__ == "__main__":
    unittest.main()
