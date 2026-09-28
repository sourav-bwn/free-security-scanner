import json
import os
import tempfile
import unittest
from unittest.mock import patch
from scripts import security_issues as s

FINDING = {"check_id": "python.lang.security.audit.eval-detected.eval-detected", "path": "app.py", "start": {"line": 4}, "extra": {"fingerprint": "abc", "message": "Avoid eval", "severity": "WARNING"}}

class TestIssues(unittest.TestCase):
    def test_anonymous_fingerprint_fallback(self):
        finding = {"check_id": "r", "path": "a", "start": {"line": 4}, "extra": {"fingerprint": "requires login"}}
        self.assertEqual(s.marker_for(finding), s.marker_for(finding))
        finding["start"]["line"] = 5
        self.assertNotEqual(s.marker_for(finding), s.marker_for({"check_id": "r", "path": "a", "start": {"line": 4}, "extra": {"fingerprint": "requires login"}}))

    def test_dedup_and_no_raw_source(self):
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json") as f:
            json.dump({"results": [FINDING, FINDING], "errors": []}, f)
            f.flush()
            calls = []
            def fake_request(method, path, payload=None):
                calls.append((method, path, payload))
                return [] if method == "GET" else {"html_url": "https://github.com/sourav-bwn/demo/issues/1"}
            env = {"GITHUB_REPOSITORY": "sourav-bwn/demo", "GITHUB_RUN_ID": "1", "GITHUB_SHA": "a" * 40}
            with patch.dict(os.environ, env), patch.object(s, "request", side_effect=fake_request), patch.object(s.sys, "argv", ["script", f.name]):
                s.main()
            posts = [c for c in calls if c[0] == "POST"]
            self.assertEqual(len(posts), 1)
            self.assertIn(s.marker_for(FINDING), posts[0][2]["body"])
            self.assertIn("possible security issue", posts[0][2]["body"])

    def test_closed_issue_prevents_duplicate(self):
        finding = FINDING
        marker = s.marker_for(finding)
        with patch.object(s, "request", return_value=[{"body": marker + "\n", "state": "closed"}]):
            self.assertIn(marker, s.existing_markers("sourav-bwn/demo"))

    def test_scan_errors_stop_posts(self):
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json") as f:
            json.dump({"results": [FINDING], "errors": [{"message": "parse failure"}]}, f)
            f.flush()
            with patch.object(s, "request") as req, patch.object(s.sys, "argv", ["script", f.name]):
                with self.assertRaises(RuntimeError):
                    s.main()
                req.assert_not_called()

    def test_other_owner_rejected(self):
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json") as f:
            json.dump({"results": [FINDING], "errors": []}, f)
            f.flush()
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": "someone-else/demo"}), patch.object(s, "request") as req, patch.object(s.sys, "argv", ["script", f.name]):
                with self.assertRaises(ValueError):
                    s.main()
                req.assert_not_called()

if __name__ == "__main__":
    unittest.main()
