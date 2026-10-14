"""Offline header-check regressions; no HTTP requests."""
import json
from pathlib import Path
import runpy
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/header_check.py'
GOOD = {'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff'}


class HeaderTests(unittest.TestCase):
    def flags(self, changes=None, final_url='https://example.com/'):
        # Run the CLI, not a reimplementation; also works against the old script.
        import tempfile
        from urllib.request import Request
        headers = dict(GOOD)
        headers.update(changes or {})
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def geturl(self): return final_url
        response = Response()
        response.headers = headers
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'headers.json'
            with patch('urllib.request.urlopen', return_value=response) as request, patch('sys.argv', ['check', 'https://example.com/', str(out)]):
                runpy.run_path(str(SCRIPT), run_name='__main__')
            self.assertEqual(request.call_count, 1)
            return {f['key'] for f in json.loads(out.read_text())['results']}

    def test_valid_headers(self):
        self.assertEqual(self.flags(), set())

    def test_nosniff_wrong_value(self):
        self.assertIn('x-content-type-options', self.flags({'X-Content-Type-Options': 'none'}))

    def test_hsts_zero_disables_policy(self):
        self.assertIn('strict-transport-security', self.flags({'Strict-Transport-Security': 'max-age=0'}))

    def test_hsts_without_age(self):
        self.assertIn('strict-transport-security', self.flags({'Strict-Transport-Security': 'includeSubDomains'}))

    def test_csp_report_uri_is_not_frame_policy(self):
        self.assertIn('clickjacking', self.flags({'Content-Security-Policy': 'report-uri https://example.com/frame-ancestors'}))

    def test_wildcard_ancestors(self):
        self.assertIn('clickjacking', self.flags({'Content-Security-Policy': 'frame-ancestors *'}))

    def test_empty_ancestors(self):
        self.assertIn('clickjacking', self.flags({'Content-Security-Policy': 'frame-ancestors; default-src none'}))

    def test_invalid_xfo_does_not_pass(self):
        self.assertIn('clickjacking', self.flags({'Content-Security-Policy': 'default-src self', 'X-Frame-Options': 'ALLOW-FROM https://example.com'}))

    def test_valid_xfo(self):
        self.assertNotIn('clickjacking', self.flags({'Content-Security-Policy': 'default-src self', 'X-Frame-Options': 'sameorigin'}))

    def test_downgrade(self):
        self.assertIn('https-downgrade', self.flags(final_url='http://example.com/'))

    def test_trimmed_values_and_case(self):
        self.assertEqual(self.flags({'X-Content-Type-Options': ' NOSNIFF ', 'Strict-Transport-Security': 'MAX-AGE=100'}), set())


if __name__ == '__main__':
    unittest.main()
