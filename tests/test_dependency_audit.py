"""Offline checks: never install packages, contact registries or open issues."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/dependency_audit.py'


class DependencyAuditTests(unittest.TestCase):
    def execute(self, files, responses, fails=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in files:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{}')
            report = root / 'report.json'
            report.write_text('{"results":["stale"]}')
            previous = os.getcwd()
            os.chdir(root)
            try:
                with patch('subprocess.run', side_effect=responses) as runner, patch('sys.argv', ['audit', str(report)]):
                    if fails:
                        with self.assertRaises(RuntimeError):
                            runpy.run_path(str(SCRIPT), run_name='__main__')
                        self.assertFalse(report.exists())
                        return runner.call_count
                    runpy.run_path(str(SCRIPT), run_name='__main__')
                return json.loads(report.read_text())['results']
            finally:
                os.chdir(previous)

    def result(self, code=0, data=None, raw=None):
        return subprocess.CompletedProcess([], code, raw if raw is not None else json.dumps(data), 'registry unavailable')

    def test_npm_failure_does_not_look_clean(self):
        self.execute(['package-lock.json'], [self.result(1, {'error': {'code': 'ENOTFOUND'}})], True)

    def test_invalid_json_fails_closed(self):
        self.execute(['package-lock.json'], [self.result(1, raw='not json')], True)

    def test_empty_json_is_not_a_successful_scan(self):
        self.execute(['package-lock.json'], [self.result(0, {})], True)

    def test_unexpected_exit_fails_even_with_valid_shape(self):
        self.execute(['package-lock.json'], [self.result(2, {'vulnerabilities': {}})], True)

    def test_npm_vulnerabilities_exit_one_is_valid(self):
        data = {'vulnerabilities': {'demo': {'severity': 'high', 'via': [{'title': 'Advisory'}], 'fixAvailable': True}}}
        findings = self.execute(['.project/package-lock.json'], [self.result(1, data)])
        self.assertEqual(findings[0]['path'], '.project/package-lock.json')
        self.assertEqual(findings[0]['severity'], 'HIGH')

    def test_pip_install_failure_stops_before_audit(self):
        count = self.execute(['requirements.txt'], [self.result(1, raw='')], True)
        self.assertEqual(count, 1)

    def test_pip_audit_failure_is_not_clean(self):
        self.execute(['requirements.txt'], [self.result(), self.result(1, {})], True)

    def test_skipped_python_dependency_fails_closed(self):
        self.execute(['requirements.txt'], [self.result(), self.result(0, {'dependencies': [{'name': 'local', 'skip_reason': 'not on PyPI'}]})], True)

    def test_valid_python_findings(self):
        data = {'dependencies': [{'name': 'demo', 'version': '1', 'vulns': [{'id': 'CVE-example', 'fix_versions': ['2']}]}]}
        findings = self.execute(['requirements.txt'], [self.result(), self.result(1, data)])
        self.assertEqual(findings[0]['key'], 'demo:CVE-example')

    def test_clean_audit_writes_empty_report(self):
        self.assertEqual(self.execute(['package-lock.json'], [self.result(0, {'vulnerabilities': {}})]), [])

    def test_ignored_directories_are_not_audited(self):
        self.assertEqual(self.execute(['node_modules/package-lock.json', '.scanner-tools/requirements.txt'], []), [])

    def test_partial_results_are_not_written(self):
        self.execute(['package-lock.json', 'requirements.txt'], [self.result(0, {'vulnerabilities': {}}), self.result(1, raw='')], True)


if __name__ == '__main__':
    unittest.main()
