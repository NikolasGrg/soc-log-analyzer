import tempfile
import unittest
from pathlib import Path

from log_analyzer import analyze_logs


class TestLogAnalyzer(unittest.TestCase):
    def analyze_text(self, text):
        """Create a temporary log file and analyze its contents."""
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "test.log"
            log_file.write_text(text, encoding="utf-8")
            return analyze_logs(log_file)

    def test_failed_login(self):
        findings = self.analyze_text(
            "Failed login attempt from 192.0.2.10\n"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "AUTH_FAILURE")
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(
            findings[0]["category"], "Authentication Failure"
        )
        self.assertEqual(findings[0]["line"], 1)
        self.assertEqual(findings[0]["evidence"], "Failed login")

    def test_operational_error(self):
        findings = self.analyze_text("Error connecting to server\n")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SERVICE_ERROR")
        self.assertEqual(findings[0]["severity"], "LOW")

    def test_benign_messages(self):
        findings = self.analyze_text(
            "User login successful\n"
            "Backup failed\n"
            "Service running errorless\n"
        )

        self.assertEqual(findings, [])

    def test_case_insensitive_matching(self):
        findings = self.analyze_text("LOGIN FAILED for demo user\n")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "AUTH_FAILURE")

    def test_blank_lines_preserve_line_numbers(self):
        findings = self.analyze_text("\n\nInvalid password\n")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 3)

    def test_multiple_rules_can_match_one_line(self):
        findings = self.analyze_text("Error: failed login\n")

        self.assertEqual(
            {finding["rule_id"] for finding in findings},
            {"AUTH_FAILURE", "SERVICE_ERROR"},
        )
        self.assertEqual(len(findings), 2)

    def test_empty_file(self):
        self.assertEqual(self.analyze_text(""), [])


if __name__ == "__main__":
    unittest.main()
