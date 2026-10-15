import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "log_analyzer.py"


class TestCLI(unittest.TestCase):
    def run_cli(self, *args, cwd=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, args)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=cwd,
        )

    def test_default_sample_from_another_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_cli(cwd=directory)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Total findings: 3", result.stdout)

    def test_json_export(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            output = Path(directory) / "findings.json"
            source.write_text("Failed login\n", encoding="utf-8")

            result = self.run_cli(
                source, "--format", "json", "--output", output
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], 1)
            self.assertEqual(len(data["findings"]), 1)
            self.assertEqual(
                data["findings"][0]["rule_id"], "AUTH_FAILURE"
            )

    def test_csv_preserves_commas_and_quotes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            output = Path(directory) / "findings.csv"
            message = 'Error connecting to "server", retry needed'
            source.write_text(message + "\n", encoding="utf-8")

            result = self.run_cli(
                source, "--format", "csv", "--output", output
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            with output.open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["message"], message)

    def test_empty_csv_has_header(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "empty.log"
            source.write_text("", encoding="utf-8")
            result = self.run_cli(source, "--format", "csv")

        self.assertEqual(result.returncode, 0, result.stderr)
        reader = csv.DictReader(io.StringIO(result.stdout))
        self.assertIn("rule_id", reader.fieldnames)
        self.assertEqual(list(reader), [])

    def test_missing_input_returns_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.log"
            result = self.run_cli(missing)

        self.assertEqual(result.returncode, 2)
        self.assertIn("Error:", result.stderr)

    def test_input_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            original = "Failed login\n"
            source.write_text(original, encoding="utf-8")

            result = self.run_cli(source, "--output", source)

            self.assertEqual(result.returncode, 2)
            self.assertEqual(
                source.read_text(encoding="utf-8"), original
            )


if __name__ == "__main__":
    unittest.main()
