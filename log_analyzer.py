import argparse
import csv
import json
import re
from pathlib import Path


RULES = [
    {
        "id": "AUTH_FAILURE",
        "severity": "MEDIUM",
        "category": "Authentication Failure",
        "pattern": re.compile(
            r"\b(?:failed (?:login|password|authentication)"
            r"|(?:login|authentication) failed"
            r"|invalid password)\b",
            re.IGNORECASE,
        ),
    },
    {
        "id": "SERVICE_ERROR",
        "severity": "LOW",
        "category": "Operational Error",
        "pattern": re.compile(r"\berror\b", re.IGNORECASE),
    },
]


def analyze_logs(file):
    """Return findings for log messages matching the detection rules."""
    findings = []

    with open(file, "r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            message = line.strip()

            if not message:
                continue

            for rule in RULES:
                match = rule["pattern"].search(message)

                if match:
                    findings.append({
                        "line": line_number,
                        "rule_id": rule["id"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "evidence": match.group(),
                        "message": message,
                    })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Analyze log messages using explicit detection rules."
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().with_name("sample_logs.txt"),
        help="Path to a UTF-8 text log file",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Save findings to a file",
    )
    args = parser.parse_args()

    if args.output and args.input.resolve() == args.output.resolve():
        parser.error("Input and output must be different files.")

    try:
        findings = analyze_logs(args.input)

        if args.format == "json":
            output = json.dumps(
                {"schema_version": 1, "findings": findings},
                indent=2,
                ensure_ascii=False,
            ) + "\n"

        elif args.format == "csv":
            import io

            buffer = io.StringIO(newline="")
            fields = [
                "line", "rule_id", "severity",
                "category", "evidence", "message",
            ]
            writer = csv.DictWriter(buffer, fieldnames=fields)
            writer.writeheader()
            writer.writerows(findings)
            output = buffer.getvalue()

        else:
            lines = ["=== Log Analysis Findings ==="]

            for finding in findings:
                lines.append(
                    f"[{finding['severity']}] "
                    f"({finding['category']}) "
                    f"line={finding['line']}: {finding['message']}"
                )

            lines.append(f"\nTotal findings: {len(findings)}")
            output = "\n".join(lines) + "\n"

        if args.output:
            with args.output.open(
                "w", encoding="utf-8", newline=""
            ) as output_file:
                output_file.write(output)
        else:
            print(output, end="")

    except (OSError, UnicodeError) as error:
        parser.exit(2, f"Error: {error}\n")


if __name__ == "__main__":
    main()
