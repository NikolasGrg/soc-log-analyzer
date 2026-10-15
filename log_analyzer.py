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


def analyze_logs(file, input_format="text"):
    """Analyze text or JSONL logs and return explainable findings."""
    if input_format not in ("text", "jsonl"):
        raise ValueError("Input format must be text or jsonl.")

    findings = []
    context_fields = ("timestamp", "host", "user", "source_ip")

    with open(file, "r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if not line.strip():
                continue

            if input_format == "jsonl":
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"Line {line_number}: invalid JSON."
                    ) from error

                if not isinstance(event, dict):
                    raise ValueError(
                        f"Line {line_number}: expected a JSON object."
                    )

                if not isinstance(event.get("message"), str):
                    raise ValueError(
                        f"Line {line_number}: message must be a string."
                    )

                for field in context_fields:
                    if field in event and not isinstance(event[field], str):
                        raise ValueError(
                            f"Line {line_number}: {field} must be a string."
                        )
            else:
                event = {"message": line.strip()}

            message = event["message"]

            for rule in RULES:
                match = rule["pattern"].search(message)

                if match:
                    finding = {
                        "line": line_number,
                        "rule_id": rule["id"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "evidence": match.group(),
                        "message": message,
                    }

                    for field in context_fields:
                        finding[field] = event.get(field, "")

                    findings.append(finding)

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
        parser.add_argument(
        "--input-format",
        choices=["text", "jsonl"],
        default="text",
        help="Input format (default: text)",
    )
    args = parser.parse_args()

    if args.output and args.input.resolve() == args.output.resolve():
        parser.error("Input and output must be different files.")

    try:
     findings = analyze_logs(args.input, args.input_format)

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
                "category", "evidence", "message", "timestamp", "host", "user", "source_ip",
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

    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(2, f"Error: {error}\n")


if __name__ == "__main__":
    main()
