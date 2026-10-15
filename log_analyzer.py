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


if __name__ == "__main__":
    sample_file = Path(__file__).resolve().with_name("sample_logs.txt")

    try:
        results = analyze_logs(sample_file)
    except (OSError, UnicodeError) as error:
        raise SystemExit(f"Could not read log file: {error}")

    print("=== Log Analysis Findings ===")

    for finding in results:
        print(
            f"[{finding['severity']}] "
            f"({finding['category']}) "
            f"line={finding['line']}: {finding['message']}"
        )

    print(f"\nTotal findings: {len(results)}")
