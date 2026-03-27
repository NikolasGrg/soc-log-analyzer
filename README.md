# SOC Log Analyzer

SOC-focused log analysis tool for detecting suspicious events and performing basic incident triage using Python.

---

## Overview

This project simulates how a SOC analyst processes logs to identify potential security incidents such as:

* Failed login attempts
* System errors
* Suspicious activity patterns

---

## Features

* Detects failed logins and system errors
* Flags suspicious log entries
* Applies basic severity classification
* Categorizes events based on type
* Simple and easily extendable detection logic

---

## SOC Use Case

This tool mimics the initial alert triage process performed in a SOC environment using SIEM platforms (e.g. FortiSIEM, Splunk).

It helps analysts:

* Identify suspicious authentication activity
* Detect system anomalies
* Prioritize events based on severity

---

## Usage

Run the script locally:

```bash
py log_analyzer.py
```

---

## Sample Data

The `sample_logs.txt` file contains simulated log entries used for testing detection logic.

---

## Detection Logic

* `"failed"` → Possible brute-force or authentication issue (**MEDIUM severity**)
* `"error"` → Potential system or service anomaly (**LOW severity**)

---

## Example Output

```text
=== Suspicious Events Detected ===

[MEDIUM] (Authentication Failure) Failed login attempt from 10.0.0.5
[LOW] (System Error) Error connecting to server
[MEDIUM] (Authentication Failure) Failed login attempt from 10.0.0.5
```

---

## Skills Demonstrated

* Log Analysis
* Incident Triage
* Detection Logic Design
* Python Scripting for Security
* Basic SIEM Use Case Simulation

---

## Future Improvements

* Regex-based detection rules
* Advanced severity classification
* Integration with threat intelligence APIs (e.g. VirusTotal, AbuseIPDB)
* Export results to JSON or CSV
* Real-time log monitoring

---

## Author

Nikolas Georgopoulos
SOC Analyst | CySA+
