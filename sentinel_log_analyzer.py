#!/usr/bin/env python3

"""
Sentinel Log Analyzer
---------------------

A defensive security log analyzer for detecting suspicious
authentication activity, brute-force behavior, IP anomalies,
and potential Indicators of Compromise.

Author: Malek
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable


# ============================================================
# Configuration
# ============================================================

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = 300

FAILED_AUTH_PATTERNS = (
    "failed password",
    "authentication failure",
    "failed login",
    "invalid user",
    "login failed",
)

SUCCESS_AUTH_PATTERNS = (
    "accepted password",
    "authentication succeeded",
    "login successful",
    "successful login",
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

USERNAME_PATTERN = re.compile(
    r"(?:user|for)\s+(?:invalid\s+)?user\s+([a-zA-Z0-9._-]+)",
    re.IGNORECASE,
)

TIMESTAMP_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)


# ============================================================
# Data Models
# ============================================================

@dataclass
class LogEvent:
    timestamp: str
    ip: str
    username: str
    event_type: str
    raw_line: str


@dataclass
class RiskFinding:
    ip: str
    risk_score: int
    severity: str
    failed_attempts: int
    successful_attempts: int
    unique_users: int
    reasons: list[str]


# ============================================================
# Utility Functions
# ============================================================

def is_valid_ip(value: str) -> bool:
    """Return True if value is a valid IPv4 or IPv6 address."""

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_ip(line: str) -> str | None:
    """Extract the first valid IP address from a log line."""

    for candidate in IP_PATTERN.findall(line):
        if is_valid_ip(candidate):
            return candidate

    return None


def extract_username(line: str) -> str:
    """Extract a username when present."""

    match = USERNAME_PATTERN.search(line)

    if match:
        return match.group(1)

    return "unknown"


def extract_timestamp(line: str) -> str:
    """Extract a timestamp from a common syslog-style line."""

    match = TIMESTAMP_PATTERN.search(line)

    if match:
        return match.group(1)

    return "unknown"


def classify_event(line: str) -> str:
    """Classify a log line into a security event type."""

    normalized = line.lower()

    if any(pattern in normalized for pattern in FAILED_AUTH_PATTERNS):
        return "failed_authentication"

    if any(pattern in normalized for pattern in SUCCESS_AUTH_PATTERNS):
        return "successful_authentication"

    return "other"


# ============================================================
# Log Parsing
# ============================================================

def parse_line(line: str) -> LogEvent | None:
    """Parse one log line into a LogEvent."""

    event_type = classify_event(line)

    if event_type == "other":
        return None

    ip = extract_ip(line)

    if not ip:
        return None

    return LogEvent(
        timestamp=extract_timestamp(line),
        ip=ip,
        username=extract_username(line),
        event_type=event_type,
        raw_line=line.rstrip(),
    )


def parse_log(file_path: Path) -> list[LogEvent]:
    """Read and parse a complete log file."""

    events: list[LogEvent] = []

    try:
        with file_path.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            for line in file:
                event = parse_line(line)

                if event:
                    events.append(event)

    except OSError as error:
        raise RuntimeError(
            f"Unable to read log file: {error}"
        ) from error

    return events


# ============================================================
# Detection Engine
# ============================================================

def detect_bruteforce(
    events: Iterable[LogEvent],
    threshold: int,
) -> dict[str, list[str]]:
    """
    Detect IP addresses with repeated failed authentication attempts.
    """

    failed_counts = Counter(
        event.ip
        for event in events
        if event.event_type == "failed_authentication"
    )

    findings: dict[str, list[str]] = {}

    for ip, count in failed_counts.items():

        if count >= threshold:

            findings[ip] = [
                f"{count} failed authentication attempts"
            ]

    return findings


def detect_multi_user_attack(
    events: Iterable[LogEvent],
    minimum_users: int = 3,
) -> dict[str, list[str]]:
    """
    Detect IP addresses targeting multiple usernames.
    """

    users_by_ip: defaultdict[str, set[str]] = defaultdict(set)

    for event in events:

        if event.event_type != "failed_authentication":
            continue

        if event.username == "unknown":
            continue

        users_by_ip[event.ip].add(event.username)

    findings: dict[str, list[str]] = {}

    for ip, users in users_by_ip.items():

        if len(users) >= minimum_users:

            findings[ip] = [
                f"Targeted {len(users)} different usernames"
            ]

    return findings


def detect_success_after_failures(
    events: Iterable[LogEvent],
    minimum_failures: int = 3,
) -> dict[str, list[str]]:
    """
    Detect IPs that eventually achieved a successful login
    after multiple failed authentication attempts.
    """

    failed_counts = Counter()
    findings: dict[str, list[str]] = {}

    for event in events:

        if event.event_type == "failed_authentication":
            failed_counts[event.ip] += 1

        elif event.event_type == "successful_authentication":

            if failed_counts[event.ip] >= minimum_failures:

                findings[event.ip] = [
                    "Successful authentication occurred "
                    "after repeated failures"
                ]

    return findings


# ============================================================
# Risk Engine
# ============================================================

def calculate_risk(
    events: Iterable[LogEvent],
    threshold: int,
) -> list[RiskFinding]:

    events_by_ip: defaultdict[str, list[LogEvent]] = defaultdict(list)

    for event in events:
        events_by_ip[event.ip].append(event)

    findings: list[RiskFinding] = []

    for ip, ip_events in events_by_ip.items():

        failed = sum(
            event.event_type == "failed_authentication"
            for event in ip_events
        )

        successful = sum(
            event.event_type == "successful_authentication"
            for event in ip_events
        )

        users = {
            event.username
            for event in ip_events
            if event.username != "unknown"
        }

        score = 0
        reasons: list[str] = []

        # Rule 1: repeated failures
        if failed >= threshold:

            score += min(40, failed * 4)

            reasons.append(
                f"Repeated authentication failures: {failed}"
            )

        # Rule 2: multiple usernames
        if len(users) >= 3:

            score += 20

            reasons.append(
                f"Multiple targeted accounts: {len(users)}"
            )

        # Rule 3: success after failures
        if successful > 0 and failed >= 3:

            score += 30

            reasons.append(
                "Successful authentication after failures"
            )

        # Rule 4: very high activity
        if failed >= threshold * 3:

            score += 20

            reasons.append(
                "High-volume authentication activity"
            )

        score = min(score, 100)

        if score >= 80:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if score > 0:

            findings.append(
                RiskFinding(
                    ip=ip,
                    risk_score=score,
                    severity=severity,
                    failed_attempts=failed,
                    successful_attempts=successful,
                    unique_users=len(users),
                    reasons=reasons,
                )
            )

    return sorted(
        findings,
        key=lambda finding: finding.risk_score,
        reverse=True,
    )


# ============================================================
# Reporting
# ============================================================

def generate_report(
    file_path: Path,
    events: list[LogEvent],
    findings: list[RiskFinding],
) -> dict:

    return {
        "metadata": {
            "tool": "Sentinel Log Analyzer",
            "version": "1.0.0",
            "analyzed_file": str(file_path),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        },
        "statistics": {
            "security_events": len(events),
            "unique_ips": len({event.ip for event in events}),
            "failed_authentication": sum(
                event.event_type == "failed_authentication"
                for event in events
            ),
            "successful_authentication": sum(
                event.event_type == "successful_authentication"
                for event in events
            ),
        },
        "findings": [
            asdict(finding)
            for finding in findings
        ],
    }


def print_report(report: dict) -> None:

    statistics = report["statistics"]
    findings = report["findings"]

    print()
    print("=" * 72)
    print("                    SENTINEL LOG ANALYZER")
    print("=" * 72)

    print(
        f"Security events        : "
        f"{statistics['security_events']}"
    )

    print(
        f"Unique IP addresses    : "
        f"{statistics['unique_ips']}"
    )

    print(
        f"Failed authentication  : "
        f"{statistics['failed_authentication']}"
    )

    print(
        f"Successful login       : "
        f"{statistics['successful_authentication']}"
    )

    print()
    print("Risk Findings")
    print("-" * 72)

    if not findings:

        print("[+] No suspicious authentication behavior detected.")

    else:

        for finding in findings:

            print(
                f"[{finding['severity']}] "
                f"{finding['ip']} "
                f"(Risk: {finding['risk_score']}/100)"
            )

            print(
                f"    Failed attempts : "
                f"{finding['failed_attempts']}"
            )

            print(
                f"    Successful      : "
                f"{finding['successful_attempts']}"
            )

            print(
                f"    Unique users    : "
                f"{finding['unique_users']}"
            )

            for reason in finding["reasons"]:

                print(f"    └─ {reason}")

            print()

    print("=" * 72)


def save_json(report: dict, output: Path) -> None:

    with output.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
        )


def save_csv(
    findings: list[dict],
    output: Path,
) -> None:

    if not findings:
        return

    fields = [
        "ip",
        "risk_score",
        "severity",
        "failed_attempts",
        "successful_attempts",
        "unique_users",
    ]

    with output.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )

        writer.writeheader()

        for finding in findings:

            writer.writerow(
                {
                    key: finding[key]
                    for key in fields
                }
            )


# ============================================================
# CLI
# ============================================================

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=(
            "Sentinel Log Analyzer - "
            "Defensive authentication log analysis"
        )
    )

    parser.add_argument(
        "logfile",
        type=Path,
        help="Path to the log file",
    )

    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help=(
            "Failed authentication threshold "
            f"(default: {DEFAULT_THRESHOLD})"
        ),
    )

    parser.add_argument(
        "--json",
        type=Path,
        metavar="FILE",
        help="Export report as JSON",
    )

    parser.add_argument(
        "--csv",
        type=Path,
        metavar="FILE",
        help="Export findings as CSV",
    )

    return parser


def main() -> int:

    parser = build_parser()
    args = parser.parse_args()

    if not args.logfile.is_file():

        print(
            f"[!] Log file not found: {args.logfile}",
            file=sys.stderr,
        )

        return 1

    if args.threshold < 1:

        print(
            "[!] Threshold must be greater than zero.",
            file=sys.stderr,
        )

        return 1

    try:

        events = parse_log(args.logfile)

        findings = calculate_risk(
            events,
            args.threshold,
        )

        report = generate_report(
            args.logfile,
            events,
            findings,
        )

        print_report(report)

        if args.json:

            save_json(
                report,
                args.json,
            )

            print(
                f"[+] JSON report saved to {args.json}"
            )

        if args.csv:

            save_csv(
                report["findings"],
                args.csv,
            )

            print(
                f"[+] CSV report saved to {args.csv}"
            )

        return 0

    except RuntimeError as error:

        print(
            f"[!] {error}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())
