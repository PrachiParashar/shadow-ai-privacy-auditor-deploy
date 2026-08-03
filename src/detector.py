
import re
from typing import TypedDict


class Finding(TypedDict):
    start: int
    end: int
    value: str
    category: str
    replacement: str
    explanation: str
    severity: str


PATTERNS = [
    {
        "category": "Email address",
        "replacement": "[EMAIL]",
        "explanation": "An email address may expose private contact information.",
        "severity": "Medium",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    },
    {
        "category": "Phone number",
        "replacement": "[PHONE]",
        "explanation": "A phone number is personal contact information.",
        "severity": "Medium",
        "pattern": (
            r"(?<!\d)(?:\+?1[-.\s]?)?"
            r"(?:\(\d{3}\)|\d{3})[-.\s]?"
            r"\d{3}[-.\s]?\d{4}(?!\d)"
        ),
    },
    {
        "category": "Social Security number",
        "replacement": "[SSN]",
        "explanation": "A Social Security number is a sensitive government identifier.",
        "severity": "Critical",
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
    },
    {
        "category": "Payment card number",
        "replacement": "[PAYMENT CARD]",
        "explanation": "This resembles sensitive payment-card information.",
        "severity": "Critical",
        "pattern": r"\b(?:\d[ -]*?){13,16}\b",
    },
    {
        "category": "Password",
        "replacement": "[PASSWORD]",
        "explanation": "Passwords can provide unauthorized access to systems.",
        "severity": "Critical",
        "pattern": r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]+",
    },
    {
        "category": "API key or access token",
        "replacement": "[API KEY]",
        "explanation": "API keys and tokens may provide access to private services.",
        "severity": "Critical",
        "pattern": (
            r"(?i)\b(?:api[_ -]?key|access[_ -]?token|"
            r"secret[_ -]?key)\s*[:=]\s*[A-Za-z0-9_\-]{8,}"
        ),
    },
    {
        "category": "Employee, client or patient ID",
        "replacement": "[INTERNAL ID]",
        "explanation": "Internal identifiers may expose private records.",
        "severity": "High",
        "pattern": (
            r"(?i)\b(?:employee|client|patient|volunteer)"
            r"[ _-]?id\s*[:#=-]?\s*[A-Za-z0-9-]{3,}\b"
        ),
    },
    {
        "category": "Medical information",
        "replacement": "[MEDICAL INFORMATION]",
        "explanation": "Medical diagnoses and treatments are sensitive information.",
        "severity": "High",
        "pattern": (
            r"(?i)\b(?:diagnosed with|prescribed|medical condition|"
            r"blood type|treatment for)\s+"
            r"[A-Za-z][A-Za-z0-9 ,'-]{2,50}"
        ),
    },
    {
        "category": "Confidential organizational information",
        "replacement": "[CONFIDENTIAL INFORMATION]",
        "explanation": "Confidential business information should not be shared publicly.",
        "severity": "High",
        "pattern": (
            r"(?i)\b(?:strictly confidential|internal only|"
            r"unreleased product|acquisition plan|secret project|"
            r"confidential roadmap)\b"
        ),
    },
]


def detect_sensitive_data(text: str) -> list[Finding]:
    findings: list[Finding] = []

    for rule in PATTERNS:
        for match in re.finditer(rule["pattern"], text):
            findings.append(
                {
                    "start": match.start(),
                    "end": match.end(),
                    "value": match.group(),
                    "category": rule["category"],
                    "replacement": rule["replacement"],
                    "explanation": rule["explanation"],
                    "severity": rule["severity"],
                }
            )

    findings.sort(key=lambda item: (item["start"], -(item["end"] - item["start"])))

    cleaned: list[Finding] = []

    for finding in findings:
        overlaps = any(
            finding["start"] < saved["end"]
            and finding["end"] > saved["start"]
            for saved in cleaned
        )

        if not overlaps:
            cleaned.append(finding)

    return sorted(cleaned, key=lambda item: item["start"])


def redact_text(text: str, findings: list[Finding]) -> str:
    redacted = text

    for finding in sorted(
        findings,
        key=lambda item: item["start"],
        reverse=True,
    ):
        redacted = (
            redacted[:finding["start"]]
            + finding["replacement"]
            + redacted[finding["end"]:]
        )

    return redacted
