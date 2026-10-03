import argparse
import json
import logging
import re
from collections import Counter
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)

# Виправлення для ruff (LOG015): створення власного логера замість глобального logging
logger = logging.getLogger(__name__)

PATTERNS = {
    "emails": re.compile(r"[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "cards": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
    "phones": re.compile(r"\+?\d[\d\s().-]{8,}\d"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


def scan_directory(scan_dir):
    scan_path = Path(scan_dir)
    findings = []
    files_scanned = 0

    for file_path in scan_path.rglob("*"):
        if not file_path.is_file():
            continue

        files_scanned += 1

        try:
            text = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        for line_number, line in enumerate(text.splitlines(), start=1):
            for data_type, pattern in PATTERNS.items():
                for match in pattern.finditer(line):
                    findings.append(
                        {
                            "type": data_type,
                            "value": match.group(),
                            "file": str(file_path),
                            "line": line_number,
                        }
                    )

    return files_scanned, findings


def count_findings(findings):
    counter = Counter()

    for finding in findings:
        counter[finding["type"]] += 1

    return counter


def mask_value(value, data_type):
    if data_type == "cards":
        digits = re.sub(r"\D", "", value)
        return f"{digits[:4]}-****-****-{digits[-4:]}"

    if data_type == "emails":
        local, domain = value.split("@", 1)
        return f"{local[0]}****@{domain}"

    if data_type == "phones":
        digits = re.sub(r"\D", "", value)
        return f"{digits[:2]}-****-**-{digits[-2:]}"

    if data_type == "ipv4":
        parts = value.split(".")
        return f"{parts[0]}.{parts[1]}.***.***"

    return value


def prepare_findings(findings, mask=False):
    prepared = []

    for finding in findings:
        item = finding.copy()

        if mask:
            item["value"] = mask_value(
                item["value"],
                item["type"],
            )

        prepared.append(item)

    return prepared


def save_report(out_json, files_scanned, counter, findings):
    report = {
        "files_scanned": files_scanned,
        "summary": dict(counter),
        "findings": findings,
    }

    output_path = Path(out_json)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)


def parse_args():
    parser = argparse.ArgumentParser(description="PII Exfiltration Scanner")

    parser.add_argument(
        "--scan-dir",
        required=True,
        help="Directory to scan",
    )

    parser.add_argument(
        "--patterns",
        choices=["all", "cards", "emails"],
        default="all",
        help="PII patterns to search for",
    )

    parser.add_argument(
        "--mask",
        action="store_true",
        help="Mask detected PII",
    )

    parser.add_argument(
        "--out-json",
        required=True,
        help="Path to JSON report",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # Використання logger.info замість logging.info
    logger.info(f"Scanning directory {args.scan_dir} for unmasked PII data...")

    files_scanned, findings = scan_directory(args.scan_dir)

    if args.patterns != "all":
        findings = [finding for finding in findings if finding["type"] == args.patterns]

    counter = count_findings(findings)

    if findings:
        # Використання logger.warning замість logging.warning
        logger.warning("Unmasked PII found in plaintext logs!")

    prepared_findings = prepare_findings(findings, args.mask)

    print(f"[INFO] Scanned {files_scanned} files.")
    print("=== Detected Sensitive Data (PII) ===")
    print(f"Email Addresses : {counter['emails']} matches")
    print(f"Credit Card Numbers: {counter['cards']} matches")
    print(f"Phone Numbers : {counter['phones']} matches")
    print(f"IPv4 Addresses : {counter['ipv4']} matches")

    print("=== Sample Findings (Masked for Display) ===")

    for finding in prepared_findings[:5]:
        print(f"[PII FOUND] File: {finding['file']} (Line {finding['line']})")
        print(f"{finding['type'].capitalize()} : {finding['value']}")

    save_report(
        args.out_json,
        files_scanned,
        counter,
        prepared_findings,
    )

    # Використання logger.info замість logging.info
    logger.info(f"Sanitized report saved to {args.out_json}")


if __name__ == "__main__":
    main()
