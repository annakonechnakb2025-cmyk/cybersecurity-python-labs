import argparse
import json
import re
import sys
from pathlib import Path

import requests

from labs.lab04.analysis import build_report, extract_record
from labs.lab04.api_client import fetch_response
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def load_response(path: str | Path) -> dict:
    """Завантажує JSON-відповідь NVD із локального файла."""
    with Path(path).open("r", encoding="utf-8") as file:
        return json.load(file)


def main(argv: list[str] | None = None) -> int:
    """Обробляє аргументи та формує JSON-звіт."""
    if type(VARIANT_NUMBER) is not int or not 1 <= VARIANT_NUMBER <= 15:
        print("Error: invalid variant number", file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser(description="NVD CVE analyzer")

    parser.add_argument(
        "--cve",
        required=True,
        help="CVE identifier, e.g. CVE-2021-44228",
    )

    parser.add_argument(
        "--input",
        help="Path to a local NVD JSON response",
    )

    args = parser.parse_args(argv)

    if CVE_PATTERN.fullmatch(args.cve) is None:
        parser.error("Invalid CVE identifier format")

    try:
        if args.input:
            payload = load_response(args.input)
        else:
            payload = fetch_response(args.cve)

        record = extract_record(payload, args.cve)
        report = build_report(record, args.cve, VARIANT_NUMBER)

    except (FileNotFoundError, PermissionError, OSError):
        print("Error: cannot read input file", file=sys.stderr)
        return 1

    except json.JSONDecodeError:
        print("Error: invalid JSON response", file=sys.stderr)
        return 1

    except requests.exceptions.Timeout:
        print("Error: NVD request timed out", file=sys.stderr)
        return 1

    except requests.exceptions.ConnectionError:
        print("Error: cannot connect to NVD", file=sys.stderr)
        return 1

    except requests.exceptions.HTTPError as error:
        status = error.response.status_code if error.response is not None else "unknown"
        print(f"Error: HTTP status {status}", file=sys.stderr)
        return 1

    except requests.exceptions.RequestException:
        print("Error: NVD request failed", file=sys.stderr)
        return 1

    except ValueError as error:
        print(f"Error: invalid data: {error}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
