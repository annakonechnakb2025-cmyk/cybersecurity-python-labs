import argparse

from labs.lab02.task1 import Admin, User, UserAccount
from labs.lab02.task2 import (
    count_findings,
    prepare_findings,
    save_report,
    scan_directory,
)


def demo():
    print("=== User and UserAccount ===")

    user = User(
        "anna",
        "anna_13@example.com",
        "user",
    )

    user.set_password("Test123!")

    account = UserAccount(user)

    print("Login with correct password:")
    print(account.login("Test123!", "192.168.1.10"))

    print("Authenticated:")
    print(account.is_authenticated())

    print("Login with wrong password:")
    print(account.login("Wrong123!", "192.168.1.10"))

    print("\n=== Email validation ===")

    print("Current email:", user.email)

    user.email = "anna_new@example.com"
    print("New email:", user.email)

    try:
        user.email = "wrong-email"
    except ValueError as error:
        print("Invalid email:", error)

    print("\n=== Admin permissions ===")

    admin = Admin(
        "admin",
        "admin_13@example.com",
    )

    admin.grant_permission("read")
    admin.grant_permission("write")

    print(admin)
    print("Has read permission:", admin.has_permission("read"))
    print("Has delete permission:", admin.has_permission("delete"))

    admin.revoke_permission("write")

    print("After revoke:", admin)

    print("\n=== Logout ===")

    account.logout()
    print("Authenticated after logout:")
    print(account.is_authenticated())

    print("\n=== Audit Log ===")

    account.audit_log.show_all()


def analyze(args):
    print("=== PII Analysis ===")

    files_scanned, findings = scan_directory(args.scan_dir)

    if args.patterns != "all":
        findings = [finding for finding in findings if finding["type"] == args.patterns]

    counter = count_findings(findings)
    prepared_findings = prepare_findings(findings, args.mask)

    print(f"[INFO] Scanned {files_scanned} files.")
    print("=== Detected Sensitive Data (PII) ===")
    print(f"Email Addresses : {counter['emails']} matches")
    print(f"Credit Card Numbers: {counter['cards']} matches")
    print(f"Phone Numbers : {counter['phones']} matches")
    print(f"IPv4 Addresses : {counter['ipv4']} matches")

    if findings:
        print("\n=== Sample Findings ===")

        for finding in prepared_findings[:5]:
            print(f"[PII FOUND] File: {finding['file']} (Line {finding['line']})")
            print(f"{finding['type'].capitalize()} : {finding['value']}")
    else:
        print("\nNo sensitive data found.")

    save_report(
        args.out_json,
        files_scanned,
        counter,
        prepared_findings,
    )

    print(f"\n[INFO] Sanitized report saved to {args.out_json}")


def create_parser():
    parser = argparse.ArgumentParser(
        description="Lab 2 - User Management and PII Scanner"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser(
        "demo",
        help="Run User/UserAccount/Admin demonstration",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Scan directory for sensitive data",
    )

    analyze_parser.add_argument(
        "--scan-dir",
        required=True,
        help="Directory to scan",
    )

    analyze_parser.add_argument(
        "--patterns",
        choices=["all", "cards", "emails"],
        default="all",
        help="PII patterns to search for",
    )

    analyze_parser.add_argument(
        "--mask",
        action="store_true",
        help="Mask detected PII in the output report",
    )

    analyze_parser.add_argument(
        "--out-json",
        required=True,
        help="Path to JSON report",
    )

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "demo":
        demo()

    elif args.command == "analyze":
        analyze(args)


if __name__ == "__main__":
    main()
