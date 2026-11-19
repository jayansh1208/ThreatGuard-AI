from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time

from api_client import ThreatGuardClient
from agent_server import serve_agent
from scanner import run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ThreatGuard read-only Windows endpoint agent")
    parser.add_argument("--scan", action="store_true", help="Collect a local scan and upload it after confirmation")
    parser.add_argument("--system-info", action="store_true", help="Print operating system and coverage information")
    parser.add_argument("--check-connection", action="store_true", help="Check the configured backend health endpoint")
    parser.add_argument("--serve", action="store_true", help="Run the on-demand local agent bridge for the ThreatGuard dashboard")
    parser.add_argument("--periodic", action="store_true", help="Opt in to repeated scans in this foreground process")
    parser.add_argument("--interval-minutes", type=int, default=60, help="Periodic scan interval, 1–1440 minutes (default: 60)")
    return parser


def _confirm(message: str) -> bool:
    return input(f"{message} [y/N] ").strip().lower() == "y"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    client = ThreatGuardClient()
    if args.serve:
        if not _confirm("Allow the authenticated ThreatGuard dashboard to request local read-only scans and upload findings while this process runs?"):
            print("Agent bridge cancelled.")
            return 0
        serve_agent(client)
        return 0
    if args.check_connection:
        try:
            print("ThreatGuard backend is reachable." if client.check_connection() else "Backend health is not ready.")
            return 0
        except Exception as exc:
            print(f"Backend connection failed: {exc}", file=sys.stderr)
            return 1
    if args.system_info:
        from windows_security import collect_windows_security
        print(json.dumps(collect_windows_security(), indent=2))
        return 0
    if args.periodic:
        if not 1 <= args.interval_minutes <= 1440:
            build_parser().error("--interval-minutes must be between 1 and 1440")
        print("Periodic mode remains in this foreground session only; it creates no scheduled task or startup entry.")
        try:
            while True:
                if not _confirm("Run the next local scan?"):
                    print("Periodic scanning stopped.")
                    return 0
                report = run_scan()
                print(json.dumps(report["summary"], indent=2))
                if _confirm("Upload this scan to the configured ThreatGuard backend?"):
                    email = os.getenv("THREATGUARD_EMAIL") or input("ThreatGuard account email: ").strip()
                    password = getpass.getpass("ThreatGuard password (used for sign-in only; not saved): ")
                    try:
                        client.login(email, password, org_id=os.getenv("THREATGUARD_ORG_ID"), tenant_id=os.getenv("THREATGUARD_TENANT_ID"))
                        stored = client.upload_scan(report)
                    except PermissionError:
                        print("The session expired. Sign in again to retry this scan.")
                        client.login(email, getpass.getpass("ThreatGuard password: "),
                                     org_id=os.getenv("THREATGUARD_ORG_ID"), tenant_id=os.getenv("THREATGUARD_TENANT_ID"))
                        stored = client.upload_scan(report)
                    print(f"Scan uploaded. Scan ID: {stored.get('scan_id', report['scan_id'])}")
                else:
                    print("This scan was not uploaded.")
                print(f"Next scan prompt in {args.interval_minutes} minute(s). Press Ctrl+C to stop.")
                time.sleep(args.interval_minutes * 60)
        except KeyboardInterrupt:
            print("\nPeriodic scanning stopped.")
            return 0
    if not args.scan:
        build_parser().print_help()
        return 0
    if not _confirm("This will inspect local Windows security settings, installed application names/versions, and listening TCP ports. Continue?"):
        print("Scan cancelled.")
        return 0
    report = run_scan()
    print(json.dumps(report["summary"], indent=2))
    if not _confirm("Upload the scan findings and limited host identifier to your configured ThreatGuard backend?"):
        print(f"Scan retained only in memory. Scan ID: {report['scan_id']}")
        return 0
    email = os.getenv("THREATGUARD_EMAIL") or input("ThreatGuard account email: ").strip()
    password = getpass.getpass("ThreatGuard password (used for sign-in only; not saved): ")
    try:
        client.login(email, password, org_id=os.getenv("THREATGUARD_ORG_ID"), tenant_id=os.getenv("THREATGUARD_TENANT_ID"))
        stored = client.upload_scan(report)
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Scan upload failed: {exc}", file=sys.stderr)
        return 1
    print(f"Scan uploaded. Scan ID: {stored.get('scan_id', report['scan_id'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
