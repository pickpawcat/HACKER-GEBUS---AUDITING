"""Command-line interface. Safe by default: with no flags it only prints a dry-run plan."""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, safety
from .backends import MockBackend, WinRMBackend
from .catalog import BENCHMARK_LABEL, CHECKS, SECTIONS
from .collector import BackendError, build_sections, collect
from .evaluator import evaluate_all, summarize
from .report import make_output_dir, print_console, utc_and_myt, write_reports

EXAMPLES = """examples:
  cischeck --list-checks                              show every control that can be audited
  cischeck                                            dry-run against 127.0.0.1 (touches nothing)
  cischeck --demo                                     full pipeline on synthetic data, no network
  cischeck --live --target 192.168.56.101 --scope 192.168.56.0/24 -u 'LABPC\\auditor'
  cischeck --live --target win11-lab --scope win11-lab -u auditor --ssl --window 09:00-18:00 \\
           --engagement-id LAB-2026-01 --sections "Windows Firewall,Account Policies"

emergency stop: Ctrl+C, or from another terminal:  touch /tmp/cischeck.STOP
"""


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="cischeck", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EXAMPLES,
        description=f"CIS Benchmark Checker v{__version__}: read-only remote audit of Windows 10/11 from Kali.")
    p.add_argument("--target", default="127.0.0.1", help="Host to audit (default: 127.0.0.1).")
    p.add_argument("--scope", action="append", default=[],
                   help="Authorised IPs/CIDRs (max /24) or hostnames; repeatable. Required for non-loopback targets.")
    p.add_argument("-u", "--username", help="Audit account, e.g. 'HOST\\auditor' or 'DOMAIN\\user'.")
    p.add_argument("--password-env", metavar="VAR", help="Read password from this environment variable (default: prompt).")
    p.add_argument("--port", type=int, help="WinRM port (default 5985, or 5986 with --ssl).")
    p.add_argument("--ssl", action="store_true", help="Use WinRM over HTTPS (certificate verified).")
    p.add_argument("--insecure", action="store_true", help="With --ssl: skip certificate validation (lab only).")
    p.add_argument("--timeout", type=int, default=30, help="Per-query timeout in seconds (default 30).")
    p.add_argument("--window", metavar="HH:MM-HH:MM", help="Authorised local time window; run refuses outside it.")
    p.add_argument("--engagement-id", default="UNSPECIFIED", help="Label recorded in reports (ticket / RoE reference).")
    p.add_argument("--sections", help=f"Comma-separated subset. Choices: {', '.join(SECTIONS)}")
    p.add_argument("--output-dir", default="output", help="Local report directory (default: ./output).")
    p.add_argument("--no-html", action="store_true", help="Skip the HTML report.")
    p.add_argument("--allow-public", action="store_true", help="Permit a public IP (requires written authorisation).")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true", help="Actually connect and audit. Without it, nothing is contacted.")
    mode.add_argument("--demo", action="store_true", help="Run on built-in synthetic data (no network).")
    mode.add_argument("--list-checks", action="store_true", help="List all controls and exit.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def select_checks(spec: str | None):
    if not spec:
        return CHECKS
    wanted = {s.strip().lower() for s in spec.split(",")}
    chosen = [c for c in CHECKS if c.section.lower() in wanted]
    if not chosen:
        raise safety.SafetyError(f"No section matched. Choices: {', '.join(SECTIONS)}")
    return chosen


def print_plan(target, scope, checks, window) -> None:
    print("[DRY-RUN] Nothing will be contacted. Plan:")
    print(f"  target : {target}\n  scope  : {', '.join(map(str, scope))}\n  window : {window or 'not restricted'}")
    print(f"  checks : {len(checks)} across {len({c.section for c in checks})} sections, collected in "
          f"{len(build_sections())} read-only query batches")
    print("  access : WinRM (NTLM), read-only guard on every script, no files written to the target")
    print("Add --live to audit (after typed authorisation) or --demo to see sample output.")


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.list_checks:
        for c in CHECKS:
            print(f"{c.id:<8}{c.severity:<8}{c.section:<26}CIS {c.cis_ref:<10}{c.title}")
        print(f"\n{len(CHECKS)} controls. Baseline: {BENCHMARK_LABEL}")
        return 0

    print(safety.LEGAL_BANNER)
    kill = safety.KillSwitch()
    try:
        kill.install()
        checks = select_checks(args.sections)
        scope = safety.parse_scope(args.scope or (["127.0.0.1"] if args.target in ("127.0.0.1", "localhost", "::1") else []))
        ip = safety.check_target(args.target, scope, args.allow_public)
        safety.enforce_time_window(args.window)

        if not args.live and not args.demo:
            print_plan(args.target, scope, checks, args.window)
            return 0

        if args.demo:
            print("[DEMO] Synthetic data only. No network connection is made.\n")
            backend, mode, target_label = MockBackend(), "(demo data)", "DEMO-WIN11"
        else:
            if not args.username:
                raise safety.SafetyError("--username is required with --live.")
            safety.confirm_authorization(args.target)
            password = os.environ.get(args.password_env or "") if args.password_env else None
            password = password or getpass.getpass(f"Password for {args.username}: ")
            port = args.port or (5986 if args.ssl else 5985)
            backend = WinRMBackend(ip, args.username, password, port, args.ssl, not args.insecure, args.timeout)
            mode, target_label = "(live)", args.target

        snapshot = collect(backend, kill)
        kill.check()
        results = evaluate_all(snapshot, checks)
        summary = summarize(results)
        stamp = datetime.now(timezone.utc)
        utc, myt = utc_and_myt(stamp)
        osinfo = snapshot.get("os", {})
        meta = {"target": target_label, "target_ip": ip, "engagement": args.engagement_id, "timestamp_utc": utc,
                "timestamp_myt": myt, "baseline": BENCHMARK_LABEL, "version": __version__, "mode": mode,
                "os": f"{osinfo.get('Caption', 'unknown')} build {osinfo.get('Build', '?')}"}
        out_dir = make_output_dir(Path(args.output_dir), target_label, stamp)
        files = write_reports(out_dir, meta, snapshot, results, summary, not args.no_html)
        print_console(results, summary, sys.stdout.isatty())
        print(f"\n[+] Reports saved locally (owner-only permissions):\n    " + "\n    ".join(map(str, files)))
        return 0
    except (safety.Aborted, KeyboardInterrupt):
        print("\n[STOP] Aborted by operator. Nothing on the target was changed; no report written.")
        return 130
    except safety.SafetyError as exc:
        print(f"\n[REFUSED] {exc}")
        return 3
    except BackendError as exc:
        print(f"\n[ERROR] Could not complete collection: {exc}")
        print("        Check WinRM is enabled on the target, credentials, port and firewall.")
        return 2
