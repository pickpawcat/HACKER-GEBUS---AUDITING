"""Ethical guardrails: scope, time window, consent, kill switch, read-only guard."""
from __future__ import annotations

import ipaddress
import re
import signal
import socket
from datetime import datetime
from pathlib import Path

MAX_SCOPE_ADDRESSES = 256  # nothing larger than a /24 can be declared as scope


class SafetyError(Exception):
    """A guardrail refused to let the run continue."""


class Aborted(Exception):
    """The operator (or a stop file) asked the run to stop."""


LEGAL_BANNER = r"""
==============================================================================
 CIS BENCHMARK CHECKER (Kali Remote Edition) - LEGAL & ETHICAL NOTICE
==============================================================================
 This tool audits Windows security configuration. It is READ-ONLY: it never
 changes settings, installs software, or exploits anything on the target.

 MALAYSIA - Computer Crimes Act 1997 (Act 563): unauthorised access to a
 computer (s.3), access with intent to commit a further offence (s.4) and
 unauthorised modification (s.5) are criminal offences. Other jurisdictions
 have equivalent laws.

 Use ONLY on systems you own or hold WRITTEN authorisation to assess. Stay
 inside the agreed scope and time window. Stop immediately if authorisation
 is withdrawn or the scope is unclear (Ctrl+C, or: touch /tmp/cischeck.STOP).
==============================================================================
"""

STOP_FILES = (Path("STOP"), Path("/tmp/cischeck.STOP"))


# --------------------------------------------------------------- scope control
def parse_scope(entries: list[str]) -> list:
    """Turn user-declared scope strings into networks or lower-cased hostnames."""
    scope = []
    for raw in entries:
        item = raw.strip()
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            scope.append(item.lower())
            continue
        if net.num_addresses > MAX_SCOPE_ADDRESSES:
            raise SafetyError(f"Scope '{item}' is too broad (max {MAX_SCOPE_ADDRESSES} addresses).")
        scope.append(net)
    if not scope:
        raise SafetyError("Scope is empty. Declare it with --scope.")
    return scope


def check_target(target: str, scope: list, allow_public: bool = False) -> str:
    """Return the resolved IP if `target` is inside scope; raise SafetyError otherwise."""
    name = None
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        name = target.lower()
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(target))
        except OSError as exc:
            raise SafetyError(f"Cannot resolve target '{target}': {exc}") from exc
    if ip.is_global and not allow_public:
        raise SafetyError(f"{ip} is a public address. Refusing (use --allow-public only with written authorisation).")
    in_scope = any(
        (isinstance(s, str) and s == name) or (not isinstance(s, str) and ip in s) for s in scope
    )
    if not in_scope:
        raise SafetyError(f"Target {target} ({ip}) is OUTSIDE the declared scope.")
    return str(ip)


def enforce_time_window(window: str | None, now: datetime | None = None) -> None:
    """Refuse to run outside an agreed 'HH:MM-HH:MM' local-time window (overnight allowed)."""
    if not window:
        return
    match = re.fullmatch(r"(\d{2}):(\d{2})-(\d{2}):(\d{2})", window)
    if not match:
        raise SafetyError("--window must look like 09:00-18:00")
    h1, m1, h2, m2 = map(int, match.groups())
    if not (h1 < 24 and h2 < 24 and m1 < 60 and m2 < 60):
        raise SafetyError("--window contains an invalid time.")
    start, end = h1 * 60 + m1, h2 * 60 + m2
    now = now or datetime.now()
    current = now.hour * 60 + now.minute
    inside = start <= current <= end if start <= end else (current >= start or current <= end)
    if not inside:
        raise SafetyError(f"Outside the authorised time window {window} (now {now:%H:%M}).")


def confirm_authorization(target: str, ask=input) -> None:
    """Typed, target-specific confirmation. Cannot be bypassed with a flag."""
    phrase = f"I AM AUTHORIZED TO AUDIT {target}"
    print(f"\nTo continue, type exactly:\n  {phrase}")
    try:
        answer = ask("> ").strip()
    except EOFError as exc:
        raise SafetyError("No interactive confirmation available (stdin closed).") from exc
    if answer != phrase:
        raise SafetyError("Authorisation not confirmed. Nothing was contacted.")


# ------------------------------------------------------------------ kill switch
class KillSwitch:
    """Ctrl+C / SIGTERM / stop-file all lead to one clean abort path."""

    def __init__(self, stop_files=STOP_FILES):
        self.stop_files = stop_files
        self.requested = False

    def install(self) -> None:
        stale = [str(p) for p in self.stop_files if p.exists()]
        if stale:
            raise SafetyError(f"Stop file present ({', '.join(stale)}). Delete it to start a new run.")
        signal.signal(signal.SIGINT, self._handler)
        signal.signal(signal.SIGTERM, self._handler)

    def _handler(self, signum, frame):
        self.requested = True
        raise Aborted(f"signal {signum}")

    def check(self) -> None:
        """Call between every remote operation."""
        if self.requested or any(p.exists() for p in self.stop_files):
            raise Aborted("stop requested")


# --------------------------------------------------------------- read-only guard
_DENY_VERBS = (
    r"\b(Set|New|Remove|Add|Enable|Disable|Start|Stop|Restart|Install|Uninstall|Clear|Register|"
    r"Unregister|Grant|Revoke|Invoke|Export|Import|Copy|Move|Rename|Reset|Update|Write|Save|Send|"
    r"Push|Format)-[A-Za-z]+"
)
_DENY_OTHER = (
    r"\bOut-File\b|\bOut-Printer\b|>|\biex\b|DownloadString|\bwmic\b|\bschtasks\b|\bshutdown\b|"
    r"\bbcdedit\b|\btaskkill\b|\breg(\.exe)?\s+(add|delete|import)\b|"
    r"\bsc(\.exe)?\s+(config|stop|start|delete|create)\b|"
    r"\bnet(\.exe)?\s+(user|localgroup|stop|start|use|share|accounts\s+/)"
)
_DENY = re.compile(f"{_DENY_VERBS}|{_DENY_OTHER}", re.IGNORECASE)


def assert_read_only(script: str) -> None:
    """Every script is checked before it leaves the Kali box. Any state-changing verb aborts."""
    hit = _DENY.search(script)
    if hit:
        raise SafetyError(f"Read-only guard blocked a command: '{hit.group(0)}'")
