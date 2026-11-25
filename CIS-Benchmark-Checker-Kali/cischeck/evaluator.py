"""Compares collected values with catalogue expectations. Pure logic: no I/O, easy to test."""
from __future__ import annotations

import re
from collections import Counter

from .catalog import CHECKS, Check

KIND_SECTION = {"registry": "registry", "netaccounts": "netaccounts", "firewall": "firewall",
                "guest": "guest", "defender": "defender", "service": "services", "audit": "audit"}
NUMERIC_OPS = {"ge", "le", "between"}


def _num(value):
    """Registry/`net accounts` values arrive as ints or numeric strings; normalise."""
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value.strip())
    return value


def _is_num(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


OPS = {
    "eq": lambda a, e: a == e,
    "in": lambda a, e: a in e,
    "ge": lambda a, e: a >= e,
    "le": lambda a, e: a <= e,
    "between": lambda a, e: e[0] <= a <= e[1],
    "includes": lambda a, e: all(token.lower() in str(a).lower() for token in e),
}


def _lookup(check: Check, snapshot: dict):
    """Return (section_error | None, found, actual)."""
    section = snapshot.get(KIND_SECTION[check.kind])
    if section is None:
        return "section not collected", False, None
    if isinstance(section, dict) and "__error__" in section:
        return section["__error__"], False, None
    if check.kind == "registry":
        value = section.get(f"{check.target[0]}|{check.target[1]}")
        return None, value is not None, value
    if check.kind == "firewall":
        value = section.get(check.target[0], {}).get(check.target[1])
        return None, value is not None, value
    if check.kind == "service":
        if check.target[0] not in section:
            return None, False, None
        svc = section[check.target[0]]
        return None, True, "Absent" if svc is None else svc.get("Start")
    value = section.get(check.target[0])
    return None, value is not None, value


def evaluate(check: Check, snapshot: dict) -> dict:
    error, found, actual = _lookup(check, snapshot)
    base = {"id": check.id, "title": check.title, "section": check.section, "cis_ref": check.cis_ref,
            "severity": check.severity, "expected": f"{check.op} {check.expected}", "remediation": check.fix}
    if error:
        return {**base, "status": "ERROR", "actual": "n/a", "evidence": f"Could not collect: {error}"}
    if not found:
        return {**base, "status": check.missing, "actual": "not configured",
                "evidence": "Setting not present; the OS default applies."}
    actual = _num(actual)
    if check.op in NUMERIC_OPS and not _is_num(actual):
        return {**base, "status": "REVIEW", "actual": str(actual),
                "evidence": "Value is not numeric (non-English OS or unexpected format)."}
    ok = OPS[check.op](actual, check.expected)
    return {**base, "status": "PASS" if ok else "FAIL", "actual": str(actual),
            "evidence": f"Observed {actual!r}; required {check.op} {check.expected!r}."}


def evaluate_all(snapshot: dict, checks=CHECKS) -> list[dict]:
    results = []
    for check in checks:
        try:
            results.append(evaluate(check, snapshot))
        except Exception as exc:  # one bad check must never sink the audit
            results.append({"id": check.id, "title": check.title, "section": check.section,
                            "cis_ref": check.cis_ref, "severity": check.severity, "expected": "",
                            "actual": "n/a", "status": "ERROR", "evidence": f"Evaluator error: {exc}",
                            "remediation": check.fix})
    return results


def summarize(results: list[dict]) -> dict:
    counts = Counter(r["status"] for r in results)
    decided = counts["PASS"] + counts["FAIL"]
    by_section = {}
    for r in results:
        sec = by_section.setdefault(r["section"], Counter())
        sec[r["status"]] += 1
    return {
        "pass": counts["PASS"], "fail": counts["FAIL"], "review": counts["REVIEW"],
        "error": counts["ERROR"], "total": len(results),
        "compliance_pct": round(100 * counts["PASS"] / decided, 1) if decided else 0.0,
        "high_severity_failures": sum(1 for r in results if r["status"] == "FAIL" and r["severity"] == "High"),
        "by_section": {k: dict(v) for k, v in sorted(by_section.items())},
    }
