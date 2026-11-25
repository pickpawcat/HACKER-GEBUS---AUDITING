"""Writes labelled, local-only reports (JSON, CSV, HTML). Nothing is ever transmitted."""
from __future__ import annotations

import csv
import html
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

NOTICE = "CONFIDENTIAL - security audit evidence. Handle per the engagement agreement."
COLORS = {"PASS": "\033[32m", "FAIL": "\033[31m", "REVIEW": "\033[33m", "ERROR": "\033[35m"}
SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def make_output_dir(root: Path, target: str, stamp: datetime) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    path = (root / f"audit_{safe}_{stamp:%Y%m%d_%H%M%S}").expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection from target-supplied strings."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)


def print_console(results: list[dict], summary: dict, use_color: bool) -> None:
    def paint(status):
        return f"{COLORS[status]}{status:<6}\033[0m" if use_color else f"{status:<6}"
    print(f"\n{'ID':<8}{'STATUS':<8}{'SEV':<8}CHECK")
    print("-" * 78)
    for r in sorted(results, key=lambda x: (x["status"] != "FAIL", SEV_ORDER[x["severity"]], x["id"])):
        print(f"{r['id']:<8}{paint(r['status'])}  {r['severity']:<8}{r['title']}")
    print("-" * 78)
    print(f"PASS {summary['pass']} | FAIL {summary['fail']} | REVIEW {summary['review']} | "
          f"ERROR {summary['error']} | TOTAL {summary['total']}")
    print(f"Compliance (PASS / decided): {summary['compliance_pct']}%   "
          f"High-severity failures: {summary['high_severity_failures']}")


def _html(meta: dict, results: list[dict], summary: dict) -> str:
    esc = html.escape
    rows = "".join(
        f"<tr class='{r['status']}' data-s='{r['status']}'><td>{esc(r['id'])}</td><td>{esc(r['section'])}</td>"
        f"<td>{esc(r['title'])}<br><small>CIS {esc(r['cis_ref'])}</small></td><td>{esc(r['severity'])}</td>"
        f"<td><b>{r['status']}</b></td><td>{esc(r['evidence'])}</td><td>{esc(r['remediation'])}</td></tr>"
        for r in sorted(results, key=lambda x: (x["status"] != "FAIL", SEV_ORDER[x["severity"]], x["id"])))
    sections = "".join(
        f"<tr><td>{esc(k)}</td><td>{v.get('PASS', 0)}</td><td>{v.get('FAIL', 0)}</td><td>{v.get('REVIEW', 0)}</td>"
        f"<td>{v.get('ERROR', 0)}</td></tr>" for k, v in summary["by_section"].items())
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>CIS Audit - {esc(meta['target'])}</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;color:#1b1f24}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left;vertical-align:top;font-size:.9rem}}th{{background:#f6f8fa}}
.PASS b{{color:#1a7f37}}.FAIL b{{color:#cf222e}}.REVIEW b{{color:#9a6700}}.ERROR b{{color:#8250df}}
.card{{display:inline-block;border:1px solid #d0d7de;border-radius:8px;padding:.6rem 1.1rem;margin-right:.6rem}}
.card span{{display:block;font-size:1.6rem;font-weight:700}}.warn{{background:#fff8c5;padding:.6rem;border-radius:6px}}
button{{margin-right:.4rem;padding:.3rem .7rem}}</style></head><body>
<h1>CIS Benchmark Audit Report</h1><p class="warn">{esc(NOTICE)}</p>
<p><b>Target:</b> {esc(meta['target'])} &middot; <b>OS:</b> {esc(meta['os'])} &middot; <b>Engagement:</b> {esc(meta['engagement'])}<br>
<b>Run (UTC):</b> {esc(meta['timestamp_utc'])} &middot; <b>Malaysia time:</b> {esc(meta['timestamp_myt'])}<br>
<b>Baseline:</b> {esc(meta['baseline'])} &middot; <b>Tool:</b> v{esc(meta['version'])} {esc(meta['mode'])}</p>
<div><div class="card"><span>{summary['compliance_pct']}%</span>compliance</div><div class="card"><span>{summary['pass']}</span>pass</div>
<div class="card"><span>{summary['fail']}</span>fail</div><div class="card"><span>{summary['review']}</span>review</div>
<div class="card"><span>{summary['error']}</span>error</div></div>
<h2>By section</h2><table><tr><th>Section</th><th>Pass</th><th>Fail</th><th>Review</th><th>Error</th></tr>{sections}</table>
<h2>Findings</h2><p><button onclick="f('ALL')">All</button><button onclick="f('FAIL')">Fail</button>
<button onclick="f('REVIEW')">Review</button><button onclick="f('PASS')">Pass</button></p>
<table id="t"><tr><th>ID</th><th>Section</th><th>Check</th><th>Severity</th><th>Status</th><th>Evidence</th><th>Remediation</th></tr>{rows}</table>
<p><small>Selected-control audit; not a full CIS certification. Read-only: no setting on the target was changed.</small></p>
<script>function f(s){{document.querySelectorAll('#t tr[data-s]').forEach(r=>r.style.display=(s==='ALL'||r.dataset.s===s)?'':'none')}}</script>
</body></html>"""


def write_reports(out_dir: Path, meta: dict, snapshot: dict, results: list[dict],
                  summary: dict, include_html: bool = True) -> list[Path]:
    report = {"notice": NOTICE, "meta": meta, "summary": summary, "results": results}
    _write(out_dir / "audit_report.json", json.dumps(report, indent=2))
    _write(out_dir / "raw_snapshot_EVIDENCE.json",
           json.dumps({"notice": NOTICE, "contents": "Configuration values only; no credentials or user data.",
                       "data": snapshot}, indent=2))
    cols = ["id", "section", "title", "cis_ref", "severity", "status", "expected", "actual", "evidence", "remediation"]
    csv_path = out_dir / "audit_report.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([f"# {NOTICE}"])
        writer.writerow(cols)
        for r in results:
            writer.writerow([_csv_safe(r[c]) for c in cols])
    os.chmod(csv_path, 0o600)
    files = [out_dir / "audit_report.json", csv_path, out_dir / "raw_snapshot_EVIDENCE.json"]
    if include_html:
        _write(out_dir / "audit_report.html", _html(meta, results, summary))
        files.append(out_dir / "audit_report.html")
    return files


def utc_and_myt(now: datetime | None = None) -> tuple[str, str]:
    now = now or datetime.now(timezone.utc)
    return now.isoformat(timespec="seconds"), now.astimezone(timezone(timedelta(hours=8))).isoformat(timespec="seconds")
