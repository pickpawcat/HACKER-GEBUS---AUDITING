# CIS Benchmark Checker (Kali Remote Edition)

**Attack Category:** Category 5 — Auditing  
**Course:** IKB31603 Ethical Hacking (UniKL MIIT — October 2026)  
**Team:** hacker gebus  
**Release:** `v1.0.0`

### Team Members
1. MUHAMMAD AMMAR FADHLI BIN NOOR ANIM (`52215125029`)
2. MUHAMMAD DANIAL FITRI BIN MAT DARUS (`52215125232`)
3. WAN NUR ALISYA AYUNI BINTI WAN ZAIDI (`52215125259`)
4. FARHAN IMAN BIN AHMAD RIDHUAN (`52215124293`)

---

## 1. Overview & Description

**CIS Benchmark Checker (Kali Remote Edition)** is a read-only security configuration auditor written in Python (~650 meaningful lines of code, backed by 21 unit tests). Running from **Kali Linux**, the tool connects to an authorised **Windows 10/11** machine over **WinRM**, collects settings using a fixed set of read-only PowerShell queries in 8 short batches, and evaluates them locally against **60 controls** aligned with the **CIS Microsoft Windows Benchmark**.

The tool never modifies the target system and writes no files to it. Results are displayed on the console and exported locally into `./output` (with owner-only permissions) as **JSON, CSV, and HTML** reports containing the observed value, required value, severity, CIS reference, and remediation step.

### Control Coverage (60 Controls)
| Domain | Controls |
| :--- | :---: |
| Account & Lockout Policy | 8 |
| Firewall & Windows Defender | 9 |
| User Account Control (UAC) | 5 |
| Interactive Logon | 3 |
| Network & Authentication (SMB signing, SMBv1, NTLM, LLMNR) | 12 |
| Windows Components | 9 |
| Remote Access | 2 |
| Risky Services | 5 |
| Advanced Audit Policy | 7 |
| **Total** | **60** |

---

## 2. Architecture & Workflow Diagram

The design strictly separates **remote read-only collection** from **local pure-logic evaluation**, allowing every rule to be unit-tested without a Windows target via an offline mock backend (`demo_data.py`).

```text
[CLI Entry: cli.py / __main__.py]
        │
        ▼
[Ethical Gate: safety.py]
  ├── Computer Crimes Act 1997 banner & typed target-specific confirmation (no bypass flag)
  ├── Mandatory scope enforcement (max /24, one target per run, public IPs refused by default)
  ├── Authorised local time-window enforcement (--window HH:MM-HH:MM)
  └── Kill switch hooks (Ctrl+C, SIGTERM, touch /tmp/cischeck.STOP)
        │
        ├── (No mode flag) ──▶ [Dry-Run Plan against 127.0.0.1 — Touches Nothing]
        ├── (--demo)       ──▶ [MockBackend using demo_data.py — No Network]
        │
        ▼ (--live explicitly supplied)
[Read-Only Collection: collector.py + backends.py]
  ├── Pre-flight read-only deny-list guard inspects every PowerShell script
  └── 8 read-only WinRM batches (kill switch checked before every call)
        │
        ▼
[Local Evaluation: evaluator.py + catalog.py]
  └── Evaluates 60 data-driven controls (eq, in, ge, le, between, includes, not-configured rules)
        │
        ▼
[Local Reporting: report.py]
  └── Console summary + owner-only ./output/ (JSON, CSV formula-safe, HTML, raw evidence snapshot)
```

### Module Structure
- `cischeck/catalog.py` — Stores all 60 CIS-aligned controls as structured data.
- `cischeck/collector.py` — Builds the fixed set of 8 read-only PowerShell query batches.
- `cischeck/backends.py` — Executes queries via `WinRMBackend` or replays synthetic data offline via `MockBackend`.
- `cischeck/demo_data.py` — Synthetic Windows 11 dataset for offline demonstration and testing.
- `cischeck/evaluator.py` — Evaluates observed settings against expected values and per-control "not configured" rules.
- `cischeck/report.py` — Writes console summaries and local JSON, CSV (with OWASP CSV injection neutralisation), and HTML reports.
- `cischeck/safety.py` — Enforces the legal banner, scope limits, public-IP refusal, time window, read-only guard, and kill switch.
- `cischeck/cli.py` & `cischeck/__main__.py` — Command-line interface orchestrating all modules.
- `tests/test_cischeck.py` — 21 unit tests verifying evaluator operators, refusals, kill switch, and read-only enforcement.

---

## 3. Attack Lifecycle Mapping

As a defensive auditing tool, CIS Benchmark Checker maps to the pre-exploitation assessment phases of **NIST SP 800-115** and deliberately stops before exploitation:

| Lifecycle Phase | What the Tool Does | Modules |
| :--- | :--- | :--- |
| **1. Planning & Authorisation** | Displays the Computer Crimes Act 1997 banner; enforces scope and time window; requires a typed, target-specific confirmation. | `safety.py`, `cli.py` |
| **2. Reconnaissance / Enumeration** | Identifies OS and build; collects registry, policy, firewall, service, Defender, and audit settings in 8 read-only batches. | `collector.py`, `backends.py` |
| **3. Vulnerability / Misconfiguration Analysis** | Evaluates each value against the catalogue (`eq`, `in`, `ge`, `le`, `between`, `includes`) and applies per-control rules for "not configured" settings. | `evaluator.py`, `catalog.py` |
| **4. Reporting** | Produces Console, JSON, CSV, and HTML reports with evidence, severity, and remediation steps; keeps the raw snapshot as labelled evidence. | `report.py` |
| **5. Exploitation, Persistence, Exfiltration** | Intentionally **not implemented**. The tool only observes. | `N/A` |

---

## 4. Installation

### Prerequisites
- Kali Linux (or Debian/Ubuntu-based Linux)
- Python 3.8 or higher
- For `--live` runs: an authorised Windows 10/11 machine with WinRM enabled (`Enable-PSRemoting`) and valid administrator credentials

### Setup
```bash
# 1. Clone the repository
git clone [https://github.com/pickpawcat/HACKER-GEBUS---AUDITING.git](https://github.com/pickpawcat/HACKER-GEBUS---AUDITING.git)
cd HACKER-GEBUS---AUDITING

# 2. (Optional) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 5. Usage Examples

Run via `python3 -m cischeck` from the repository root (or `cischeck` if installed as a package).

### Show Help & All CLI Options
```bash
python3 -m cischeck --help
```

### List All 60 Auditable CIS Controls
```bash
python3 -m cischeck --list-checks
```

### Safe Default Dry-Run (Targets `127.0.0.1` — Touches Nothing)
```bash
python3 -m cischeck
```

### Run Full Pipeline on Built-In Synthetic Data (No Network Required)
```bash
python3 -m cischeck --demo
```
*(Offline synthetic Windows 11 baseline result: **39 Pass, 17 Fail, 4 Review, 0 Error — 69.6% Compliance**, where `Compliance = PASS / (PASS + FAIL)` and `REVIEW`/`ERROR` are never counted as a pass.)*

### Run a Live Read-Only Audit Against an Authorised Lab Windows VM
```bash
python3 -m cischeck --live --target 192.168.56.101 --scope 192.168.56.0/24 -u 'LABPC\auditor'
```

### Live Audit with WinRM over HTTPS, Time Window, Engagement ID & Specific Sections
```bash
python3 -m cischeck --live --target win11-lab --scope win11-lab -u auditor \
  --ssl --window 09:00-18:00 --engagement-id LAB-2026-01 \
  --sections "Windows Firewall,Account Policies"
```

### Key CLI Flags
| Flag | Description |
| :--- | :--- |
| `--target` | Host to audit (default: `127.0.0.1`). |
| `--scope` | Authorised IP/CIDR (max `/24`) or hostname; repeatable. Required for non-loopback targets. |
| `-u`, `--username` | Audit account (`HOST\auditor` or `DOMAIN\user`). Required with `--live`. |
| `--password-env VAR` | Read password from an environment variable instead of interactive prompt. |
| `--ssl` / `--insecure` | Use WinRM over HTTPS (port `5986`); `--insecure` skips certificate verification (lab only). |
| `--port` / `--timeout` | Custom WinRM port (default `5985`, or `5986` with `--ssl`) and per-query timeout in seconds (default `30`). |
| `--window HH:MM-HH:MM` | Enforces an authorised local time window; refuses execution outside it. |
| `--engagement-id` | Engagement/RoE ticket reference embedded in generated reports (default: `UNSPECIFIED`). |
| `--sections` | Comma-separated subset of CIS sections to audit. |
| `--output-dir` | Local report output directory (default: `./output`, owner-only permissions). |
| `--no-html` | Skip HTML report generation (writes Console, JSON, and CSV only). |
| `--allow-public` | Explicitly permit a public IP (requires written authorisation). |
| `--live` / `--demo` / `--list-checks` | Execution mode (mutually exclusive; defaults to dry-run if omitted). |

### Run the Unit Test Suite (21 Tests)
```bash
python3 -m unittest discover -s tests -v
```

---

## 6. Screenshots

### CLI Execution & Ethical Confirmation Gate
<img width="1156" height="761" alt="Screenshot 2026-11-26 134220" src="https://github.com/user-attachments/assets/e759f799-7819-4529-baac-2dd1fb55e393" />


### Generated Local HTML Audit Report
<img width="1851" height="486" alt="Screenshot 2026-11-25 182933" src="https://github.com/user-attachments/assets/7b9bf810-5938-4b60-9071-bec1e8513e5e" />
<img width="1859" height="861" alt="Screenshot 2026-11-25 182526" src="https://github.com/user-attachments/assets/a130eb5a-5bc9-4757-a4fe-3e53033a1f20" />


---

## 7. Ethical Considerations & Safety Guardrails

Every guardrail is enforced directly in code (`safety.py` and `cli.py`) to prevent realistic operational mistakes:

- **Dry-Run by Default (`--live` Required):** Running with no flags defaults to `127.0.0.1` and prints only the audit plan without contacting any host.
- **Strict Scope Enforcement:** Requires an explicit `--scope` (maximum `/24`), restricts execution to **one target per run**, and refuses public IPs unless `--allow-public` is explicitly supplied.
- **Typed Target-Specific Confirmation (No Bypass Flag):** Refuses generic `--yes` shortcuts; operators must consciously type the exact target after reviewing the legal disclaimer.
- **Time-Window Enforcement:** Restricts live audits to agreed engagement hours via `--window` (supporting overnight windows) to reduce operational impact.
- **Code-Enforced Read-Only Guard:** A pre-flight deny-list inspects every PowerShell script before it leaves Kali Linux, aborting immediately if any state-changing verb, redirect, `reg add`, `net user`, or `net accounts /...` mutation is detected.
- **Multi-Channel Kill Switch:** Supports `Ctrl+C`, `SIGTERM`, and a stop file (`touch /tmp/cischeck.STOP`), checked before every one of the 8 remote batches (alongside per-query timeouts) to abort cleanly with exit code `130`.
- **Data Minimisation & Local Storage:** Collects configuration values only—never password hashes, user lists, personal files, or event logs. Passwords are prompted interactively via `getpass` (or `--password-env`) and are never stored or logged. Reports stay strictly local in `./output` with owner-only permissions, labelled `CONFIDENTIAL`, excluded from Git via `.gitignore`, and sanitised against CSV formula injection (OWASP).

---

## 8. Rules of Engagement (RoE)

Operators must strictly follow these Rules of Engagement before running CIS Benchmark Checker:

1. **Authorized Scope:** Live auditing (`--live`) is permitted strictly against Windows 10/11 hosts owned by the operator or explicitly documented in written authorisation, within a maximum `/24` boundary and one target per run. Public IPs are prohibited unless explicitly authorised in writing.
2. **Time Windows:** Live audits must only be conducted within the pre-approved testing window enforced via `--window` (including authorised overnight maintenance windows) to avoid operational disruption.
3. **Permitted Techniques:** Read-only WinRM execution of the 8 fixed, guard-validated PowerShell query batches defined in `collector.py`, and offline evaluation via `--demo`.
4. **Prohibited Actions:**
   - Auditing any host without explicit prior written authorisation.
   - Modifying target configurations, writing files to the target (e.g., `secedit /export`), running state-changing commands, or bypassing the read-only guard.
   - Exfiltrating or collecting credentials, hashes, user lists, or sensitive host files, or committing generated output files to public repositories.
5. **Emergency Stop Procedures:** Immediately abort an active scan via `Ctrl+C`, `SIGTERM`, or from another terminal using `touch /tmp/cischeck.STOP` (exits cleanly with code `130` without writing a report or modifying the target). If an unexpected issue arises on an authorised target, stop testing immediately and notify the system owner or lab supervisor.

---

## 9. Responsible Disclosure Policy

When CIS Benchmark Checker identifies security misconfigurations or High-severity failures on an authorised system:

- **Who to Notify:** Deliver findings exclusively to the **authorised system owner** named in the engagement authorisation (or designated IT security contact / lab supervisor). For critical national or public-sector infrastructure in Malaysia, coordinate escalation through **MyCERT / CyberSecurity Malaysia** (`cyber999@cybersecurity.my`).
- **When to Notify:** Flag **High-severity failures for prompt notification** (within 24–48 hours of discovery). Public discussion or write-ups are strictly prohibited unless explicit written consent is granted after an agreed remediation period.
- **How to Notify:** Transmit the `CONFIDENTIAL`-labelled local report strictly over an **access-controlled, encrypted channel**. Include only the affected CIS control ID, observed vs. required configuration, severity, and remediation guidance—never attach credentials or unrelated host data.

---

## 10. Legal Disclaimer

This tool is developed strictly for **educational purposes and authorised defensive security auditing**. Unauthorised access to computer systems or data is a criminal offence under the **Malaysia Computer Crimes Act 1997 (Act 563)** and equivalent international cybercrime statutes.

On startup, CIS Benchmark Checker displays this legal notice and requires explicit, target-specific confirmation before any live connection is attempted. The authors assume no liability for misuse, unauthorised auditing, or damages resulting from improper use of this software.

---

## 11. Limitations

- **Selected-Control Audit (Not Certification):** Audits 60 selected CIS-aligned controls and is not an official CIS certification. Control section numbers marked `.x` vary across CIS benchmark releases and must be verified against the cited benchmark version.
- **Target WinRM Dependencies:** Live auditing depends on target configuration—WinRM enabled, administrator privileges (accounting for UAC remote token filtering on local non-built-in admin accounts), and **English-language** system output (for `net accounts` parsing). Unreadable settings are logged as `ERROR` or `REVIEW` rather than crashing the audit.
- **Read-Only Only:** Reports remediation steps for administrator review and deliberately does not apply automatic system changes.

---

## 12. License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
