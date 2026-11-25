# CISHawk — CIS Benchmark Checker

**Attack Category:** Auditing 
**Course:** IKB31603 Ethical Hacking   
**Team Name:** hacker gebus  
**Team Members:** 
  1. MUHAMMAD AMMAR FADHLI BIN NOOR ANIM (52215125029)
  2. MUHAMMAD DANIAL FITRI BIN MAT DARUS (52215125232)
  3. WAN NUR ALISYA AYUNI BINTI WAN ZAIDI (52215125259)
  4. FARHAN IMAN BIN AHMAD RIDHUAN (52215124293)
---

## 1. Overview & Description

**CISHawk** is a lightweight, read-only Linux security auditing and CIS Benchmark compliance checker written in Python. Inspired by automated system auditing frameworks, CISHawk inspects critical local Linux configurations—including system file permissions, SSH hardening parameters, password aging policies, kernel hardening flags, and firewall status—to calculate a weighted **CIS Compliance Score (0–100%)** and provide actionable remediation commands.

CISHawk is engineered with strict ethical guardrails: safe local defaults (`127.0.0.1`), a `--dry-run` simulation mode, a clean `Ctrl+C` kill switch, mandatory legal authorization confirmation, and local-only labeled reporting with zero external data transmission.

---

## 2. Attack Lifecycle Mapping

CISHawk supports defensive auditing and blue-team hardening across multiple phases of the ethical hacking lifecycle:

| Lifecycle Phase | Role of CISHawk |
| :--- | :--- |
| **1. Reconnaissance / Local Enumeration** | Gathers read-only baseline configuration states (file modes, active SSH directives, kernel parameters, and firewall state) without modifying the host. |
| **2. Vulnerability & Misconfiguration Assessment** | Evaluates collected configurations against CIS Linux Benchmark controls to identify privilege escalation risks, weak authentication policies, and missing host protections. |
| **3. Exploitation Prevention (Gap Analysis)** | Maps detected misconfigurations to potential attack vectors (e.g., weak `/etc/shadow` permissions or `PermitRootLogin yes`) before adversaries can abuse them. |
| **4. Reporting & Remediation** | Computes a weighted severity score (`High`, `Medium`, `Low`), outputs clear terminal findings, and exports a labeled local report containing step-by-step hardening fixes. |

---

## 3. Architecture & Workflow Diagram

```text
[User Runs CLI]
       │
       ▼
[Legal Disclaimer & Authorization Gate] ──(Declined)──▶ [Exit Cleanly]
       │ (Confirmed: y/yes)
       ▼
[Scope Validation (Default: 127.0.0.1)]
       │
       ├──(--dry-run)──▶ [List Planned CIS Checks & Exit]
       │
       ▼
[Read-Only Audit Modules] ◀──(Ctrl+C Kill Switch)──▶ [Abort Cleanly]
  ├── File Permissions (/etc/passwd, /etc/shadow, /etc/group)
  ├── SSH Hardening (/etc/ssh/sshd_config)
  ├── Password & Account Policy (/etc/login.defs)
  ├── Kernel Hardening (ASLR, IP Forwarding)
  └── Firewall Status (UFW)
       │
       ▼
[Weighted Scoring Engine] ──▶ [Terminal Summary + Local ./audit_reports/ JSON/TXT]
```

---

## 4. Installation

### Prerequisites
- Linux environment (tested on Kali Linux / Ubuntu)
- Python 3.8 or higher

### Setup
```bash
# 1. Clone the repository
git clone https://github.com/pickpawcat/HACKER-GEBUS---AUDITING.git
cd HACKER-GEBUS---AUDITING

# 2. (Optional) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 5. Usage Examples

> **Note:** Verify these flags against `python3 -m cischeck --help` so every example matches your exact `cli.py` arguments.

### Display Help & Available Flags
```bash
python3 -m cischeck --help
```

### Run a Dry-Run Simulation (Safe Preview Without System Reads)
```bash
python3 -m cischeck --dry-run
```

### Run Standard CIS Audit Against Safe Default (`127.0.0.1`)
```bash
python3 -m cischeck
```

### Run Unit Tests
```bash
python3 -m unittest discover -s tests
```

*(Note: Certain system checks such as `/etc/shadow` or firewall status may require elevated read privileges via `sudo python3 -m cischeck`.)*

---

## 6. Screenshots

### CLI Execution & Legal Disclaimer Banner
*(Drag & drop screenshot terminal korang di sini semasa edit di GitHub)*

### Generated Local Audit Report Preview
<img width="1859" height="861" alt="Screenshot 2026-11-25 182526" src="https://github.com/user-attachments/assets/754edb28-eb4b-4e8a-852d-4b0bcd41133e" />
<img width="1851" height="486" alt="Screenshot 2026-11-25 182933" src="https://github.com/user-attachments/assets/0a16ed12-f34f-42c4-8ee5-89e46688e86b" />



---

## 7. Ethical Considerations & Safety Guardrails

- **Safe Defaults:** The tool defaults strictly to `127.0.0.1` / `localhost` (or isolated test/demo data) so accidental execution never targets external infrastructure.
- **Dry-Run Mode:** Supports a dry-run preview mode so operators can inspect planned benchmark checks before querying system configurations.
- **Kill Switch:** Intercepts `SIGINT` (`Ctrl+C`) to abort execution cleanly without leaving orphaned processes or corrupt state.
- **Local Data Handling (No Exfiltration):** Performs zero outbound data transmission. All generated audit reports are stored strictly locally in a clearly labeled output directory and excluded from version control via `.gitignore`.

---

## 8. Rules of Engagement (RoE)

Operators using CISHawk must strictly follow these Rules of Engagement:

1. **Authorized Scope:** Execution is restricted solely to systems owned by the operator (`localhost` / `127.0.0.1`) or lab/target systems covered by explicit written authorization.
2. **Time Windows:** Audits on shared or organizational hosts must only be conducted within approved testing or maintenance windows agreed upon with the system administrator.
3. **Permitted Techniques:** Read-only inspection of system configuration files, file permissions, kernel parameters, and host security controls.
4. **Prohibited Actions:**
   - Scanning or auditing unauthorized external IPs, university production infrastructure, or third-party systems.
   - Modifying host configurations, weakening permissions, or running exploitation payloads.
   - Exfiltrating or publicly publishing raw host audit outputs or sensitive system metadata.
5. **Emergency Stop Procedures:** Press `Ctrl+C` (`SIGINT`) at any time to invoke the built-in kill switch and terminate execution immediately. If unexpected host behavior occurs on a shared environment, halt all testing and notify the system owner or lab supervisor immediately.

---

## 9. Responsible Disclosure Policy

If CISHawk identifies a critical security misconfiguration on an authorized system:

- **Who to Notify:** Report the finding privately to the authorized system owner, organizational IT security team, or lab coordinator. For critical infrastructure or public-sector systems in Malaysia, coordinate through **MyCERT / CyberSecurity Malaysia** (`cyber999@cybersecurity.my`).
- **When to Notify:** Submit an initial confidential notification within **24–48 hours** of discovery. Do not publicly disclose findings until remediation is confirmed or a standard **90-day coordinated disclosure window** has passed.
- **How to Notify:** Send a private, structured report detailing the affected CIS control, observed misconfiguration, risk severity, minimal non-sensitive reproduction steps, and recommended remediation command—excluding raw credential files or full host dumps.

---

## 10. Legal Disclaimer

This tool is developed strictly for **educational purposes and authorized security auditing**. Unauthorized access to or modification of computer systems is an offense under the **Malaysia Computer Crimes Act 1997 (Act 563)** and equivalent international cybercrime laws.

On startup, CISHawk displays this legal warning and requires explicit confirmation that the operator holds proper authorization for the target scope. The authors accept no liability for misuse, unauthorized scanning, or resulting damages.

---

## 11. Limitations

- **OS Compatibility:** Primarily designed for Linux environments (Kali Linux / Ubuntu); paths and service checks may vary on RHEL-based distributions, macOS, or Windows.
- **Privilege Dependency:** Running without `sudo` limits visibility into restricted files (such as `/etc/shadow` or active firewall rules), which are handled gracefully without crashing.
- **Selected CIS Controls:** Audits a curated subset of high-impact CIS Linux Benchmark controls rather than the full enterprise benchmark suite.
- **Read-Only Design:** Recommends remediation steps for manual administrator review rather than applying automatic system changes, avoiding unintended service disruption.

---

## 12. License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
