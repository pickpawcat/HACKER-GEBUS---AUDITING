# CISHawk — CIS Benchmark Checker

**Attack Category:** Auditing (Category 5)  
**Course:** IKB31603 Ethical Hacking — Universiti Kuala Lumpur (UniKL MIIT)  
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
