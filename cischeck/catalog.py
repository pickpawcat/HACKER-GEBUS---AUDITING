"""Declarative check catalogue. Data only: adding a check never needs new logic.

`cis_ref` values ending in ".x" mean the section is known but the exact number
differs between benchmark releases; verify against the release you cite.
`missing` = status when the setting is not configured (what the OS default means).
"""
from dataclasses import dataclass

BENCHMARK_LABEL = "CIS Microsoft Windows 10/11 Benchmark (selected controls)"


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    section: str
    cis_ref: str
    severity: str          # High | Medium | Low
    kind: str              # registry | netaccounts | firewall | guest | defender | service | audit
    target: tuple          # kind-specific lookup key
    op: str                # eq | in | ge | le | between | includes
    expected: object
    missing: str           # PASS | FAIL | REVIEW
    fix: str


SYS = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
LSA = r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
WKS = r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
SRV = r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
POL = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows"
EXP = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
TS = r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"


def _reg(cid, title, sec, ref, sev, path, name, op, exp, missing, fix):
    return Check(cid, title, sec, ref, sev, "registry", (path, name), op, exp, missing, fix)


def _simple(cid, title, sec, ref, sev, kind, target, op, exp, fix, missing="REVIEW"):
    return Check(cid, title, sec, ref, sev, kind, target, op, exp, missing, fix)


A, F, U, L, N, W, R, S, D = ("Account Policies", "Windows Firewall", "User Account Control",
                             "Interactive Logon", "Network & Authentication",
                             "Windows Components", "Remote Access", "System Services",
                             "Audit Policy")

CHECKS = [
    # --- Account policies (read from `net accounts`, no file written on target) ---
    _simple("ACC-01", "Password history >= 24", A, "1.1.1", "Medium", "netaccounts", ("history",), "ge", 24,
            "Set 'Enforce password history' to 24 or more."),
    _simple("ACC-02", "Maximum password age 1-365 days", A, "1.1.2", "Medium", "netaccounts", ("max_age",), "between", [1, 365],
            "Set 'Maximum password age' to 365 days or fewer (not 0/unlimited)."),
    _simple("ACC-03", "Minimum password age >= 1 day", A, "1.1.3", "Low", "netaccounts", ("min_age",), "ge", 1,
            "Set 'Minimum password age' to 1 or more days."),
    _simple("ACC-04", "Minimum password length >= 14", A, "1.1.4", "High", "netaccounts", ("min_len",), "ge", 14,
            "Set 'Minimum password length' to 14 or more characters."),
    _simple("ACC-05", "Account lockout duration >= 15 min", A, "1.2.1", "Medium", "netaccounts", ("lockout_duration",), "ge", 15,
            "Set 'Account lockout duration' to 15 or more minutes."),
    _simple("ACC-06", "Account lockout threshold 1-5", A, "1.2.2", "High", "netaccounts", ("lockout_threshold",), "between", [1, 5],
            "Set 'Account lockout threshold' to 5 or fewer invalid attempts (not 0)."),
    _simple("ACC-07", "Reset lockout counter >= 15 min", A, "1.2.x", "Low", "netaccounts", ("lockout_window",), "ge", 15,
            "Set 'Reset account lockout counter after' to 15 or more minutes."),
    _simple("ACC-08", "Built-in Guest account disabled", A, "2.3.1.x", "Medium", "guest", ("Enabled",), "eq", False,
            "Disable the built-in Guest account."),
    # --- Windows Firewall ---
    *[_simple(f"FW-0{i * 2 + 1}", f"Firewall enabled ({p})", F, f"9.{i + 1}.1", "High", "firewall", (p, "Enabled"), "eq", "True",
              f"Turn Windows Defender Firewall on for the {p} profile.")
      for i, p in enumerate(["Domain", "Private", "Public"])],
    *[_simple(f"FW-0{i * 2 + 2}", f"Default inbound action Block ({p})", F, f"9.{i + 1}.2", "Medium", "firewall", (p, "Inbound"), "eq", "Block",
              f"Set the {p} profile inbound connections default to Block.")
      for i, p in enumerate(["Domain", "Private", "Public"])],
    # --- Antivirus (best practice, not a numbered CIS control) ---
    _simple("AV-01", "Defender antivirus enabled", F, "Best practice", "High", "defender", ("AV",), "eq", True,
            "Enable Microsoft Defender Antivirus (or document the approved AV)."),
    _simple("AV-02", "Defender real-time protection on", F, "Best practice", "High", "defender", ("RTP",), "eq", True,
            "Enable real-time protection."),
    _simple("AV-03", "Defender signatures <= 7 days old", F, "Best practice", "Medium", "defender", ("SigAge",), "le", 7,
            "Update Defender signatures and verify update source."),
    # --- UAC ---
    _reg("UAC-01", "UAC enabled (EnableLUA)", U, "2.3.17.x", "High", SYS, "EnableLUA", "eq", 1, "FAIL",
         "Enable 'Run all administrators in Admin Approval Mode'."),
    _reg("UAC-02", "Admin elevation prompts for consent", U, "2.3.17.x", "Medium", SYS, "ConsentPromptBehaviorAdmin", "in", [1, 2], "FAIL",
         "Set admin elevation prompt to 'Prompt for consent on the secure desktop'."),
    _reg("UAC-03", "Standard users auto-deny elevation", U, "2.3.17.x", "Low", SYS, "ConsentPromptBehaviorUser", "eq", 0, "REVIEW",
         "Set standard-user elevation to 'Automatically deny'."),
    _reg("UAC-04", "Elevation prompt on secure desktop", U, "2.3.17.x", "Medium", SYS, "PromptOnSecureDesktop", "eq", 1, "FAIL",
         "Enable 'Switch to the secure desktop when prompting for elevation'."),
    _reg("UAC-05", "Admin Approval Mode for built-in Administrator", U, "2.3.17.1", "Medium", SYS, "FilterAdministratorToken", "eq", 1, "FAIL",
         "Enable Admin Approval Mode for the built-in Administrator."),
    # --- Interactive logon ---
    _reg("LOG-01", "Do not display last signed-in user", L, "2.3.7.x", "Low", SYS, "DontDisplayLastUserName", "eq", 1, "FAIL",
         "Enable 'Do not display last user name'."),
    _reg("LOG-02", "Machine inactivity limit 1-900 s", L, "2.3.7.x", "Medium", SYS, "InactivityTimeoutSecs", "between", [1, 900], "FAIL",
         "Set 'Machine inactivity limit' to 900 seconds or fewer."),
    _reg("LOG-03", "Cached logons <= 4", L, "2.3.7.x", "Low", r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
         "CachedLogonsCount", "le", 4, "REVIEW", "Set cached logon count to 4 or fewer."),
    # --- Network & authentication ---
    _reg("NET-01", "NTLMv2 only (LmCompatibilityLevel 5)", N, "2.3.11.x", "High", LSA, "LmCompatibilityLevel", "eq", 5, "FAIL",
         "Set 'LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM'."),
    _reg("NET-02", "LM hash storage disabled", N, "2.3.11.x", "High", LSA, "NoLMHash", "eq", 1, "PASS",
         "Enable 'Do not store LAN Manager hash value on next password change'."),
    _reg("NET-03", "Restrict anonymous enumeration", N, "2.3.10.x", "Medium", LSA, "RestrictAnonymous", "eq", 1, "FAIL",
         "Enable 'Do not allow anonymous enumeration of shares'."),
    _reg("NET-04", "Restrict anonymous SAM enumeration", N, "2.3.10.x", "Medium", LSA, "RestrictAnonymousSAM", "eq", 1, "PASS",
         "Enable 'Do not allow anonymous enumeration of SAM accounts'."),
    _reg("NET-05", "Everyone excludes Anonymous", N, "2.3.10.x", "Medium", LSA, "EveryoneIncludesAnonymous", "eq", 0, "PASS",
         "Disable 'Let Everyone permissions apply to anonymous users'."),
    _reg("NET-06", "SMB client signing required", N, "2.3.8.1", "Medium", WKS, "RequireSecuritySignature", "eq", 1, "FAIL",
         "Enable 'Microsoft network client: Digitally sign communications (always)'."),
    _reg("NET-07", "SMB server signing required", N, "2.3.9.x", "Medium", SRV, "RequireSecuritySignature", "eq", 1, "FAIL",
         "Enable 'Microsoft network server: Digitally sign communications (always)'."),
    _reg("NET-08", "SMBv1 server disabled", N, "18.4.x", "High", SRV, "SMB1", "eq", 0, "REVIEW",
         "Disable the SMBv1 server (Set-SmbServerConfiguration -EnableSMB1Protocol $false)."),
    _reg("NET-09", "SMBv1 client driver disabled", N, "18.4.x", "High", r"HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10",
         "Start", "eq", 4, "REVIEW", "Disable the SMBv1 client driver (mrxsmb10 Start=4)."),
    _reg("NET-10", "WDigest plaintext credentials off", N, "18.4.x", "High",
         r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", "eq", 0, "PASS",
         "Set WDigest UseLogonCredential to 0."),
    _reg("NET-11", "LLMNR disabled", N, "18.6.4.x", "Medium", r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
         "EnableMulticast", "eq", 0, "FAIL", "Disable multicast name resolution (LLMNR)."),
    _reg("NET-12", "SMB plaintext passwords disabled", N, "2.3.8.x", "High", WKS, "EnablePlainTextPassword", "eq", 0, "PASS",
         "Disable sending unencrypted passwords to third-party SMB servers."),
    # --- Windows components ---
    _reg("WIN-01", "AutoRun default = do not execute", W, "18.x", "Medium", EXP, "NoAutorun", "eq", 1, "FAIL",
         "Set default AutoRun behaviour to 'Do not execute any autorun commands'."),
    _reg("WIN-02", "AutoRun disabled on all drives", W, "18.x", "Medium", EXP, "NoDriveTypeAutoRun", "eq", 255, "FAIL",
         "Turn off AutoPlay for all drives."),
    _reg("WIN-03", "AlwaysInstallElevated off", W, "18.x", "High", POL + r"\Installer", "AlwaysInstallElevated", "eq", 0, "PASS",
         "Disable 'Always install with elevated privileges'."),
    _reg("WIN-04", "Security log >= 196608 KB", W, "18.10.x", "Medium", POL + r"\EventLog\Security", "MaxSize", "ge", 196608, "FAIL",
         "Set Security event log maximum size to 196,608 KB or more."),
    _reg("WIN-05", "PowerShell script block logging", W, "18.10.x", "Medium", POL + r"\PowerShell\ScriptBlockLogging",
         "EnableScriptBlockLogging", "eq", 1, "FAIL", "Enable PowerShell Script Block Logging."),
    _reg("WIN-06", "Automatic updates not disabled", W, "18.10.x", "High", POL + r"\WindowsUpdate\AU", "NoAutoUpdate", "eq", 0, "PASS",
         "Do not disable automatic updates by policy."),
    _reg("WIN-07", "Diagnostic data limited (0-1)", W, "18.10.x", "Low", POL + r"\DataCollection", "AllowTelemetry", "between", [0, 1], "REVIEW",
         "Set 'Allow Diagnostic Data' to Basic or lower."),
    _reg("WIN-08", "WinRM service: Basic auth off", W, "18.10.x", "High", POL + r"\WinRM\Service", "AllowBasic", "eq", 0, "PASS",
         "Disable Basic authentication on the WinRM service."),
    _reg("WIN-09", "WinRM service: unencrypted traffic off", W, "18.10.x", "High", POL + r"\WinRM\Service", "AllowUnencryptedTraffic", "eq", 0, "PASS",
         "Disallow unencrypted WinRM traffic."),
    # --- Remote access ---
    _reg("RDP-01", "Remote Desktop connections denied", R, "18.10.x", "Medium", TS, "fDenyTSConnections", "eq", 1, "REVIEW",
         "Disable Remote Desktop unless required; if required, restrict via firewall/groups."),
    _reg("RDP-02", "RDP requires NLA", R, "18.10.x", "High", TS + r"\WinStations\RDP-Tcp", "UserAuthentication", "eq", 1, "REVIEW",
         "Require Network Level Authentication for Remote Desktop."),
    # --- Services (absent counts as compliant) ---
    *[_simple(f"SVC-0{i + 1}", f"{title} service disabled", S, "5.x", sev, "service", (name,), "in", ["Disabled", "Absent"],
              f"Set the {name} service start type to Disabled.", missing="PASS")
      for i, (name, title, sev) in enumerate([("RemoteRegistry", "Remote Registry", "Medium"), ("TlntSvr", "Telnet", "High"),
                                              ("SNMP", "SNMP", "Medium"), ("SSDPSRV", "SSDP Discovery", "Low"),
                                              ("upnphost", "UPnP Device Host", "Low")])],
    # --- Advanced audit policy (needs admin on target) ---
    _simple("AUD-01", "Audit Credential Validation: S+F", D, "17.1.1", "Medium", "audit", ("Credential Validation",), "includes", ["Success", "Failure"],
            "Audit Credential Validation for Success and Failure."),
    _simple("AUD-02", "Audit Security Group Mgmt: Success", D, "17.2.x", "Low", "audit", ("Security Group Management",), "includes", ["Success"],
            "Audit Security Group Management for Success."),
    _simple("AUD-03", "Audit User Account Mgmt: S+F", D, "17.2.x", "Medium", "audit", ("User Account Management",), "includes", ["Success", "Failure"],
            "Audit User Account Management for Success and Failure."),
    _simple("AUD-04", "Audit Process Creation: Success", D, "17.3.x", "Medium", "audit", ("Process Creation",), "includes", ["Success"],
            "Audit Process Creation for Success."),
    _simple("AUD-05", "Audit Account Lockout: Failure", D, "17.5.x", "Low", "audit", ("Account Lockout",), "includes", ["Failure"],
            "Audit Account Lockout for Failure."),
    _simple("AUD-06", "Audit Logon: S+F", D, "17.5.x", "Medium", "audit", ("Logon",), "includes", ["Success", "Failure"],
            "Audit Logon for Success and Failure."),
    _simple("AUD-07", "Audit Policy Change: Success", D, "17.7.x", "Low", "audit", ("Audit Policy Change",), "includes", ["Success"],
            "Audit Audit Policy Change for Success."),
]

SECTIONS = sorted({c.section for c in CHECKS})
