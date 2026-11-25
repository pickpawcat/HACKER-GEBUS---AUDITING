"""Synthetic Windows 11 snapshot used by --demo. Contains no real system data."""
from .catalog import EXP, LSA, POL, SRV, SYS, WKS

DEMO_NET_ACCOUNTS = """Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              8
Length of password history maintained:                5
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
"""

DEMO_SNAPSHOT = {
    "os": {"Caption": "Microsoft Windows 11 Pro (DEMO)", "Version": "10.0.22631", "Build": "22631", "Host": "DEMO-WIN11"},
    "registry": {
        f"{SYS}|EnableLUA": 1, f"{SYS}|ConsentPromptBehaviorAdmin": 5, f"{SYS}|PromptOnSecureDesktop": 1,
        f"{SYS}|DontDisplayLastUserName": 1, f"{SYS}|InactivityTimeoutSecs": 900,
        f"{LSA}|LmCompatibilityLevel": 3, f"{LSA}|NoLMHash": 1, f"{LSA}|RestrictAnonymous": 0,
        f"{WKS}|RequireSecuritySignature": 0, f"{SRV}|RequireSecuritySignature": 1,
        f"{SRV}|SMB1": 0, f"{EXP}|NoDriveTypeAutoRun": 255,
        f"{POL}\\EventLog\\Security|MaxSize": 32768,
        f"{POL}\\PowerShell\\ScriptBlockLogging|EnableScriptBlockLogging": 1,
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections": 1,
        r"HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10|Start": 4,
    },
    "netaccounts": DEMO_NET_ACCOUNTS,
    "firewall": {"Domain": {"Enabled": "True", "Inbound": "Block"},
                 "Private": {"Enabled": "True", "Inbound": "Block"},
                 "Public": {"Enabled": "False", "Inbound": "Block"}},
    "guest": {"Name": "Guest", "Enabled": False},
    "defender": {"AV": True, "RTP": True, "SigAge": 12},
    "services": {"RemoteRegistry": {"Start": "Disabled", "Status": "Stopped"}, "TlntSvr": None,
                 "SNMP": None, "SSDPSRV": {"Start": "Manual", "Status": "Stopped"}, "upnphost": None},
    "audit": {"Credential Validation": "No Auditing", "Security Group Management": "Success",
              "User Account Management": "Success and Failure", "Process Creation": "No Auditing",
              "Account Lockout": "Failure", "Logon": "Success and Failure", "Audit Policy Change": "Success"},
}
