"""Builds the read-only PowerShell queries, runs them via a backend, parses the output."""
from __future__ import annotations

import json

from . import safety
from .catalog import CHECKS

ERR = '@{__error__=$_.Exception.Message} | ConvertTo-Json -Compress'
STOP = "$ErrorActionPreference='Stop'\n"

SECTION_SCRIPTS = {
    "os": STOP + """try { Get-CimInstance -ClassName Win32_OperatingSystem | ForEach-Object {
  @{Caption=[string]$_.Caption;Version=[string]$_.Version;Build=[string]$_.BuildNumber;Host=[string]$_.CSName} } |
  ConvertTo-Json -Compress } catch { %ERR% }""",
    "registry": STOP + """try { $r=@{}
foreach ($e in @(%PAIRS%)) { $k=$e[0]+'|'+$e[1]
  try { $r[$k]=(Get-ItemProperty -Path $e[0] -Name $e[1] -ErrorAction Stop).($e[1]) } catch { $r[$k]=$null } }
$r | ConvertTo-Json -Compress } catch { %ERR% }""",
    "netaccounts": STOP + """try { @{text=(net accounts | Out-String)} | ConvertTo-Json -Compress } catch { %ERR% }""",
    "firewall": STOP + """try { $f=@{}
Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
  $f[[string]$_.Name]=@{Enabled=[string]$_.Enabled;Inbound=[string]$_.DefaultInboundAction} }
$f | ConvertTo-Json -Compress } catch { %ERR% }""",
    "guest": STOP + """try { Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | ForEach-Object {
  @{Name=[string]$_.Name;Enabled=[bool]$_.Enabled} } | ConvertTo-Json -Compress } catch { %ERR% }""",
    "defender": STOP + """try { Get-MpComputerStatus | ForEach-Object {
  @{AV=[bool]$_.AntivirusEnabled;RTP=[bool]$_.RealTimeProtectionEnabled;SigAge=[int]$_.AntivirusSignatureAge} } |
  ConvertTo-Json -Compress } catch { %ERR% }""",
    "services": STOP + """try { $s=@{}
foreach ($n in @(%SERVICES%)) { $x=Get-Service -Name $n -ErrorAction SilentlyContinue
  if ($x) { $s[$n]=@{Start=[string]$x.StartType;Status=[string]$x.Status} } else { $s[$n]=$null } }
$s | ConvertTo-Json -Compress } catch { %ERR% }""",
    "audit": STOP + """try { $a=@{}
auditpol /get /category:* /r | Where-Object { $_ -match ',' } | ConvertFrom-Csv | ForEach-Object {
  $a[[string]$_.Subcategory]=[string]$_.'Inclusion Setting' }
if ($a.Count -eq 0) { throw 'auditpol returned no data (administrator rights required)' }
$a | ConvertTo-Json -Compress } catch { %ERR% }""",
}

NET_FIELDS = ["force_logoff", "min_age", "max_age", "min_len", "history",
              "lockout_threshold", "lockout_duration", "lockout_window", "role"]
ZERO_WORDS = {"never", "none", "unlimited"}


class BackendError(Exception):
    """Transport or authentication failure."""


def _ps_list(items) -> str:
    return ",".join("'" + i.replace("'", "''") + "'" for i in items)


def build_sections(checks=CHECKS) -> dict[str, str]:
    pairs = sorted({c.target for c in checks if c.kind == "registry"})
    services = sorted({c.target[0] for c in checks if c.kind == "service"})
    reg_literal = ",".join(f"@({_ps_list(p)})" for p in pairs)
    scripts = {}
    for name, template in SECTION_SCRIPTS.items():
        scripts[name] = (template.replace("%ERR%", ERR).replace("%PAIRS%", reg_literal)
                         .replace("%SERVICES%", _ps_list(services)))
    return scripts


def parse_net_accounts(text: str) -> dict:
    """Parse `net accounts` by line position (labels are locale-dependent, order is not)."""
    values = [ln.rsplit(":", 1)[1].strip() for ln in text.splitlines() if ":" in ln]
    parsed = {}
    for field, raw in zip(NET_FIELDS, values):
        if raw.isdigit():
            parsed[field] = int(raw)
        elif raw.lower() in ZERO_WORDS:
            parsed[field] = 0
        else:
            parsed[field] = raw
    return parsed


def collect(backend, killswitch, log=print) -> dict:
    """Run every section sequentially, checking the kill switch before each remote call."""
    snapshot = {}
    for name, script in build_sections().items():
        killswitch.check()
        safety.assert_read_only(script)
        log(f"[*] Collecting: {name}")
        try:
            raw = backend.run(script).strip()
            data = json.loads(raw) if raw else {"__error__": "empty output"}
        except BackendError:
            if name == "os":      # cannot even reach the host: stop instead of 8 errors
                raise
            data = {"__error__": "remote query failed"}
        except json.JSONDecodeError:
            data = {"__error__": "unparseable output"}
        if name == "netaccounts" and "text" in data:
            data = parse_net_accounts(data["text"])
        snapshot[name] = data
    return snapshot
