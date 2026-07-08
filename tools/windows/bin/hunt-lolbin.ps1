# hunt-lolbin.ps1 - Phase 5: LOLBin / LOLBAS usage audit (Windows)
# Scans live command lines AND (optionally) PSReadLine history for trusted
# binaries invoked in adversary-characteristic ways. Read-only.
#
# Tuning.md: hunt-lolbin is the sharpest instrument in the kit - behavior
# based, high precision. This port carries the largest pattern table and every
# pattern is anchored to a specific abused binary + abused flag combination,
# never to a binary name alone.

[CmdletBinding()]
param(
    [switch]$History   # also scan PSReadLine history (may contain benign admin activity)
)

$ErrorActionPreference = 'SilentlyContinue'
foreach ($lib in @("$PSScriptRoot\..\lib\hunt-common.ps1", "$PSScriptRoot\hunt-common.ps1")) {
    if (Test-Path -LiteralPath $lib) { . $lib; $libOk = $true; break }
}
if (-not $libOk) { Write-Error 'hunt-common.ps1 not found'; exit 1 }

Hunt-Header ("hunt-lolbin v{0} ({1}) @ {2}" -f $script:HuntVersion, $script:HuntPlatform, (Hunt-Timestamp))
Require-AdminOrWarn

# LOLBAS pattern table: regex / severity / ATT&CK / description
$patterns = @(
    # -- ingress tool transfer / download cradles --
    @{ Rx = '(?i)certutil(\.exe)?\s.*(-urlcache|-verifyctl|-ping)\s.*(http|\\\\)'; Sev = 'HIGH';   Atk = 'T1105';     Desc = 'certutil download cradle' },
    @{ Rx = '(?i)certutil(\.exe)?\s.*-(decode|encode)\b';                          Sev = 'HIGH';   Atk = 'T1140';     Desc = 'certutil base64 encode/decode chain' },
    @{ Rx = '(?i)bitsadmin(\.exe)?\s.*/transfer|start-bitstransfer\s.*http';       Sev = 'HIGH';   Atk = 'T1105';     Desc = 'BITS job file transfer' },
    @{ Rx = '(?i)(curl|wget)(\.exe)?\s.*(-o|--output|-outfile)\s*\S*\\(temp|public|appdata)\\'; Sev = 'HIGH'; Atk = 'T1105'; Desc = 'remote file staged to user-writable path' },
    @{ Rx = '(?i)(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient).*(\||;)\s*(\biex\b|invoke-expression)'; Sev = 'HIGH'; Atk = 'T1105'; Desc = 'PowerShell download-and-execute cradle' },
    @{ Rx = '(?i)\biex\b\s*\(\s*(new-object\s+net\.webclient|invoke-webrequest|\biwr\b)'; Sev = 'HIGH'; Atk = 'T1105'; Desc = 'IEX over web download' },
    @{ Rx = '(?i)esentutl(\.exe)?\s.*/y\s.*(http|\\\\)';                           Sev = 'MEDIUM'; Atk = 'T1105';     Desc = 'esentutl remote copy' },
    @{ Rx = '(?i)msiexec(\.exe)?\s.*(/i|/q).*http';                                Sev = 'HIGH';   Atk = 'T1218.007'; Desc = 'msiexec install from URL' },
    # -- signed-binary proxy execution --
    @{ Rx = '(?i)regsvr32(\.exe)?\s.*(/i:|scrobj\.dll|http)';                      Sev = 'HIGH';   Atk = 'T1218.010'; Desc = 'regsvr32 scriptlet proxy execution (Squiblydoo)' },
    @{ Rx = '(?i)rundll32(\.exe)?\s.*(javascript:|url\.dll|ieadvpack|advpack.*LaunchINFSection|shell32.*ShellExec_RunDLL)'; Sev = 'HIGH'; Atk = 'T1218.011'; Desc = 'rundll32 script/INF proxy execution' },
    @{ Rx = '(?i)mshta(\.exe)?\s+(https?:|vbscript:|javascript:)';                 Sev = 'HIGH';   Atk = 'T1218.005'; Desc = 'mshta remote/inline script execution' },
    @{ Rx = '(?i)msbuild(\.exe)?\s+\S*\\(temp|appdata|public|downloads)\\';        Sev = 'MEDIUM'; Atk = 'T1127.001'; Desc = 'msbuild project from user-writable path (inline-task execution)' },
    @{ Rx = '(?i)installutil(\.exe)?\s.*/logfile=\s*/u\b';                         Sev = 'MEDIUM'; Atk = 'T1218.004'; Desc = 'installutil uninstall-method proxy execution' },
    @{ Rx = '(?i)forfiles(\.exe)?\s.*/c\s';                                        Sev = 'MEDIUM'; Atk = 'T1202';     Desc = 'forfiles indirect command execution' },
    @{ Rx = '(?i)pcalua(\.exe)?\s+-a\s';                                           Sev = 'MEDIUM'; Atk = 'T1202';     Desc = 'pcalua indirect command execution' },
    # -- WMI / remote exec --
    @{ Rx = '(?i)wmic(\.exe)?\s.*process\s+call\s+create';                         Sev = 'HIGH';   Atk = 'T1047';     Desc = 'wmic process creation' },
    @{ Rx = '(?i)wmic(\.exe)?\s.*/format:\s*("|'')?\s*https?:';                    Sev = 'HIGH';   Atk = 'T1220';     Desc = 'wmic XSL script processing from URL' },
    # -- encoded / hidden PowerShell --
    @{ Rx = '(?i)(powershell|pwsh)(\.exe)?\s.*\s-e(nc?|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}'; Sev = 'HIGH'; Atk = 'T1059.001'; Desc = 'encoded PowerShell command' },
    @{ Rx = '(?i)(powershell|pwsh)(\.exe)?\s.*-nop\b.*-w(indowstyle)?\s+hid';      Sev = 'MEDIUM'; Atk = 'T1059.001'; Desc = 'no-profile hidden-window PowerShell' },
    @{ Rx = '(?i)frombase64string.*(\biex\b|invoke-expression)';                   Sev = 'HIGH';   Atk = 'T1140';     Desc = 'base64 payload decoded to execution' },
    # -- persistence / defense evasion via CLI --
    @{ Rx = '(?i)schtasks(\.exe)?\s.*/create\s.*(powershell|mshta|wscript|cscript|\\temp\\|\\appdata\\|-enc)'; Sev = 'HIGH'; Atk = 'T1053.005'; Desc = 'scheduled task created with script/temp payload' },
    @{ Rx = '(?i)reg(\.exe)?\s+add\s.*\\currentversion\\run';                      Sev = 'MEDIUM'; Atk = 'T1547.001'; Desc = 'Run-key persistence via reg add' },
    @{ Rx = '(?i)netsh(\.exe)?\s.*(interface\s+)?portproxy\s+add';                 Sev = 'HIGH';   Atk = 'T1090';     Desc = 'netsh port-proxy tunnel' },
    @{ Rx = '(?i)vssadmin(\.exe)?\s.*delete\s+shadows|wmic\s.*shadowcopy\s+delete'; Sev = 'HIGH';  Atk = 'T1490';     Desc = 'shadow-copy deletion (ransomware precursor)' },
    @{ Rx = '(?i)wevtutil(\.exe)?\s+cl\s';                                         Sev = 'HIGH';   Atk = 'T1070.001'; Desc = 'event-log clearing' },
    @{ Rx = '(?i)bcdedit(\.exe)?\s.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)'; Sev = 'HIGH'; Atk = 'T1490'; Desc = 'recovery tampering' },
    # -- credential access --
    @{ Rx = '(?i)rundll32(\.exe)?\s.*comsvcs(\.dll)?[,\s].*(minidump|#24)';        Sev = 'HIGH';   Atk = 'T1003.001'; Desc = 'LSASS dump via comsvcs MiniDump' },
    @{ Rx = '(?i)ntdsutil(\.exe)?\s.*(ifm|create\s+full)';                         Sev = 'HIGH';   Atk = 'T1003.003'; Desc = 'NTDS.dit extraction via ntdsutil' },
    @{ Rx = '(?i)reg(\.exe)?\s+save\s+hkl?m\\(sam|security|system)';               Sev = 'HIGH';   Atk = 'T1003.002'; Desc = 'registry hive dump (SAM/SECURITY/SYSTEM)' }
)

function Scan-Stream {
    param([string]$Source, [string[]]$Lines)
    foreach ($line in $Lines) {
        if (-not $line) { continue }
        if ($line -match '(?i)hunt-(lolbin|land|procs|net|persist|memory)') { continue }
        foreach ($pat in $patterns) {
            if ($line -match $pat.Rx) {
                $shown = if ($line.Length -gt 160) { $line.Substring(0, 160) + '...' } else { $line }
                Add-Finding $pat.Sev $pat.Atk ("{0}: {1}: {2}" -f $Source, $pat.Desc, $shown)
            }
        }
    }
}

# ---- live process command lines -------------------------------------------------
Hunt-Info 'scanning live command lines...'
$live = @(Get-CimInstance Win32_Process |
    Where-Object { [uint32]$_.ProcessId -ne [uint32]$PID } |
    ForEach-Object { $_.CommandLine } | Where-Object { $_ })
Scan-Stream -Source 'live-proc' -Lines $live

# ---- PSReadLine history (opt-in; can be noisy) -----------------------------------
if ($History) {
    Hunt-Info 'scanning PSReadLine history files...'
    $histFiles = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    })
    foreach ($hf in $histFiles) {
        if (-not (Test-Path -LiteralPath $hf)) { continue }
        Scan-Stream -Source ("hist:{0}" -f $hf) -Lines @(Get-Content -LiteralPath $hf -ErrorAction SilentlyContinue)
    }
}

Show-FindingSummary
