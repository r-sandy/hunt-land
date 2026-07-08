# hunt-persist.ps1 - Phase 3: persistence & execution-surface sweep (Windows)
# Run/RunOnce keys, scheduled tasks, WMI event subscriptions, services,
# startup folders, IFEO debugger hijacks, Winlogon, PowerShell profiles.
# Read-only.
#
# Tuning.md: hunt-persist needs the most tuning per unit of value, so this
# port is deliberately conservative: HIGH only when the *content* of an entry
# matches adversary patterns; location/recency alone is MEDIUM; entries that
# are merely non-default are LOW or not reported. AppData-resident autoruns
# (OneDrive, Teams, updaters) are normal on Windows and are NOT flagged by
# path alone.

[CmdletBinding()]
param(
    [int]$Days = 30   # flag persistence artifacts modified within N days
)

$ErrorActionPreference = 'SilentlyContinue'
foreach ($lib in @("$PSScriptRoot\..\lib\hunt-common.ps1", "$PSScriptRoot\hunt-common.ps1")) {
    if (Test-Path -LiteralPath $lib) { . $lib; $libOk = $true; break }
}
if (-not $libOk) { Write-Error 'hunt-common.ps1 not found'; exit 1 }

Hunt-Header ("hunt-persist v{0} ({1}) @ {2} - window: {3}d" -f $script:HuntVersion, $script:HuntPlatform, (Hunt-Timestamp), $Days)
Require-AdminOrWarn

$cutoff = (Get-Date).AddDays(-$Days)

# adversary-characteristic content (HIGH when matched inside a persistence entry)
$susRx = '(?i)(-e(nc?|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}|frombase64string|downloadstring|downloadfile|invoke-webrequest|\biex\b|invoke-expression|-nop\b|-w(indowstyle)?\s+hid|mshta(\.exe)?\s+(http|vbscript|javascript)|regsvr32.*(/i:|scrobj)|rundll32.*javascript|certutil.*(-urlcache|-decode)|bitsadmin.*transfer|\.onion|\\Temp\\[^\s"]+\.(vbs|js|bat|ps1|hta)|\bnc(\.exe)?\s+-|ncat)'
# merely-suspicious location (MEDIUM): Temp / Public - NOT AppData generally
$susPathRx = '(?i)\\(AppData\\Local\\Temp|Windows\\Temp|Users\\Public|Recycle)\\'

function Trim-Val([string]$Value, [int]$Max = 160) {
    if (-not $Value) { return '' }
    if ($Value.Length -gt $Max) { return $Value.Substring(0, $Max) + '...' }
    return $Value
}

# ---- 1. Run / RunOnce keys (T1547.001) -----------------------------------------
Hunt-Info 'sweeping Run/RunOnce keys...'
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($key in $runKeys) {
    $item = Get-Item -LiteralPath $key -ErrorAction SilentlyContinue
    if (-not $item) { continue }
    foreach ($name in $item.GetValueNames()) {
        $val = '' + $item.GetValue($name)
        if (-not $val) { continue }
        if ($val -match $susRx) {
            Add-Finding HIGH T1547.001 ("Run key {0}\{1} contains suspicious command: {2}" -f $key, $name, (Trim-Val $val))
        } elseif ($val -match $susPathRx) {
            Add-Finding MEDIUM T1547.001 ("Run key {0}\{1} executes from Temp/Public: {2}" -f $key, $name, (Trim-Val $val))
        }
    }
}

# ---- 2. Scheduled tasks (T1053.005) ---------------------------------------------
Hunt-Info 'sweeping scheduled tasks (non-Microsoft paths)...'
foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    if ($task.TaskPath -like '\Microsoft\*') { continue }
    foreach ($action in @($task.Actions)) {
        $exec = '' + $action.Execute
        if (-not $exec) { continue }
        $full = ($exec + ' ' + $action.Arguments).Trim()
        if ($full -match $susRx) {
            Add-Finding HIGH T1053.005 ("scheduled task '{0}{1}' runs suspicious command: {2}" -f $task.TaskPath, $task.TaskName, (Trim-Val $full))
        } elseif ($full -match $susPathRx) {
            Add-Finding MEDIUM T1053.005 ("scheduled task '{0}{1}' executes from Temp/Public: {2}" -f $task.TaskPath, $task.TaskName, (Trim-Val $full))
        }
    }
}

# ---- 3. WMI event subscriptions (T1546.003) --------------------------------------
Hunt-Info 'checking WMI event subscriptions...'
foreach ($consumer in @(Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue)) {
    Add-Finding HIGH T1546.003 ("WMI CommandLineEventConsumer '{0}' runs: {1}" -f $consumer.Name, (Trim-Val ('' + $consumer.ExecutablePath + ' ' + $consumer.CommandLineTemplate)))
}
foreach ($consumer in @(Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue)) {
    Add-Finding HIGH T1546.003 ("WMI ActiveScriptEventConsumer '{0}' ({1}): {2}" -f $consumer.Name, $consumer.ScriptingEngine, (Trim-Val ('' + $consumer.ScriptText + $consumer.ScriptFileName)))
}

# ---- 4. Services (T1543.003) -------------------------------------------------------
Hunt-Info 'auditing service binary paths...'
foreach ($svc in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
    $path = '' + $svc.PathName
    if (-not $path) { continue }
    if ($path -match $susRx -or $path -match '(?i)\b(powershell|pwsh|mshta|wscript|cscript)(\.exe)?\b|\bcmd(\.exe)?\s+/c') {
        Add-Finding HIGH T1543.003 ("service '{0}' has interpreter/suspicious binPath: {1}" -f $svc.Name, (Trim-Val $path))
    } elseif ($path -match $susPathRx) {
        Add-Finding HIGH T1543.003 ("service '{0}' binPath in user-writable dir: {1}" -f $svc.Name, (Trim-Val $path))
    } elseif ($path -notmatch '^"' -and $path -match '\s' -and $path -notmatch '(?i)^\w:\\(windows|program files)') {
        Add-Finding LOW T1574.009 ("service '{0}' has unquoted binPath with spaces outside standard dirs: {1}" -f $svc.Name, (Trim-Val $path))
    }
}

# ---- 5. Startup folders (T1547.001) ---------------------------------------------
Hunt-Info 'sweeping startup folders...'
$startupDirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") +
    @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
foreach ($dir in $startupDirs) {
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)) {
        if ($f.Name -eq 'desktop.ini') { continue }
        if ($f.Extension -match '(?i)^\.(bat|cmd|vbs|js|ps1|hta|wsf)$') {
            $body = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
            if ($body -and $body -match $susRx) {
                Add-Finding HIGH T1547.001 ("startup script {0} contains suspicious command" -f $f.FullName)
                continue
            }
        }
        if ($f.LastWriteTime -gt $cutoff) {
            Add-Finding MEDIUM T1547.001 ("startup item modified within {0}d: {1} ({2})" -f $Days, $f.FullName, $f.LastWriteTime.ToString('yyyy-MM-dd'))
        }
    }
}

# ---- 6. IFEO debugger hijacks (T1546.012) ----------------------------------------
Hunt-Info 'checking Image File Execution Options debugger hijacks...'
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($sub in @(Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue)) {
    $dbg = '' + $sub.GetValue('Debugger')
    if (-not $dbg) { continue }
    if ($dbg -match '(?i)vsjitdebugger\.exe') {
        Add-Finding LOW T1546.012 ("IFEO debugger on {0} is Visual Studio JIT (usually benign): {1}" -f $sub.PSChildName, $dbg)
    } else {
        Add-Finding HIGH T1546.012 ("IFEO debugger hijack on {0}: {1}" -f $sub.PSChildName, (Trim-Val $dbg))
    }
}

# ---- 7. Winlogon Shell / Userinit (T1547.004) ------------------------------------
Hunt-Info 'checking Winlogon Shell/Userinit...'
$wl = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wl) {
    $shell = '' + $wl.GetValue('Shell')
    $userinit = '' + $wl.GetValue('Userinit')
    if ($shell -and $shell.Trim() -ne 'explorer.exe') {
        Add-Finding HIGH T1547.004 ("Winlogon Shell is not explorer.exe: {0}" -f (Trim-Val $shell))
    }
    if ($userinit -and $userinit.Trim().TrimEnd(',') -notmatch '(?i)^\w:\\windows\\system32\\userinit\.exe$') {
        Add-Finding HIGH T1547.004 ("Winlogon Userinit modified: {0}" -f (Trim-Val $userinit))
    }
}

# ---- 8. PowerShell profiles (T1546.013) -------------------------------------------
Hunt-Info 'checking PowerShell profiles...'
$profilePaths = @("$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1",
                  "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1") +
    @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Join-Path $_.FullName 'Documents\WindowsPowerShell\profile.ps1'
        Join-Path $_.FullName 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'
        Join-Path $_.FullName 'Documents\PowerShell\profile.ps1'
    })
foreach ($pp in $profilePaths) {
    if (-not (Test-Path -LiteralPath $pp)) { continue }
    $body = Get-Content -LiteralPath $pp -Raw -ErrorAction SilentlyContinue
    if ($body -and $body -match $susRx) {
        Add-Finding HIGH T1546.013 ("PowerShell profile contains suspicious command: {0}" -f $pp)
    } elseif ((Get-Item -LiteralPath $pp).LastWriteTime -gt $cutoff) {
        Add-Finding MEDIUM T1546.013 ("PowerShell profile modified within {0}d: {1}" -f $Days, $pp)
    }
}

Show-FindingSummary
