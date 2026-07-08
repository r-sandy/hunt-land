# hunt-procs.ps1 - Phase 1: volatile process-tree carving (Windows)
# Hunts lineage anomalies: server daemons and Office spawning shells, encoded
# command lines, execution from user-writable paths, name masquerading,
# svchost/lsass lineage violations. Read-only.
#
# Tuning.md: the masquerade + tmp-exec checks are the high-precision core of
# this phase - they stay HIGH. Lineage checks cite parent and child so the
# analyst can verify in one look.

[CmdletBinding()]
param(
    [switch]$Tree,   # also print the full process tree
    [switch]$Quiet   # findings only, skip informational output
)

$ErrorActionPreference = 'SilentlyContinue'
foreach ($lib in @("$PSScriptRoot\..\lib\hunt-common.ps1", "$PSScriptRoot\hunt-common.ps1")) {
    if (Test-Path -LiteralPath $lib) { . $lib; $libOk = $true; break }
}
if (-not $libOk) { Write-Error 'hunt-common.ps1 not found'; exit 1 }

if (-not $Quiet) { Hunt-Header ("hunt-procs v{0} ({1}) @ {2}" -f $script:HuntVersion, $script:HuntPlatform, (Hunt-Timestamp)) }
Require-AdminOrWarn

# ---- full process snapshot ----------------------------------------------------
$procs = @(Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine)
$byPid = @{}
foreach ($p in $procs) { $byPid[[uint32]$p.ProcessId] = $p }

# PIDs belonging to this hunt (self + ancestors) - never flag our own tooling
$selfPids = @()
$cur = [uint32]$PID
while ($cur -and $byPid.ContainsKey($cur) -and $selfPids.Count -lt 10) {
    $selfPids += $cur
    $cur = [uint32]$byPid[$cur].ParentProcessId
}

function Get-ParentName([object]$Proc) {
    $pp = [uint32]$Proc.ParentProcessId
    if ($byPid.ContainsKey($pp)) { return $byPid[$pp].Name }
    return '?'
}

if ($Tree) {
    Hunt-Header 'Process tree'
    $children = @{}
    foreach ($p in $procs) {
        $pp = [uint32]$p.ParentProcessId
        if (-not $children.ContainsKey($pp)) { $children[$pp] = @() }
        $children[$pp] += $p
    }
    $printed = @{}
    function Show-Branch([object]$Proc, [int]$Depth) {
        if ($printed.ContainsKey([uint32]$Proc.ProcessId)) { return }
        $printed[[uint32]$Proc.ProcessId] = $true
        Write-Host ("{0}{1,-6} {2}" -f ('  ' * $Depth), $Proc.ProcessId, $Proc.Name)
        if ($children.ContainsKey([uint32]$Proc.ProcessId)) {
            foreach ($c in ($children[[uint32]$Proc.ProcessId] | Sort-Object ProcessId)) {
                if ([uint32]$c.ProcessId -ne [uint32]$Proc.ProcessId) { Show-Branch $c ($Depth + 1) }
            }
        }
    }
    foreach ($p in ($procs | Sort-Object ProcessId)) {
        $pp = [uint32]$p.ParentProcessId
        if (-not $byPid.ContainsKey($pp) -or $pp -eq [uint32]$p.ProcessId) { Show-Branch $p 0 }
    }
    foreach ($p in ($procs | Sort-Object ProcessId)) { Show-Branch $p 0 }
}

function Trim-Cmd([string]$Cmd, [int]$Max = 180) {
    if (-not $Cmd) { return '(cmdline unavailable)' }
    if ($Cmd.Length -gt $Max) { return $Cmd.Substring(0, $Max) + '...' }
    return $Cmd
}

$shells = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'powershell_ise.exe')
$scriptHosts = @('wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe')

# ---- 1. server daemon / Office / browser -> shell lineage (T1059) -------------
if (-not $Quiet) { Hunt-Info 'checking for daemons, Office apps and browsers spawning shells...' }
$serverParents = @('w3wp.exe', 'sqlservr.exe', 'httpd.exe', 'nginx.exe', 'tomcat.exe', 'tomcat8.exe', 'tomcat9.exe',
                   'mysqld.exe', 'postgres.exe', 'php-cgi.exe', 'inetinfo.exe', 'exchangetransport.exe')
$officeParents = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe', 'acrord32.exe', 'acrobat.exe')
$browserParents = @('chrome.exe', 'msedge.exe', 'firefox.exe', 'iexplore.exe', 'brave.exe')

foreach ($p in $procs) {
    if ($selfPids -contains [uint32]$p.ProcessId) { continue }
    $name = ('' + $p.Name).ToLower()
    if (($shells + $scriptHosts) -notcontains $name) { continue }
    $parent = ('' + (Get-ParentName $p)).ToLower()
    if ($serverParents -contains $parent) {
        Add-Finding HIGH T1059 ("PID {0}: shell/script host '{1}' spawned by server daemon '{2}' - cmdline: {3}" -f $p.ProcessId, $name, $parent, (Trim-Cmd $p.CommandLine))
    } elseif ($officeParents -contains $parent) {
        Add-Finding HIGH T1059 ("PID {0}: '{1}' spawned by Office/reader app '{2}' (macro/exploit pattern) - cmdline: {3}" -f $p.ProcessId, $name, $parent, (Trim-Cmd $p.CommandLine))
    } elseif ($browserParents -contains $parent) {
        Add-Finding MEDIUM T1059 ("PID {0}: '{1}' spawned by browser '{2}' - verify it is a known native-messaging helper. cmdline: {3}" -f $p.ProcessId, $name, $parent, (Trim-Cmd $p.CommandLine))
    }
}

# ---- 2. encoded / download-cradle / hidden command lines (T1059.001, T1027) ---
if (-not $Quiet) { Hunt-Info 'checking command lines for encoding, hiding and cradle patterns...' }
$encRx = '(?i)(\s-e(nc?|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\s*\(|-nop\b.*-w(indowstyle)?\s+hid)'
foreach ($p in $procs) {
    if ($selfPids -contains [uint32]$p.ProcessId) { continue }
    $cmd = '' + $p.CommandLine
    if (-not $cmd -or $cmd -match '(?i)hunt-(procs|land|lolbin|net|persist|memory)') { continue }
    if ($cmd -match $encRx) {
        Add-Finding HIGH T1059.001 ("PID {0} ({1}): encoded/hidden/cradle command line: {2}" -f $p.ProcessId, $p.Name, (Trim-Cmd $cmd))
    }
}

# ---- 3. executables running from user-writable paths (T1036) ------------------
if (-not $Quiet) { Hunt-Info 'checking for execution from Temp, Public, Downloads...' }
foreach ($p in $procs) {
    $exe = '' + $p.ExecutablePath
    if ($exe -and $exe -match $script:HuntVolatilePathRx) {
        Add-Finding HIGH T1036 ("PID {0}: executing from user-writable/volatile path: {1}" -f $p.ProcessId, $exe)
    }
}

# ---- 4. masquerading: trusted names in untrusted paths + lineage (T1036) ------
if (-not $Quiet) { Hunt-Info 'checking for name-masquerading and system-process lineage violations...' }
$sysNames = @('svchost.exe', 'lsass.exe', 'csrss.exe', 'services.exe', 'winlogon.exe', 'smss.exe',
              'wininit.exe', 'taskhostw.exe', 'dwm.exe', 'spoolsv.exe', 'explorer.exe', 'conhost.exe')
$winRoot = ('' + $env:SystemRoot).ToLower()
foreach ($p in $procs) {
    $name = ('' + $p.Name).ToLower()
    if ($sysNames -notcontains $name) { continue }
    $exe = '' + $p.ExecutablePath
    if ($exe -and $winRoot -and -not $exe.ToLower().StartsWith($winRoot)) {
        Add-Finding HIGH T1036 ("PID {0}: trusted name '{1}' running OUTSIDE {2}: {3}" -f $p.ProcessId, $p.Name, $env:SystemRoot, $exe)
    }
}

# svchost must be a child of services.exe; lsass must never have children
foreach ($p in $procs) {
    $name = ('' + $p.Name).ToLower()
    if ($name -eq 'svchost.exe') {
        $parent = ('' + (Get-ParentName $p)).ToLower()
        if ($parent -notin @('services.exe', '?')) {
            Add-Finding HIGH T1036 ("PID {0}: svchost.exe with anomalous parent '{1}' (expected services.exe) - cmdline: {2}" -f $p.ProcessId, $parent, (Trim-Cmd $p.CommandLine))
        }
    }
}
$lsass = $procs | Where-Object { ('' + $_.Name).ToLower() -eq 'lsass.exe' }
foreach ($l in @($lsass)) {
    $kids = @($procs | Where-Object { [uint32]$_.ParentProcessId -eq [uint32]$l.ProcessId })
    foreach ($k in $kids) {
        Add-Finding HIGH T1003 ("PID {0}: lsass.exe spawned child '{1}' (PID {2}) - lsass should never have children" -f $l.ProcessId, $k.Name, $k.ProcessId)
    }
}

Show-FindingSummary
