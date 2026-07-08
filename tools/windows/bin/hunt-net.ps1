# hunt-net.ps1 - Phase 2: network socket <-> process cross-referencing (Windows)
# Flags native binaries egressing to raw external IPs, odd listeners, and
# (with -Watch) constant-interval beaconing candidates. Read-only.
#
# Tuning.md: this phase is high-value but unusable without a baseline - so it
# supports one. Capture a known-good snapshot with -SaveBaseline on a healthy
# host, then hunt with -Baseline: baselined proc/peer/port pairs are
# suppressed, and the generic uncommon-port heuristic (the noisy part) is only
# raised to MEDIUM when a baseline is in play; without one it stays LOW.

[CmdletBinding()]
param(
    [switch]$Watch,                 # beaconing detection over repeated samples
    [int]$Samples = 6,
    [int]$IntervalSec = 10,
    [switch]$All,                   # dump the full connection table first
    [string]$Baseline,              # known-good pairs file to suppress
    [string]$SaveBaseline           # write current external pairs and exit
)

$ErrorActionPreference = 'SilentlyContinue'
foreach ($lib in @("$PSScriptRoot\..\lib\hunt-common.ps1", "$PSScriptRoot\hunt-common.ps1")) {
    if (Test-Path -LiteralPath $lib) { . $lib; $libOk = $true; break }
}
if (-not $libOk) { Write-Error 'hunt-common.ps1 not found'; exit 1 }

Hunt-Header ("hunt-net v{0} ({1}) @ {2}" -f $script:HuntVersion, $script:HuntPlatform, (Hunt-Timestamp))
Require-AdminOrWarn

$procName = @{}
$procPath = @{}
foreach ($p in Get-Process) {
    $procName[[int]$p.Id] = $p.ProcessName + '.exe'
    if ($p.Path) { $procPath[[int]$p.Id] = $p.Path }
}

# -> objects: Proc, ProcPid, Peer, Port, Path
function Get-EstablishedSnapshot {
    foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
        $owner = [int]$c.OwningProcess
        $name = if ($procName.ContainsKey($owner)) { $procName[$owner] } else { '?' }
        $path = if ($procPath.ContainsKey($owner)) { $procPath[$owner] } else { '' }
        [pscustomobject]@{
            Proc = $name.ToLower(); ProcPid = $owner
            Peer = '' + $c.RemoteAddress; Port = [int]$c.RemotePort; Path = $path
        }
    }
}

$snap = @(Get-EstablishedSnapshot)

if ($SaveBaseline) {
    $lines = $snap | Where-Object { -not (Test-PrivateIP $_.Peer) } |
        ForEach-Object { "{0}`t{1}`t{2}" -f $_.Proc, $_.Peer, $_.Port } | Sort-Object -Unique
    Set-Content -LiteralPath $SaveBaseline -Value $lines
    Hunt-Ok ("baseline written: {0} external pair(s) -> {1}" -f @($lines).Count, $SaveBaseline)
    exit 0
}

$baselineSet = @{}
if ($Baseline -and (Test-Path -LiteralPath $Baseline)) {
    foreach ($line in Get-Content -LiteralPath $Baseline) {
        if ($line.Trim()) { $baselineSet[$line.Trim()] = $true }
    }
    Hunt-Info ("baseline loaded: {0} known-good pair(s) will be suppressed" -f $baselineSet.Count)
} elseif ($Baseline) {
    Hunt-Warn ("baseline file not found: {0} - proceeding without" -f $Baseline)
}

function Test-Baselined([object]$Conn) {
    $baselineSet.ContainsKey(("{0}`t{1}`t{2}" -f $Conn.Proc, $Conn.Peer, $Conn.Port))
}

if ($All) {
    Hunt-Header 'Established connections (proc pid peer port)'
    $snap | Sort-Object Proc | Format-Table Proc, ProcPid, Peer, Port -AutoSize | Out-String | Write-Host
}

$commonPorts = @(22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443)
# native binaries that have no business egressing to the internet
$noEgress = @('spoolsv.exe', 'lsass.exe', 'services.exe', 'winlogon.exe', 'smss.exe', 'csrss.exe',
              'searchindexer.exe', 'taskhostw.exe', 'wininit.exe', 'lsm.exe')
# shells / script hosts / LOLBins that egress = strong signal
$shellNet = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
              'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'msbuild.exe', 'installutil.exe')

# ---- 1. external egress analysis (T1071) --------------------------------------
Hunt-Info ("analyzing {0} established connection(s)..." -f $snap.Count)
$seen = @{}
foreach ($c in $snap) {
    if (Test-PrivateIP $c.Peer) { continue }
    if ($c.ProcPid -eq $PID) { continue }
    if (Test-Baselined $c) { continue }
    $key = "{0}|{1}|{2}|{3}" -f $c.Proc, $c.ProcPid, $c.Peer, $c.Port
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true

    if ($noEgress -contains $c.Proc) {
        Add-Finding HIGH T1071 ("'{0}' (PID {1}) should not egress but is connected to {2}:{3}" -f $c.Proc, $c.ProcPid, $c.Peer, $c.Port)
    }
    if ($shellNet -contains $c.Proc) {
        Add-Finding HIGH T1059 ("shell/script host '{0}' (PID {1}) connected to {2}:{3} - possible reverse shell / download cradle" -f $c.Proc, $c.ProcPid, $c.Peer, $c.Port)
    }
    if ($c.Path -and $c.Path -match $script:HuntVolatilePathRx) {
        Add-Finding HIGH T1071 ("binary in user-writable path '{0}' (PID {1}) connected to {2}:{3}" -f $c.Path, $c.ProcPid, $c.Peer, $c.Port)
    }
    if ($commonPorts -notcontains $c.Port) {
        if ($baselineSet.Count -gt 0) {
            Add-Finding MEDIUM T1071 ("'{0}' (PID {1}) -> {2}:{3} (uncommon port, not in baseline)" -f $c.Proc, $c.ProcPid, $c.Peer, $c.Port)
        } else {
            Add-Finding LOW T1071 ("'{0}' (PID {1}) -> {2}:{3} (uncommon port; supply -Baseline to raise confidence)" -f $c.Proc, $c.ProcPid, $c.Peer, $c.Port)
        }
    }
}

# ---- 2. listener audit (T1571) -------------------------------------------------
Hunt-Info 'auditing listeners...'
foreach ($l in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
    if ($l.LocalAddress -in @('127.0.0.1', '::1')) { continue }
    $owner = [int]$l.OwningProcess
    $path = if ($procPath.ContainsKey($owner)) { $procPath[$owner] } else { '' }
    if ($path -and $path -match $script:HuntVolatilePathRx) {
        Add-Finding HIGH T1571 ("listener on port {0} owned by user-writable binary: {1} (PID {2})" -f $l.LocalPort, $path, $owner)
    }
}

# ---- 3. beaconing watch (T1071) --------------------------------------------------
if ($Watch) {
    Hunt-Info ("beacon watch: {0} samples every {1}s (total {2}s)..." -f $Samples, $IntervalSec, ($Samples * $IntervalSec))
    $counts = @{}
    for ($i = 1; $i -le $Samples; $i++) {
        foreach ($c in @(Get-EstablishedSnapshot)) {
            if (Test-PrivateIP $c.Peer) { continue }
            $key = "{0}|{1}|{2}|{3}" -f $c.Proc, $c.ProcPid, $c.Peer, $c.Port
            if ($counts.ContainsKey($key)) { $counts[$key]++ } else { $counts[$key] = 1 }
        }
        if ($i -lt $Samples) { Start-Sleep -Seconds $IntervalSec }
    }
    $threshold = [math]::Ceiling($Samples * 0.8)
    foreach ($key in $counts.Keys) {
        if ($counts[$key] -lt $threshold) { continue }
        $parts = $key -split '\|'
        Add-Finding HIGH T1071 ("persistent channel: '{0}' (PID {1}) held {2}:{3} across {4}/{5} samples - beaconing/C2 candidate" -f $parts[0], $parts[1], $parts[2], $parts[3], $counts[$key], $Samples)
    }
}

Show-FindingSummary
