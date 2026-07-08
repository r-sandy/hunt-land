# hunt-land.ps1 - orchestrator: runs the full LotL hunt pipeline on Windows
# and emits a single Compromise Assessment Report. Read-only by default.
#
# usage: hunt-land.ps1 [-Watch] [-History] [-Days N] [-Report FILE] [-Quick]
#                      [-Baseline FILE]
# exit codes: 0 clean - 1 medium signals present - 2 high-severity signals

[CmdletBinding()]
param(
    [switch]$Watch,      # include network beacon watch (adds ~60s)
    [switch]$History,    # scan PSReadLine history for LOLBin usage
    [int]$Days = 30,     # persistence lookback window
    [string]$Report,     # report path (default: .\hunt-report-<host>-<ts>.md)
    [switch]$Quick,      # skip memory phase (fastest triage)
    [string]$Baseline    # known-good network baseline for hunt-net
)

$ErrorActionPreference = 'SilentlyContinue'

# Shared findings file across every phase - must be set BEFORE the lib loads
$env:HUNT_FINDINGS = Join-Path $env:TEMP ("hunt-findings-{0}.tsv" -f ([guid]::NewGuid().ToString('N').Substring(0, 12)))
Set-Content -LiteralPath $env:HUNT_FINDINGS -Value $null

foreach ($lib in @("$PSScriptRoot\..\lib\hunt-common.ps1", "$PSScriptRoot\hunt-common.ps1")) {
    if (Test-Path -LiteralPath $lib) { . $lib; $libOk = $true; break }
}
if (-not $libOk) { Write-Error 'hunt-common.ps1 not found'; exit 1 }

$hostName = $env:COMPUTERNAME
$ts = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
if (-not $Report) { $Report = ".\hunt-report-$hostName-$ts.md" }

$raw = Join-Path $env:TEMP ("hunt-raw-{0}.log" -f ([guid]::NewGuid().ToString('N').Substring(0, 12)))
Set-Content -LiteralPath $raw -Value $null

function Invoke-Phase {
    param([string]$Label, [string]$Script, [object[]]$Arguments = @())
    Add-Content -LiteralPath $raw -Value ("`n`n######## {0} ########" -f $Label)
    Hunt-Header ("PHASE: {0}" -f $Label)
    & (Join-Path $PSScriptRoot $Script) @Arguments *>&1 | ForEach-Object {
        $text = ($_ | Out-String).TrimEnd("`r", "`n")
        $hostMsg = $null
        if ($_ -is [System.Management.Automation.InformationRecord] -and
            $_.MessageData -is [System.Management.Automation.HostInformationMessage]) {
            $hostMsg = $_.MessageData
        }
        if ($hostMsg -and $hostMsg.NoNewline) {
            Add-Content -LiteralPath $raw -Value $text -NoNewline
        } else {
            Add-Content -LiteralPath $raw -Value $text
        }
        if ($hostMsg) {
            # re-render Write-Host output with its original colors
            $splat = @{ Object = $hostMsg.Message }
            if ($null -ne $hostMsg.ForegroundColor) { $splat.ForegroundColor = $hostMsg.ForegroundColor }
            if ($hostMsg.NoNewline) { $splat.NoNewline = $true }
            Write-Host @splat
        } else {
            Write-Host $text
        }
    }
}

Hunt-Banner
Write-Host ("== hunt-land compromise assessment - {0} @ {1} ==" -f $hostName, (Hunt-Timestamp)) -ForegroundColor White
Require-AdminOrWarn

$netArgs = @()
if ($Watch) { $netArgs += '-Watch' }
if ($Baseline) { $netArgs += @('-Baseline', $Baseline) }
$lolArgs = @(); if ($History) { $lolArgs += '-History' }

Invoke-Phase '1-process-tree' 'hunt-procs.ps1' @('-Tree')
Invoke-Phase '2-network'      'hunt-net.ps1' $netArgs
Invoke-Phase '3-persistence'  'hunt-persist.ps1' @('-Days', $Days)
Invoke-Phase '5-lolbin'       'hunt-lolbin.ps1' $lolArgs
if (-not $Quick) { Invoke-Phase '4-memory' 'hunt-memory.ps1' }

# ---- correlation & verdict ---------------------------------------------------
$findings = @(Get-Content -LiteralPath $env:HUNT_FINDINGS -ErrorAction SilentlyContinue | Where-Object { $_ })
$h = @($findings | Where-Object { $_ -like "HIGH`t*" }).Count
$m = @($findings | Where-Object { $_ -like "MEDIUM`t*" }).Count
$l = @($findings | Where-Object { $_ -like "LOW`t*" }).Count

if     ($h -ge 2) { $verdict = 'COMPROMISED (multiple corroborating high-severity signals)' }
elseif ($h -eq 1) { $verdict = 'SUSPICIOUS (one high-severity signal - corroborate before acting)' }
elseif ($m -ge 3) { $verdict = 'SUSPICIOUS (cluster of medium signals)' }
elseif ($m -ge 1) { $verdict = 'INCONCLUSIVE (isolated medium signals - likely noise, verify)' }
else              { $verdict = 'CLEAN-SO-FAR (no LotL indicators surfaced by these checks)' }

# ---- write report ------------------------------------------------------------
$isAdmin = Test-IsAdmin
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# Compromise Assessment Report')
$lines.Add('')
$lines.Add("- **Host:** $hostName")
$lines.Add("- **Platform:** $($script:HuntPlatform)")
$lines.Add("- **Generated (UTC):** $(Hunt-Timestamp)")
$lines.Add("- **Tool:** hunt-land v$($script:HuntVersion) (PowerShell)")
$lines.Add("- **Privilege:** $(if ($isAdmin) { 'Administrator' } else { 'non-admin (visibility limited)' })")
$lines.Add('')
$lines.Add('## Executive verdict')
$lines.Add('')
$lines.Add("**$verdict**")
$lines.Add('')
$lines.Add("Signal counts - HIGH: $h - MEDIUM: $m - LOW: $l")
$lines.Add('')
$lines.Add('## Ranked findings')
$lines.Add('')
if (($h + $m + $l) -eq 0) {
    $lines.Add('_No findings recorded._')
} else {
    $lines.Add('| Severity | ATT&CK | Observation |')
    $lines.Add('|----------|--------|-------------|')
    foreach ($sev in @('HIGH', 'MEDIUM', 'LOW')) {
        foreach ($f in ($findings | Where-Object { $_ -like "$sev`t*" })) {
            $parts = $f -split "`t", 3
            $msg = ('' + $parts[2]) -replace '\|', '\|'
            $lines.Add("| $($parts[0]) | $($parts[1]) | $msg |")
        }
    }
}
$lines.Add('')
$lines.Add('## Recommended next steps')
$lines.Add('')
$lines.Add('1. Enrich every external IP/domain above with `hunt-intel <ioc>` **from your analyst workstation** (not this host).')
$lines.Add('2. For HIGH findings, capture volatile evidence before acting: full command line, loaded modules, open sockets, and the parent chain of each flagged PID.')
$lines.Add('3. Consider a memory image (winpmem -> Volatility 3 `windows.malfind`) before any eradication.')
$lines.Add('4. Only after evidence capture and operator sign-off: scoped containment (targeted firewall block to the C2 IP, dependency-aware process kill).')
$lines.Add('')
$lines.Add('## Visibility gaps')
$lines.Add('')
if (-not $isAdmin) { $lines.Add('- Ran without Administrator: other users'' processes, sockets, memory regions and HKU hives were partially invisible. **Re-run elevated.**') }
if (-not $Watch)   { $lines.Add('- Beacon watch skipped (`-Watch` not set): low-and-slow C2 may not appear in a single snapshot.') }
if (-not $Baseline) { $lines.Add('- No network baseline supplied (`-Baseline`): uncommon-port egress was reported at LOW confidence only (see Tuning.md).') }
if ($Quick)        { $lines.Add('- Memory phase skipped (`-Quick`): in-memory-only implants (RWX injected regions) were not checked.') }
$lines.Add('')
$lines.Add('---')
$lines.Add('## Full evidence appendix')
$lines.Add('')
$lines.Add('```')
foreach ($rl in @(Get-Content -LiteralPath $raw -ErrorAction SilentlyContinue)) { $lines.Add($rl) }
$lines.Add('```')
Set-Content -LiteralPath $Report -Value $lines -Encoding UTF8

Hunt-Header ("VERDICT: {0}" -f $verdict)
Write-Host '  HIGH: ' -NoNewline
Write-Host $h -ForegroundColor Red -NoNewline
Write-Host '   MEDIUM: ' -NoNewline
Write-Host $m -ForegroundColor Yellow -NoNewline
Write-Host ("   LOW: {0}" -f $l)
Hunt-Ok ("Full report written to: {0}" -f $Report)

Remove-Item -LiteralPath $raw, $env:HUNT_FINDINGS -Force -ErrorAction SilentlyContinue
$env:HUNT_FINDINGS = $null

if ($h -ge 1) { exit 2 }
if ($m -ge 1) { exit 1 }
exit 0
