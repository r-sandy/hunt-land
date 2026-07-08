# hunt-common.ps1 - shared helpers for the hunt-land PowerShell toolkit.
# Dot-sourced by every hunt-*.ps1 tool. Windows PowerShell 5.1 compatible.

$script:HuntVersion  = '1.0.2'
$script:HuntPlatform = 'windows'

# Findings accumulate in a TSV file (severity, ATT&CK id, message).
# The orchestrator sets HUNT_FINDINGS so all phases share one file; a tool run
# standalone gets a fresh temp file of its own.
if ($env:HUNT_FINDINGS) {
    $script:HuntFindings = $env:HUNT_FINDINGS
} else {
    $script:HuntFindings = Join-Path $env:TEMP ("hunt-findings-{0}.tsv" -f ([guid]::NewGuid().ToString('N').Substring(0, 12)))
}
if (-not (Test-Path -LiteralPath $script:HuntFindings)) {
    New-Item -ItemType File -Path $script:HuntFindings -Force | Out-Null
}

# Findings already present when this tool started (earlier phases under the
# orchestrator). Show-FindingSummary reports only this tool's own additions.
$script:HuntBaseline = @(Get-Content -LiteralPath $script:HuntFindings -ErrorAction SilentlyContinue).Count

function Hunt-Timestamp {
    (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# Sand-and-beach banner (plain-color fallback of the bash gradient).
function Hunt-Banner {
    $art = @'
 _                 _             _                 _
| |__  _   _ _ __ | |_   _____  | | __ _ _ __   __| |
| '_ \| | | | '_ \| __| |_____| | |/ _` | '_ \ / _` |
| | | | |_| | | | | |_          | | (_| | | | | (_| |
|_| |_|\__,_|_| |_|\__|         |_|\__,_|_| |_|\__,_|
'@
    Write-Host $art -ForegroundColor Yellow
    Write-Host ' ~ ~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ~~ ~ ~' -ForegroundColor Cyan
    Write-Host ("     Living-off-the-Land forensic hunter  v{0}" -f $script:HuntVersion) -ForegroundColor DarkYellow
    Write-Host ''
}

function Hunt-Header([string]$Text) {
    Write-Host ''
    Write-Host ("== {0} ==" -f $Text) -ForegroundColor White
}

function Hunt-Info([string]$Text) {
    Write-Host '[*]' -ForegroundColor Cyan -NoNewline
    Write-Host (' {0}' -f $Text)
}

function Hunt-Ok([string]$Text) {
    Write-Host '[ok]' -ForegroundColor Green -NoNewline
    Write-Host (' {0}' -f $Text)
}

function Hunt-Warn([string]$Text) {
    Write-Host '[!]' -ForegroundColor Yellow -NoNewline
    Write-Host (' {0}' -f $Text)
}

# Add-Finding <HIGH|MEDIUM|LOW> <ATT&CK-id> <message>
function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('HIGH', 'MEDIUM', 'LOW')][string]$Severity,
        [Parameter(Mandatory)][string]$Attack,
        [Parameter(Mandatory)][string]$Message
    )
    $color = switch ($Severity) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Cyan' } }
    Write-Host ("[{0}]" -f $Severity) -ForegroundColor $color -NoNewline
    Write-Host (" ({0}) {1}" -f $Attack, $Message)
    $clean = $Message -replace "[`r`n`t]", ' '
    Add-Content -LiteralPath $script:HuntFindings -Value ("{0}`t{1}`t{2}" -f $Severity, $Attack, $clean)
}

function Show-FindingSummary {
    $all = @(Get-Content -LiteralPath $script:HuntFindings -ErrorAction SilentlyContinue)
    if ($all.Count -gt $script:HuntBaseline) {
        $own = @($all[$script:HuntBaseline..($all.Count - 1)])
    } else {
        $own = @()
    }
    $h = @($own | Where-Object { $_ -like "HIGH`t*" }).Count
    $m = @($own | Where-Object { $_ -like "MEDIUM`t*" }).Count
    $l = @($own | Where-Object { $_ -like "LOW`t*" }).Count
    Hunt-Header 'Findings summary'
    Write-Host '  HIGH: ' -NoNewline
    Write-Host $h -ForegroundColor Red -NoNewline
    Write-Host '   MEDIUM: ' -NoNewline
    Write-Host $m -ForegroundColor Yellow -NoNewline
    Write-Host ("   LOW: {0}" -f $l)
    if (($h + $m + $l) -eq 0) {
        Hunt-Ok 'nothing suspicious recorded by this tool'
    }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Require-AdminOrWarn {
    if (-not (Test-IsAdmin)) {
        Hunt-Warn 'not running as Administrator - some processes/sockets/hives will be invisible; findings are a lower bound'
    }
}

# Test-PrivateIP <ip> -> $true if RFC1918/loopback/link-local/unspecified
function Test-PrivateIP([string]$Ip) {
    if ([string]::IsNullOrEmpty($Ip)) { return $true }
    if ($Ip -match '^(10\.|192\.168\.|127\.|169\.254\.|0\.0\.0\.0$)') { return $true }
    if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $true }
    if ($Ip -match '^(::1?$|fe80:|fc|fd)') { return $true }
    return $false
}

# Paths a non-admin user can typically write to; execution from here is the
# strongest procs-phase signal (Tuning.md: tmp-exec checks stay high precision).
$script:HuntVolatilePathRx = '(?i)\\(AppData\\Local\\Temp|Windows\\Temp|Users\\Public|Downloads|AppData\\Local\\Packages\\[^\\]+\\TempState|Recycle)\\'
