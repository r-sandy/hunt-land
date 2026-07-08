# install.ps1 - install the hunt-land PowerShell toolkit (Windows)
# Copies the hunters + shared lib into one folder and (optionally) adds it to
# the user PATH. Read-only hunters; nothing here modifies the system it
# inspects.

[CmdletBinding()]
param(
    [string]$Prefix = "$env:LOCALAPPDATA\hunt-land",
    [switch]$AddToPath   # append the install dir to the *user* PATH
)

$ErrorActionPreference = 'Stop'
$src = $PSScriptRoot
$tools = @('hunt-land.ps1', 'hunt-procs.ps1', 'hunt-net.ps1', 'hunt-persist.ps1', 'hunt-lolbin.ps1', 'hunt-memory.ps1')

Write-Host 'Installing hunt-land PowerShell toolkit'
Write-Host "  from: $src"
Write-Host "  to  : $Prefix"

New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $src 'lib\hunt-common.ps1') -Destination (Join-Path $Prefix 'hunt-common.ps1') -Force
foreach ($t in $tools) {
    Copy-Item -LiteralPath (Join-Path $src "bin\$t") -Destination (Join-Path $Prefix $t) -Force
    Write-Host "  + $Prefix\$t"
}
# clear the Zone.Identifier mark-of-the-web so scripts run under RemoteSigned
Get-ChildItem -LiteralPath $Prefix -Filter '*.ps1' | Unblock-File -ErrorAction SilentlyContinue

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$onPath = ($userPath -split ';' | Where-Object { $_ }) -contains $Prefix
if ($AddToPath -and -not $onPath) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $Prefix), 'User')
    Write-Host "  + added $Prefix to user PATH (restart your shell to pick it up)"
} elseif (-not $onPath) {
    Write-Host ''
    Write-Host "NOTE: $Prefix is not on your PATH. Re-run with -AddToPath, or invoke by full path."
}

Write-Host ''
Write-Host "Done. Try:  powershell -ExecutionPolicy Bypass -File `"$Prefix\hunt-land.ps1`" -Quick"
Write-Host "Uninstall:  Remove-Item -Recurse -Force `"$Prefix`""
