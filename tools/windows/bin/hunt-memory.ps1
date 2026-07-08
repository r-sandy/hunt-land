# hunt-memory.ps1 - Phase 4: live injection-artifact triage (Windows)
# Without a full dump: RWX private memory regions (malfind-lite via
# VirtualQueryEx) and DLLs loaded from user-writable paths. Read-only.
#
# Tuning.md: hunt-memory is worth it only for its high-signal subset - the
# noisy heuristics (the Linux port's deleted-file mappings were the top source
# of false HIGHs) are deliberately absent here. RWX private memory in a known
# JIT host (.NET, browsers, Java, node) is NORMAL and reported LOW; the same
# artifact in a non-JIT native process is the classic injected-shellcode
# signal and stays HIGH.

[CmdletBinding()]
param(
    [int]$MaxRegionsPerProcess = 5   # cap reported regions per process
)

$ErrorActionPreference = 'SilentlyContinue'
foreach ($lib in @("$PSScriptRoot\..\lib\hunt-common.ps1", "$PSScriptRoot\hunt-common.ps1")) {
    if (Test-Path -LiteralPath $lib) { . $lib; $libOk = $true; break }
}
if (-not $libOk) { Write-Error 'hunt-common.ps1 not found'; exit 1 }

Hunt-Header ("hunt-memory v{0} ({1}) @ {2}" -f $script:HuntVersion, $script:HuntPlatform, (Hunt-Timestamp))
Require-AdminOrWarn

# ---- 1. DLLs loaded from user-writable paths (T1574.002 / T1055.001) -------------
Hunt-Info 'scanning loaded modules for user-writable paths...'
foreach ($p in @(Get-Process)) {
    if ($p.Id -eq $PID) { continue }
    $mods = $null
    try { $mods = $p.Modules } catch { continue }
    foreach ($m in @($mods)) {
        $file = '' + $m.FileName
        if ($file -and $file -match $script:HuntVolatilePathRx -and $file -match '(?i)\.dll$') {
            Add-Finding HIGH T1574.002 ("process '{0}' (PID {1}) has DLL loaded from user-writable path: {2}" -f $p.ProcessName, $p.Id, $file)
        }
    }
}

# ---- 2. RWX private memory regions - malfind-lite (T1055) -------------------------
Hunt-Info 'scanning process memory for RWX private regions (malfind-lite)...'
if (-not ('HuntLand.Mem' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace HuntLand {
    public static class Mem {
        [StructLayout(LayoutKind.Sequential)]
        public struct MBI {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint  AllocationProtect;
            public IntPtr RegionSize;
            public uint  State;
            public uint  Protect;
            public uint  Type;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualQueryEx(IntPtr handle, IntPtr address, out MBI mbi, IntPtr size);
    }
}
'@
}

$MEM_COMMIT = 0x1000; $MEM_PRIVATE = 0x20000; $PAGE_EXECUTE_READWRITE = 0x40
$PROCESS_QUERY_INFORMATION = 0x0400
# processes whose JIT legitimately allocates RWX private memory
$jitHosts = @('powershell', 'pwsh', 'powershell_ise', 'chrome', 'msedge', 'msedgewebview2', 'firefox',
              'java', 'javaw', 'node', 'dotnet', 'w3wp', 'code', 'devenv', 'explorer', 'searchapp',
              'msmpeng', 'teams', 'electron', 'discord', 'slack')

function Get-RwxPrivateRegions([int]$TargetPid) {
    $regions = @()
    $handle = [HuntLand.Mem]::OpenProcess($PROCESS_QUERY_INFORMATION, $false, $TargetPid)
    if ($handle -eq [IntPtr]::Zero) { return $null }
    try {
        $mbi = New-Object HuntLand.Mem+MBI
        $mbiSize = [IntPtr][System.Runtime.InteropServices.Marshal]::SizeOf([type][HuntLand.Mem+MBI])
        $addr = [int64]0
        $maxAddr = [int64]0x00007FFFFFFEFFFF
        while ($addr -lt $maxAddr) {
            $got = [HuntLand.Mem]::VirtualQueryEx($handle, [IntPtr]$addr, [ref]$mbi, $mbiSize)
            if ($got -eq [IntPtr]::Zero) { break }
            $size = [int64]$mbi.RegionSize
            if ($size -le 0) { break }
            if ($mbi.State -eq $MEM_COMMIT -and $mbi.Type -eq $MEM_PRIVATE -and $mbi.Protect -eq $PAGE_EXECUTE_READWRITE) {
                $regions += [pscustomobject]@{ Base = [int64]$mbi.BaseAddress; Size = $size }
            }
            $addr = [int64]$mbi.BaseAddress + $size
        }
    } finally {
        [void][HuntLand.Mem]::CloseHandle($handle)
    }
    return , $regions
}

$scanned = 0; $denied = 0
foreach ($p in @(Get-Process)) {
    if ($p.Id -eq $PID -or $p.Id -le 4) { continue }
    $regions = Get-RwxPrivateRegions -TargetPid $p.Id
    if ($null -eq $regions) { $denied++; continue }
    $scanned++
    if ($regions.Count -eq 0) { continue }
    $total = ($regions | Measure-Object -Property Size -Sum).Sum
    $top = ($regions | Sort-Object Size -Descending | Select-Object -First $MaxRegionsPerProcess |
        ForEach-Object { "0x{0:X}({1}KB)" -f $_.Base, [int]($_.Size / 1KB) }) -join ', '
    $name = $p.ProcessName.ToLower()
    if ($jitHosts -contains $name) {
        Add-Finding LOW T1055 ("PID {0} ({1}): {2} RWX private region(s), {3}KB total - known JIT host, likely benign: {4}" -f $p.Id, $p.ProcessName, $regions.Count, [int]($total / 1KB), $top)
    } else {
        Add-Finding HIGH T1055 ("PID {0} ({1}): {2} RWX private (unbacked) memory region(s), {3}KB total - injected-code candidate: {4}" -f $p.Id, $p.ProcessName, $regions.Count, [int]($total / 1KB), $top)
    }
}
Hunt-Info ("memory scan: {0} process(es) scanned, {1} inaccessible (protected/other-user)" -f $scanned, $denied)

# ---- 3. offline dump handoff -------------------------------------------------------
if (Get-Command vol, volatility3 -ErrorAction SilentlyContinue) {
    Hunt-Ok 'Volatility 3 detected - for a captured dump run: vol -f DUMP windows.malfind / windows.pslist / windows.psscan'
} else {
    Hunt-Info 'No Volatility 3 found. For deep analysis, capture RAM with a signed acquirer (e.g. winpmem) and run windows.malfind offline - never analyze on the suspect host.'
}

Show-FindingSummary
