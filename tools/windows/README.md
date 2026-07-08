# hunt-land toolkit — Windows PowerShell port

The hunt-land Living-off-the-Land hunters for **Windows**, implemented in pure
PowerShell — Windows PowerShell 5.1 compatible (stock on Windows 10/11 and
Server 2016+), no modules to install, nothing to compile. Read-only, like the
bash toolkit.

## Install

```powershell
# from an elevated or normal PowerShell prompt:
powershell -ExecutionPolicy Bypass -File .\install.ps1            # -> %LOCALAPPDATA%\hunt-land
powershell -ExecutionPolicy Bypass -File .\install.ps1 -AddToPath # also add to user PATH
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Prefix 'C:\Tools\hunt-land'
```

The installer runs `Unblock-File` on the copied scripts so they work under the
default `RemoteSigned` execution policy. To run straight from a checkout
without installing, prefix any invocation with `powershell -ExecutionPolicy
Bypass -File`.

## Tools

| Tool               | Phase | What it does |
|--------------------|-------|--------------|
| `hunt-land.ps1`    | all   | Orchestrator — runs every phase, writes a Markdown Compromise Assessment Report with an ATT&CK-mapped findings table and a verdict-based exit code. |
| `hunt-procs.ps1`   | 1     | Process-tree carving: server daemons / Office / browsers spawning shells, encoded command lines, Temp/Public execution, name masquerading, svchost/lsass lineage violations. |
| `hunt-net.ps1`     | 2     | Socket↔process pairing via `Get-NetTCPConnection`: no-egress natives talking out, shells with sockets, user-writable listeners; `-Watch` does beacon detection; `-SaveBaseline`/`-Baseline` suppress known-good pairs. |
| `hunt-persist.ps1` | 3     | Native persistence sweep: Run/RunOnce keys, scheduled tasks, WMI event subscriptions, service binPaths, startup folders, IFEO debugger hijacks, Winlogon Shell/Userinit, PowerShell profiles. |
| `hunt-lolbin.ps1`  | 5     | LOLBAS audit of live command lines (and `-History` PSReadLine history): certutil/bitsadmin cradles, regsvr32/rundll32/mshta proxy execution, encoded PowerShell, comsvcs LSASS dumps, shadow-copy deletion, log clearing. |
| `hunt-memory.ps1`  | 4     | Live injection triage: RWX private memory regions (malfind-lite via `VirtualQueryEx`), DLLs loaded from user-writable paths. Hands off to Volatility 3 for dumps. |

`hunt-intel` (IOC enrichment) has no Windows port yet — run the bash version
from your analyst workstation, which is where it belongs anyway (querying
threat intel from a compromised host leaks your IOC list to the adversary).

## Typical run

```powershell
# on the suspect host, elevated:
powershell -ExecutionPolicy Bypass -File hunt-land.ps1 -Watch -Report .\assessment.md

# then, on YOUR (Linux/macOS) analyst workstation — never the suspect host:
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' assessment.md | sort -u | hunt-intel --stdin
```

Run **elevated** (Administrator) for full visibility: other users' processes,
socket ownership, memory regions, and all registry hives. Non-elevated runs
degrade gracefully and the report flags the visibility gap. Use 64-bit
PowerShell (the default) — the memory scanner cannot walk 64-bit processes
from a 32-bit host process.

## Tuning

This port bakes in the signal-quality lessons from the Linux toolkit:

- **hunt-lolbin** is the sharpest instrument — it carries the largest pattern
  table, and every pattern requires an abused *flag combination*, never a
  binary name alone.
- **hunt-procs** keeps its high-precision core (masquerading + Temp-execution)
  at HIGH severity.
- **hunt-net** is unusable without a baseline, so it supports one:
  `hunt-net.ps1 -SaveBaseline known-good.tsv` on a healthy reference host,
  then `hunt-net.ps1 -Baseline known-good.tsv` (or `hunt-land.ps1 -Baseline`)
  during the hunt. Without a baseline the generic uncommon-port heuristic is
  reported at LOW confidence only.
- **hunt-memory** keeps only the high-signal subset. RWX private memory in a
  known JIT host (.NET, browsers, Java, node) is normal and reported LOW; the
  same artifact in a non-JIT native process stays HIGH. The noisy
  deleted-file-style heuristics were left out on purpose.
- **hunt-persist** is deliberately conservative: HIGH only when the *content*
  of an entry matches adversary patterns; location/recency alone is MEDIUM;
  AppData-resident autoruns (OneDrive, Teams, updaters) are not flagged by
  path alone.

## Exit codes (for `hunt-land.ps1`)

`0` clean · `1` medium signals present · `2` high-severity signals present —
so you can gate alerting on `powershell -File hunt-land.ps1 -Quick; $LASTEXITCODE -ge 2`.

## OPSEC

All hunters are read-only and make no outbound connections. Prefer quiet,
native collection; a live intruder may monitor for defensive activity.
