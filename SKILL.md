---
name: hunt-land
description: >-
  Living-off-the-Land (LotL) forensic hunter for Blue Team defenders. Use this
  skill when a host is suspected compromised but antivirus/EDR shows zero
  file-based alerts — i.e. the adversary is abusing native, signed, or
  built-in tooling (bash, PowerShell, wmic, certutil, curl, systemd, cron,
  rundll32) rather than dropping detectable malware. Triggers on: "living off
  the land", "LotL/LOLBin hunting", "fileless malware", "EDR says clean but I
  think it's compromised", "hunt for persistence", "suspicious process tree",
  "beaconing / C2 detection", "compromise assessment", "IR triage on a live
  host". Cross-platform (Linux + Windows). Read-only by default; produces a
  ranked findings report mapped to MITRE ATT&CK and, only on request,
  containment scripts.
---

# Living-off-the-Land (LotL) Forensic Hunter

A structured hunt methodology for detecting adversaries who operate using a
system's own trusted binaries and native functionality, leaving no malicious
file for signature-based AV/EDR to catch. The goal is to convert weak,
individually-innocent signals into a high-confidence, evidence-backed verdict.

## Operating Principles

- **Behavior over signatures.** LotL detection is about *relationships and
  context* (who spawned what, talking to where, running as whom), never file
  hashes. Every finding must cite the specific observation that supports it.
- **Read-only first, ranked always.** Default to non-destructive collection.
  Never kill a process, modify firewall rules, or delete artifacts until you
  have presented findings and the operator has explicitly authorized action.
- **Correlate before you conclude.** A single odd process is noise. A finding
  is credible only when ≥2 independent signals converge (e.g. anomalous parent
  + outbound connection to a raw IP + world-writable execution path).
- **Preserve the timeline.** Capture volatile state *before* touching anything;
  record collection time and the exact command used so findings are reproducible
  and court-defensible.
- **Assume you are watched.** A live intruder may monitor for defensive
  activity. Prefer quiet, native collection; avoid installing tooling on the
  suspect host where possible.

## Scope & Access

- Best run via Claude Code's terminal execution layer with root/Administrator
  privileges to read volatile state (all-process visibility, socket→PID
  ownership, `/proc`, kernel ring buffer, service configs).
- If root is unavailable, degrade gracefully: collect what the current user can
  see and explicitly flag the visibility gaps in the report.
- Works on a **live host**, a mounted disk image, or a **provided artifact**
  (memory dump, `/proc` snapshot, EVTX/auditd logs, netstat capture).

## Standalone Toolkit (`tools/`)

The phases below are also packaged as installable CLI tools that run **without
Claude**, on Linux and macOS (bash 3.2+, no dependencies): `hunt-procs`,
`hunt-net`, `hunt-persist`, `hunt-lolbin`, `hunt-memory`, and an `hunt-intel`
free-threat-intel enricher, tied together by the `hunt-land` orchestrator which
emits an ATT&CK-mapped Compromise Assessment Report and a verdict-based exit
code. Install with `tools/install.sh`; see `tools/README.md`. When operating on
a real host you can either drive these commands yourself or run the tools and
interpret their output. `hunt-intel` is the only tool that touches the network
and must be run on the analyst workstation, never the suspect host.

## Multi-Phase Hunt Pipeline

Run phases in order; each feeds the correlation engine in Phase 6.

### Phase 1 — Volatile Process Tree Carving
Reconstruct the full parent→child ancestry and hunt for lineage anomalies.

- **Linux:** `ps -efww --forest`, `ps auxww`, and per-PID
  `readlink /proc/<pid>/exe`, `cat /proc/<pid>/cmdline`, `/proc/<pid>/environ`,
  `ls -l /proc/<pid>/cwd`.
- **Windows:** `Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine`,
  `wmic process get Name,ProcessId,ParentProcessId,CommandLine`, or
  `tasklist /v`.
- **Red flags to score:**
  - Service/daemon spawning a shell — `nginx`/`apache2`/`httpd`/`mysqld` →
    `bash`/`sh`/`dash`; `w3wp.exe`/`sqlservr.exe` → `cmd`/`powershell`.
  - Office or browser spawning an interpreter (`winword.exe` → `powershell`).
  - `explorer.exe` launching encoded PowerShell (`-enc`, `-e`, `FromBase64String`,
    `-nop -w hidden`).
  - Interpreter with a **deleted on-disk binary** (`/proc/<pid>/exe` →
    `(deleted)`) — classic fileless execution.
  - Process masquerading: legit name in an illegit path (`/tmp/systemd`,
    `C:\Users\...\svchost.exe`), or trailing-space / homoglyph names.
  - Parent PID reparented to 1/`init`/`systemd` unexpectedly (orphaned implant).

### Phase 2 — Network Socket ↔ Process Cross-Referencing
Bind every connection to an owning process and judge the *pairing*.

- **Linux:** `ss -tulpanep`, `ss -tanp`, `lsof -i -n -P`; resolve remote IPs and
  check reputation/ASN offline where possible.
- **Windows:** `Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess`
  joined to process name; `netstat -anob`.
- **Red flags:** a native binary that has no business egressing (e.g. `cron`,
  `httpd`, `logon` scripts) talking to a raw external IP; connections to
  high/uncommon ports; long-lived ESTABLISHED sessions to a single peer;
  listeners on odd ports bound by user-writable binaries; DNS to newly-seen or
  algorithmically-generated domains.
- **Beaconing heuristic:** sample connection state repeatedly over a short
  window and flag near-constant-interval callbacks (low jitter, fixed byte
  counts) — a strong C2 signal even when the destination looks benign.

### Phase 3 — Persistence & Execution-Surface Sweep
LotL intrusions survive reboots via native mechanisms, not dropped services.

- **Linux:** crontab (`/etc/cron*`, `/var/spool/cron/*`, per-user `crontab -l`),
  systemd units & timers (`systemctl list-units`, `list-timers`,
  `/etc/systemd/system`, user units), `~/.bashrc`/`.profile`/`.bash_login`,
  `/etc/rc.local`, `ld.so.preload` / `LD_PRELOAD`, `/etc/passwd` UID-0
  additions, authorized_keys, udev rules, PAM modules, and `at` jobs.
- **Windows:** Run/RunOnce keys, Scheduled Tasks (`schtasks /query /fo LIST /v`),
  WMI event subscriptions (`Get-WmiObject -Namespace root\subscription`),
  Services with binary paths in user-writable dirs, startup folders, and
  `Image File Execution Options` debugger hijacks.
- Diff against a known-good baseline where one exists; otherwise flag anything
  recently modified relative to the suspected intrusion window.

### Phase 4 — Memory & Injection Artifact Deep-Dive
When on-disk hunting comes up empty, the payload lives in RAM.

- If a memory dump or `/proc` snapshot is available, drive **Volatility 3**
  (`windows.malfind`, `windows.pslist`/`psscan` delta, `windows.hollowfind`,
  `linux.malfind`, `linux.check_syscall`) and apply **YARA** rules for known
  in-memory implant patterns.
- **Live Linux triage without a dump:** compare `/proc/<pid>/maps` for
  `rwx` anonymous regions, mismatches between `/proc/<pid>/exe` and mapped
  libraries, and injected `.so` paths under `/dev/shm` or `/tmp`.
- Detect **Process Hollowing / DLL & shellcode injection** — mapped executable
  regions with no backing file, PE headers in private memory, and RWX pages —
  where no malicious file ever touches disk.

### Phase 5 — LOLBin / LOLBAS Usage Audit
Flag trusted binaries invoked in adversary-characteristic ways.

- **Linux (GTFOBins-style):** `curl`/`wget` piping to a shell, `certutil`-style
  base64 decode chains, `bash -i >& /dev/tcp/…` reverse shells, `python -c`
  socket payloads, `nohup`/`setsid` detachment, `gdb`/`awk`/`find -exec`
  privilege tricks, `xxd`/`base64` payload staging.
- **Windows (LOLBAS):** `certutil -urlcache -f`, `bitsadmin /transfer`,
  `regsvr32 /i:http…scrobj.dll`, `rundll32 javascript:`, `mshta`,
  `msbuild`/`installutil` proxy execution, `wmic os get /format:"http…"`,
  encoded PowerShell download cradles.
- Match against process command lines from Phase 1; a LOLBin alone is weak, a
  LOLBin *plus* an anomalous parent *plus* an egress connection is a finding.

### Phase 6 — Correlation, ATT&CK Mapping & Verdict
Fuse the phases into ranked, evidence-backed findings.

- Group converging signals per PID/session into a single finding with a
  **confidence tier** (High / Medium / Low) driven by how many independent
  phases corroborate it.
- Map each finding to **MITRE ATT&CK** technique IDs, e.g. T1036 (Masquerading),
  T1059 (Command & Scripting Interpreter), T1055 (Process Injection), T1053
  (Scheduled Task/Job), T1543 (Create/Modify System Process), T1105 (Ingress
  Tool Transfer), T1071 (Application Layer Protocol / C2), T1548 (Abuse
  Elevation Control).
- For each finding report: **what was observed** (exact command output),
  **why it's suspicious**, **ATT&CK mapping**, **confidence**, and a
  **recommended next collection step** to confirm or refute.

## Output Contract

Produce a **Compromise Assessment Report**:
1. Executive verdict (Compromised / Suspicious / Clean-so-far) with the single
   strongest piece of evidence.
2. Ranked findings table: `PID/Artifact | Signal(s) | ATT&CK | Confidence`.
3. Full evidence appendix (raw command output, timestamps, exact commands run)
   for reproducibility.
4. Visibility gaps — what could not be inspected and why.

## Containment (Only on Explicit Authorization)

Do **not** run any of this until findings are presented and the operator
approves. When authorized, generate — and show before executing — targeted,
reversible containment:

- Scoped network isolation: specific `iptables`/`nft` egress blocks to the C2
  IP, or a Windows Firewall rule — never a blanket `kill -9` sweep first.
- A dependency-aware process-termination list (children before parents) so a
  watchdog can't respawn the implant.
- Persistence removal steps paired with a **backup/collection** of the artifact
  first, preserving evidence for post-incident analysis.
- Always recommend forensic imaging *before* eradication when the incident may
  require legal/HR follow-up.
