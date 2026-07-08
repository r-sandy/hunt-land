# hunt-land toolkit — standalone LotL hunters (Linux + macOS)

Individual command-line tools that implement the hunt-land Living-off-the-Land
methodology **without Claude**. Pure POSIX shell + coreutils — nothing to
compile, no runtime dependencies. Bash 3.2 compatible (works on stock macOS).

**Windows?** A native PowerShell port of the full pipeline lives in
[`windows/`](windows/) — Windows PowerShell 5.1 compatible, no dependencies.

## Install

```sh
./install.sh                 # auto-picks /usr/local (if writable) or ~/.local
PREFIX=~/.local ./install.sh # force a prefix
```

Then add the bin dir to `PATH` if the installer tells you to. Uninstall line is
printed at the end of install.

## Tools

| Tool           | Phase | What it does |
|----------------|-------|--------------|
| `hunt-land`    | all   | Orchestrator — runs every phase, writes a Markdown Compromise Assessment Report with an ATT&CK-mapped findings table and a verdict. |
| `hunt-procs`   | 1     | Process-tree carving: daemons spawning shells, deleted/tmp-resident binaries, encoded command lines, name masquerading. |
| `hunt-net`     | 2     | Socket↔process pairing; flags no-egress binaries talking out, odd listeners; `--watch` does beacon detection over repeated samples. |
| `hunt-persist` | 3     | Native persistence sweep. Linux: cron, systemd, ld.so.preload, rc files, UID-0, keys. macOS: launchd, cron/periodic, emond, DYLD injection, login items, sudoers.d. |
| `hunt-lolbin`  | 5     | LOLBin/GTFOBins audit of live command lines (and `--history`): download-cradles, reverse shells, encoder chains, privilege tricks. |
| `hunt-memory`  | 4     | Live injection triage (Linux): RWX anon regions, deleted-file exec mappings, volatile-path `.so`, `memfd:` execution. Hands off to Volatility 3 for dumps. macOS degrades to a documented SIP gap. |
| `hunt-intel`   | 2b    | **Analyst-host** IOC enrichment against free TI: Shodan InternetDB, GreyNoise community, abuse.ch ThreatFox/URLhaus (all keyless), plus AbuseIPDB / OTX / VirusTotal if you set keys. |

## Typical run

```sh
sudo hunt-land --watch --report ./assessment.md   # full hunt on the suspect host
# then, on YOUR workstation (never the suspect host):
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' assessment.md | sort -u | hunt-intel --stdin
```

## OPSEC

`hunt-intel` is the only tool that reaches the internet, and it is meant to run
on your analyst workstation — querying threat intel from a compromised host
leaks your IOC list to the adversary. The hunters (`hunt-procs` … `hunt-memory`)
are read-only and make no outbound connections.

Optional API keys (env vars): `ABUSEIPDB_KEY`, `OTX_KEY`, `VT_KEY`.
Install `jq` for reliable JSON parsing (a regex fallback is used otherwise).

## Exit codes (for `hunt-land`)

`0` clean · `1` medium signals present · `2` high-severity signals present —
so you can gate CI / cron alerting on `hunt-land --quick; [ $? -ge 2 ]`.
