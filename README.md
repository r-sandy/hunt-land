# hunt-land

```
 _                 _             _                 _
| |__  _   _ _ __ | |_   _____  | | __ _ _ __   __| |
| '_ \| | | | '_ \| __| |_____| | |/ _` | '_ \ / _` |
| | | | |_| | | | | |_          | | (_| | | | | (_| |
|_| |_|\__,_|_| |_|\__|         |_|\__,_|_| |_|\__,_|
 ~ ~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ~~ ~ ~
     Living-off-the-Land forensic hunter
```

**Living-off-the-Land (LotL) forensic hunter for Cybersecurity defenders.**

For when a host is suspected compromised but AV/EDR shows **zero file-based
alerts** — because the adversary is abusing native, signed, built-in tooling
(bash, PowerShell, `wmic`, `certutil`, `curl`, systemd, cron, `rundll32`)
instead of dropping detectable malware. hunt-land converts weak,
individually-innocent signals into a high-confidence, evidence-backed verdict
mapped to MITRE ATT&CK.

It ships in two forms:

1. **A Claude Code skill** ([`SKILL.md`](SKILL.md)) — a structured hunt
   methodology Claude follows when you ask it to run a compromise assessment.
2. **A standalone CLI toolkit** ([`tools/`](tools/)) — installable bash tools
   on Linux and macOS, plus a native PowerShell port for Windows
   ([`tools/windows/`](tools/windows/)).

## The hunt pipeline

Six phases, each feeding a correlation engine that ranks findings by how many
independent signals converge:

| Phase | Focus | Example red flags |
|-------|-------|-------------------|
| 1 · Process tree | Lineage anomalies | daemon→shell, deleted on-disk binary, encoded PowerShell, masquerading |
| 2 · Network | Socket↔process pairing | no-egress binary calling a raw IP, low-jitter beaconing |
| 3 · Persistence | Native autostart | cron, systemd, launchd, `ld.so.preload`, Run keys, WMI subs |
| 4 · Memory | Injection artifacts | RWX anon regions, `memfd:` execution, hollowing |
| 5 · LOLBin/LOLBAS | Trusted binaries, abused | `curl \| bash`, `certutil` download cradles, GTFOBins tricks |
| 6 · Correlate | ATT&CK mapping & verdict | Compromise / Suspicious / Clean-so-far |

## Operating principles

- **Behavior over signatures** — findings cite the specific observation, never a hash.
- **Read-only first** — nothing is killed, blocked, or deleted until findings are presented and the operator authorizes action.
- **Correlate before you conclude** — a single odd process is noise; ≥2 converging signals is a finding.
- **Preserve the timeline** — capture volatile state before touching anything; record the exact command run.
- **Assume you are watched** — prefer quiet native collection; run threat-intel lookups from the analyst host, never the suspect box.

## Install (CLI toolkit)

| Channel | Command |
|---------|---------|
| **snap** | `sudo snap install hunt-land --classic` |
| **apt** (Debian/Ubuntu) | download the `.deb` from [Releases](https://github.com/r-sandy/hunt-land/releases), then `sudo apt install ./hunt-land_*_all.deb` |
| **yum/dnf** (RHEL/Fedora) | download the `.rpm` from [Releases](https://github.com/r-sandy/hunt-land/releases), then `sudo dnf install ./hunt-land-*.noarch.rpm` |
| **brew** (macOS/Linux) | `brew tap r-sandy/hunt-land https://github.com/r-sandy/hunt-land && brew install hunt-land` |
| **from source** | `git clone https://github.com/r-sandy/hunt-land && hunt-land/tools/install.sh` |
| **Windows (PowerShell)** | `git clone https://github.com/r-sandy/hunt-land` then `powershell -ExecutionPolicy Bypass -File hunt-land\tools\windows\install.ps1 -AddToPath` |

Packages are built from [`packaging/`](packaging/) and `snap/snapcraft.yaml`;
pushing a `v*` tag triggers the [release workflow](.github/workflows/release.yml),
which attaches the `.deb`, `.rpm`, and tarball to a GitHub Release and uploads
the snap when store credentials are configured.

## Quick start (CLI toolkit)

```sh
sudo hunt-land --watch           # full hunt → Compromise Assessment Report

# then, on YOUR workstation (never the suspect host):
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' hunt-report-*.md | sort -u | hunt-intel --stdin
```

Pure POSIX shell, bash 3.2 compatible (stock macOS), no runtime dependencies.
Full tool reference in [`tools/README.md`](tools/README.md).

## Quick start (Claude Code skill)

Place this repo under your Claude Code skills directory and ask, e.g.:

> "EDR says this box is clean but I think it's compromised — hunt for
> living-off-the-land activity."

Claude loads the skill, runs the phases, and returns a ranked, ATT&CK-mapped
Compromise Assessment Report. It only generates containment scripts on your
explicit request.

## Platform support

| | Linux | macOS | Windows |
|-|:-----:|:-----:|:-------:|
| Claude skill methodology | ✅ | ✅ | ✅ |
| CLI toolkit | ✅ | ✅ | ✅ |

Linux/macOS use the bash toolkit ([`tools/`](tools/)); Windows uses the native
PowerShell port ([`tools/windows/`](tools/windows/), Windows PowerShell 5.1+,
no dependencies). `hunt-intel` enrichment runs on the analyst workstation.

## Threat-intel enrichment

`hunt-intel` enriches IOCs against **free** platforms — Shodan InternetDB,
GreyNoise community, and abuse.ch ThreatFox/URLhaus are keyless; AbuseIPDB,
AlienVault OTX, and VirusTotal activate when you set `ABUSEIPDB_KEY`, `OTX_KEY`,
or `VT_KEY`. Run it on your analyst workstation only — querying threat intel
from a compromised host leaks your IOC list to the adversary.

## Safety & authorization

hunt-land is a **defensive** compromise-assessment tool. The hunters are
read-only and make no outbound connections. Use it only on hosts you are
authorized to inspect. Containment actions (network isolation, process
termination, persistence removal) are generated only after findings are
presented and an operator signs off, and always recommend forensic imaging
before eradication when an incident may need legal/HR follow-up.

## License

[MIT](LICENSE)
