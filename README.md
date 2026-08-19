# shuvscan

**Agentless Linux threat hunting for one machine or ten thousand.**

Shuvscan is a fast, evidence-first security scanner for Linux fleets. It runs read-only probes over
local `sh` or stock OpenSSH, installs no endpoint agent, and emits a stable report that humans,
automation, SIEMs, and coding agents can all consume.

The project takes inspiration from Sandfly's agentless operating model and from the audacious,
batteries-included tooling style of Jeffrey Emanuel's projects. It is independent and is not
affiliated with or endorsed by Sandfly Security.

> [!WARNING]
> This is an early scaffold, not a compliance product or a substitute for incident response.

## Why this exists

Most Linux security tools force an awkward choice: deploy a privileged resident agent everywhere,
or settle for a shallow configuration checklist. Shuvscan's goal is a third option:

- **Agentless by construction.** Use SSH and tools already present on the host.
- **Behavior and posture together.** Hunt persistence and compromise artifacts alongside hardening
  mistakes, then correlate the evidence instead of dumping unrelated warnings.
- **Explain every verdict.** Stable rule IDs, bounded raw evidence, remediation, and explicit
  collection failures.
- **Fleet-native.** Parallel targets, deterministic reports, baselines, drift, and eventually a
  local-first evidence graph.
- **Automation-native.** Human output for terminals; JSON, NDJSON, SARIF, and OCSF for integrations.
- **Safe defaults.** Read-only probes, strict host-key checking, batch-mode SSH, no curl-pipe-shell
  installer, and no hidden telemetry.

## Quick start

```bash
cargo build --release

# Scan this machine. Exit 1 means a high/critical finding was detected.
./target/release/shuvscan

# Scan several hosts concurrently using your existing OpenSSH configuration.
./target/release/shuvscan \
  --target root@web-01 \
  --target ops@db-01 \
  --concurrency 8 \
  --format json

# Treat incomplete collection as an operational failure.
./target/release/shuvscan --target ops@host --strict-collection

# Opt in to bounded, non-interactive privilege escalation of the collector.
./target/release/shuvscan --target ops@host --sudo
```

Shuvscan never accepts passwords on the command line. Configure keys, host aliases, bastions, and
hardware-backed identities in `~/.ssh/config`; Shuvscan invokes `ssh` with batch mode and strict
host-key checking enabled.

`--sudo` runs only the built-in, read-only collector through `sudo -n -- sh -s`.
It never prompts, accepts a password, or falls back silently; sudo policy or authentication
failures are reported as collection errors.

Fleet scans run at most 16 targets concurrently by default. Set
`--concurrency <COUNT>` to tune that bound; zero is rejected.

`--format sarif` emits one SARIF 2.1.0 run. Findings use host logical
locations, and collection errors are tool execution notifications. `--format
ocsf` emits an OCSF 1.8.0 JSON array containing one Scan Activity per target
and one Detection Finding per finding. OCSF requires an event timestamp, so
`time` records export time until the native report schema carries scan wall-clock
time. Use the native `json` or `jsonl` formats when the complete Shuvscan report
schema is required.

## Collection model

All probes for a host run inside **one `sh` session over one SSH connection**
(or one local `sh` for `--target local`). Each probe executes in its own
subshell, delimited by sentinel lines carrying a per-scan random nonce, so
attacker-controlled evidence (for example crafted file names) cannot forge or
terminate a probe section. Each section carries its own exit status; a probe
that fails to collect — including one that needs privileges the session lacks —
is reported as a collection error, never as a pass.
The metadata section inventories root access, sudo presence, and tools required
by the active probe pack. Missing capabilities skip affected probe bodies with
an explicit error; probes with a useful but incomplete unprivileged view still
run and annotate that partial evidence.

Exit codes: `0` clean, `1` findings at or above `--fail-on`,
`2` usage error, unwritable output, or (with `--strict-collection`) incomplete
collection.

## Current probe pack

The pack is intentionally small and inspectable (`shuvscan --list-probes`):

| Rule | Severity | Signal |
| --- | --- | --- |
| `SHUV-AUTH-001` | critical | non-root account with UID 0 |
| `SHUV-AUTH-002` | high | effective SSH configuration permits root login |
| `SHUV-AUTH-003` | medium | effective SSH configuration permits passwords |
| `SHUV-PERSIST-001` | critical | system-wide dynamic linker preload |
| `SHUV-PERSIST-002` | high | world-writable cron entry |
| `SHUV-FS-001` | critical | world-writable systemd unit |
| `SHUV-FS-002` | critical | SUID/SGID binary in /tmp, /var/tmp, or /dev/shm |
| `SHUV-PROC-001` | medium | process running a deleted executable |
| `SHUV-KERN-001` | medium | exposed kernel pointers |
| `SHUV-KERN-002` | high | unprivileged BPF enabled |
| `SHUV-EXEC-001` | high | world-writable system executable directory |

### Known limitations

- `sshd -T` (effective SSH config) needs root; unprivileged scans report those
  two probes as *evidence unavailable*. Use `--sudo` when non-interactive sudo
  policy permits the reviewed collector.
- `/proc/<pid>/exe` links of other users' processes are only readable by root,
  so unprivileged `SHUV-PROC-001` results are explicitly marked partial.
- Scheduling is in-memory and non-resumable; resumable fleet scans are planned.

## Architecture

```text
CLI / future TUI
      |
      v
scan engine ---- stable report schema ---- human | JSON | NDJSON | SARIF | OCSF
      |
      v
probe pack ---- evaluator ---- finding + bounded evidence
      |
      v
transport ---- local sh | OpenSSH ---- unmodified Linux host
```

The important boundary is `Probe -> Transport -> Evidence`. Future transports (sudo, container
namespace, fleet API) must not change rule semantics. Future policy packs must not gain arbitrary
host-side execution: commands remain reviewed scanner assets, not user-provided shell snippets.

## North star

The ambitious version of Shuvscan is a local-first Linux defense workbench:

1. **Hundreds of signed probe definitions** spanning persistence, rootkits, credentials, kernel
   attack surface, container escape, cloud metadata, supply chain, and forensic triage.
2. **Evidence graph and temporal baselines** that connect process, socket, package, identity, file,
   service, namespace, and cloud facts, then highlight meaningful drift.
3. **Distributed collection without permanent agents** through SSH fan-out, bastion-aware scheduling,
   host capability negotiation, bounded privilege escalation, and resumable fleet scans.
4. **Policy as data** with versioned packs for CIS, STIG, incident-response hypotheses, and custom
   organization rules, all sharing the same evidence model.
5. **A keyboard-first TUI** for fleet heatmaps, finding pivots, evidence timelines, suppression review,
   and one-keystroke export to SARIF, OCSF, and case-management systems.
6. **Cryptographic provenance** for scanner releases, probe packs, scan manifests, and exported
   evidence, with reproducible builds and offline verification.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Design constraints:

- Probe scripts are static scanner assets. Never interpolate target data into shell.
- A failed probe is not a passing probe. Collection errors remain visible in the report.
- Keep stdout machine-clean for `json` and `jsonl`; diagnostics belong on stderr.
- Bound evidence before retaining or transmitting it.
- New findings require a stable ID, remediation, evaluator tests, and safe/unsafe fixtures.

## Status

`0.1.0` is the walking skeleton: a useful local scanner and a trustworthy set of seams. Next work
should deepen probe correctness and fixture coverage before broadening the rule count.
