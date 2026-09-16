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

# Stream a very large fleet as JSONL in completion order with bounded memory.
./target/release/shuvscan --target host-01 --target host-02 \
  --format jsonl --unordered

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
Timeouts must also be non-zero. A timeout terminates the collector process
group, including descendants created by a local collector.

By default, reports are sorted by target and buffered until the fleet
completes. `--format jsonl --unordered` instead writes each target as it
finishes, avoids retaining the complete fleet, and is the recommended mode for
very large scans. Repeating a target intentionally scans it repeatedly.

`--format sarif` emits one SARIF 2.1.0 run. Findings use host logical
locations, evidence-only probes are omitted entirely, and collection errors are
tool execution notifications. Use native JSON/JSONL or OCSF when observations
are required. `--format
ocsf` emits an OCSF 1.8.0 JSON array containing one Scan Activity per target
and one Detection Finding per finding; observations are retained as encoded JSON
in the Scan Activity's `unmapped.shuvscan.observations_json` extension. OCSF
`time` records the target's collection completion time, and finding UIDs include
the invocation's scan ID. SARIF run and result properties carry the same scan
identity. Use the native `json` or `jsonl` formats when the complete Shuvscan
report schema is required.

Native report schema version 1 permits additive optional fields. Consumers must
ignore fields they do not recognize.
The native JSON array contract is published at `docs/report.schema.json`; each
line of JSONL is one report object from that schema's `$defs.report`. Every
invocation records one `scan_id`, while each target records Unix-millisecond
`started_at` and `completed_at` collection timestamps.

### Signed probe packs

A probe pack is a signed, versioned JSON manifest that selects and orders
reviewed probe assets compiled into Shuvscan. Packs cannot provide shell,
commands, or evaluator code. This preserves the static-script trust boundary
while allowing an organization to publish a reproducible policy selection.

```json
{
  "schema_version": 1,
  "id": "org.example.linux-baseline",
  "version": "1.0.0",
  "signer": "example-security",
  "probes": ["SHUV-AUTH-001", "SHUV-KERN-002"]
}
```

Activate a pack with its detached Ed25519 signature and an explicitly trusted
public key:

```bash
shuvscan \
  --probe-pack baseline.json \
  --probe-pack-key example-security.pub \
  --format json
```

The public-key file is the 32-byte Ed25519 public key encoded as exactly 64
hexadecimal characters. The detached signature defaults to
`baseline.json.sig` and contains the 64-byte signature as exactly 128
hexadecimal characters; override it with `--probe-pack-signature`. The signature
covers the exact manifest bytes. Shuvscan verifies it before parsing, then
rejects unknown fields, unsupported schema versions, malformed metadata,
duplicate IDs, and IDs that do not resolve to compiled probe assets. The schema
is published at `docs/probe-pack.schema.json`.

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
`2` usage error, unwritable output, total collector failure, or (with
`--strict-collection`) any incomplete per-probe collection. A target that was
not collected is never reported as a pass, even without `--strict-collection`.

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

Evidence-only probes collect context without producing findings or changing the
severity-based exit code:

| Probe | Evidence |
| --- | --- |
| `SHUV-EVID-PKG-001` | bounded running executable ownership from dpkg, RPM, apk, or pacman |
| `SHUV-EVID-PROC-001` | bounded PID/PPID pairs with real/effective UIDs, name, and command line |
| `SHUV-EVID-NET-001` | bounded listening TCP/UDP sockets and visible process owners |
| `SHUV-EVID-NS-001` | bounded per-process Linux namespace identities |
| `SHUV-EVID-CONT-001` | container markers, cgroups, and container-related mounts |

### Known limitations

- `sshd -T` (effective SSH config) needs root; unprivileged scans report those
  two probes as *evidence unavailable*. Use `--sudo` when non-interactive sudo
  policy permits the reviewed collector.
- SSH `Match` blocks depend on connection attributes. The current SSH probes
  evaluate `sshd -T`'s context-free effective configuration; review conditional
  policy separately when a deployment relies on `Match User`, `Match Address`,
  or similar clauses.
- `/proc/<pid>/exe` links of other users' processes are only readable by root,
  and process/socket/namespace/cgroup visibility can also be restricted by
  `hidepid` or kernel policy. Those unprivileged results are explicitly marked
  partial and remain collection errors for `--strict-collection`.
- Process-based observations retain a low/high PID sample. Access controls may
  filter either half after sampling; `partial` reports skipped records. Socket
  observations bound TCP and UDP independently.
- Package ownership is retained in each package manager's native text format;
  use `package_manager` when parsing `owner` values across distributions.
- Each observation has collector-specific work bounds and an 8 KiB retained
  evidence budget. `collection_limits` names every collector bound reached;
  `evidence_budget_exceeded` reports byte truncation; `truncated` is true when
  either applies. On ordinary multi-process hosts, process sample limits and
  therefore `truncated: true` are expected. Absence beyond any boundary must not
  be interpreted as proof.
- The transport retains at most 512 KiB of collector stdout and 4 KiB of
  stderr per target while continuing to drain excess bytes. Crossing the stdout
  limit marks the target as a collector failure because the framed transcript
  may be incomplete.
- Pack signatures authenticate exact manifest bytes but do not provide
  revocation or rollback protection. Pin the expected pack version in deployment
  configuration and rotate trusted key files when a signer is revoked. Reports
  record both pack and scanner versions because compiled probe implementations
  belong to the scanner release.
- Scheduling is in-memory and non-resumable; resumable fleet scans are planned.

## Architecture

```text
CLI / future TUI
      |
      v
scan engine ---- stable report schema ---- human | JSON | NDJSON | SARIF | OCSF
      |
      v
probe pack ---- detection evaluator ---- finding
           `---- evidence collector ---- bounded observation
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

JJ does not provide a `diff --check` flag. For a read-only whitespace check of the current
working-copy patch, use `jj diff --git | git apply --check --whitespace=error --allow-empty --cached -`;
use `cargo fmt --check` for Rust formatting and a targeted `rg` check when reviewing a specific
changed file.

Design constraints:

- Probe scripts are static scanner assets. Never interpolate target or probe-pack data into shell.
- A failed probe is not a passing probe. Collection errors remain visible in the report.
- Keep stdout machine-clean for `json` and `jsonl`; diagnostics belong on stderr.
- Bound evidence before retaining or transmitting it.
- New findings require a stable ID, remediation, evaluator tests, and safe/unsafe fixtures.

## Status

`0.1.0` is the walking skeleton: a useful local scanner and a trustworthy set of seams. Next work
should deepen probe correctness and fixture coverage before broadening the rule count.
