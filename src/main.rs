use std::{
    ffi::OsString,
    io,
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use clap::{Parser, ValueEnum};
use shuvscan::{
    engine,
    model::{Severity, Target},
    output, packs,
    probes::BUILTINS,
    transport,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Human,
    Json,
    Jsonl,
    Sarif,
    Ocsf,
}

/// Exit codes: 0 clean, 1 findings at or above --fail-on,
/// 2 usage/collection/write failure.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Host to scan: 'local' or an OpenSSH destination. Repeat for a fleet.
    #[arg(short, long, default_value = "local")]
    target: Vec<Target>,

    /// Output contract. Machine-readable formats write only data to stdout.
    #[arg(short, long, value_enum, default_value_t = Format::Human)]
    format: Format,

    /// Return exit 1 when this severity or higher is found.
    #[arg(long, default_value = "high")]
    fail_on: Severity,

    /// Per-target collection timeout in seconds.
    #[arg(long, default_value_t = NonZeroU64::new(60).unwrap(), value_name = "SECONDS")]
    timeout: NonZeroU64,

    /// Maximum number of targets scanned concurrently.
    #[arg(long, default_value_t = NonZeroUsize::new(engine::DEFAULT_CONCURRENCY).unwrap(), value_name = "COUNT")]
    concurrency: NonZeroUsize,

    /// Stream JSONL reports in completion order instead of buffering the fleet.
    #[arg(long)]
    unordered: bool,

    /// Return exit 2 if any probe could not be collected.
    #[arg(long)]
    strict_collection: bool,

    /// Run the reviewed collector through non-interactive sudo (`sudo -n`).
    #[arg(long)]
    sudo: bool,

    /// List probes in the active built-in or signed pack and exit.
    #[arg(long)]
    list_probes: bool,

    /// Signed JSON probe pack manifest to activate instead of the built-in pack.
    #[arg(long, value_name = "PATH", requires = "probe_pack_key")]
    probe_pack: Option<PathBuf>,

    /// Trusted Ed25519 public key as 64 hexadecimal characters.
    #[arg(long, value_name = "PATH", requires = "probe_pack")]
    probe_pack_key: Option<PathBuf>,

    /// Detached Ed25519 signature; defaults to <probe-pack>.sig.
    #[arg(long, value_name = "PATH", requires = "probe_pack")]
    probe_pack_signature: Option<PathBuf>,
}

fn main() -> ExitCode {
    transport::forward_interrupts_to_collectors();
    let cli = Cli::parse();
    if cli.unordered && !matches!(cli.format, Format::Jsonl) {
        eprintln!("shuvscan: --unordered requires --format jsonl");
        return ExitCode::from(2);
    }
    let verified_pack = match (&cli.probe_pack, &cli.probe_pack_key) {
        (Some(manifest), Some(key)) => {
            let signature = cli
                .probe_pack_signature
                .clone()
                .unwrap_or_else(|| signature_path(manifest));
            match packs::load(manifest, &signature, key) {
                Ok(pack) => Some(pack),
                Err(error) => {
                    eprintln!("shuvscan: invalid probe pack: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        _ => None,
    };
    let probes = verified_pack
        .as_ref()
        .map_or(BUILTINS, |pack| pack.probes.as_slice());
    let probe_pack = verified_pack.as_ref().map(|pack| &pack.info);
    if cli.list_probes {
        for probe in probes {
            println!(
                "{:<18} {:<9} {:<12} {}",
                probe.id,
                probe
                    .severity()
                    .map_or_else(|| "evidence".to_owned(), |severity| severity.to_string()),
                probe.category,
                probe.title
            );
        }
        return ExitCode::SUCCESS;
    }

    let stdout = io::stdout();
    if cli.unordered {
        let mut writer = stdout.lock();
        let streamed = engine::scan_all_unordered_with_probes(
            cli.target,
            Duration::from_secs(cli.timeout.get()),
            cli.sudo,
            cli.concurrency,
            probes,
            probe_pack,
            |report| output::jsonl_report(report, &mut writer),
        );
        return match streamed {
            Ok(summary) => report_exit(summary, cli.strict_collection, cli.fail_on),
            Err((error, summary)) if error.kind() == io::ErrorKind::BrokenPipe => {
                report_exit(summary, cli.strict_collection, cli.fail_on)
            }
            Err((error, _)) => {
                eprintln!("shuvscan: could not write report: {error}");
                ExitCode::from(2)
            }
        };
    }

    let reports = engine::scan_all_with_probes(
        cli.target,
        Duration::from_secs(cli.timeout.get()),
        cli.sudo,
        cli.concurrency,
        probes,
        probe_pack,
    );
    let result = match cli.format {
        Format::Human => output::human(&reports, stdout.lock()),
        Format::Json => output::json(&reports, stdout.lock()),
        Format::Jsonl => output::jsonl(&reports, stdout.lock()),
        Format::Sarif => output::sarif_with_probes(&reports, probes, stdout.lock()),
        Format::Ocsf => output::ocsf(&reports, stdout.lock()),
    };
    if let Err(error) = result {
        // A consumer closing the pipe early (`shuvscan | head`) is not a
        // scanner failure; still return the severity-based exit code below.
        if error.kind() != io::ErrorKind::BrokenPipe {
            eprintln!("shuvscan: could not write report: {error}");
            return ExitCode::from(2);
        }
    }
    let mut summary = engine::ScanSummary::default();
    for report in &reports {
        summary.include(report);
    }
    report_exit(summary, cli.strict_collection, cli.fail_on)
}

fn report_exit(
    summary: engine::ScanSummary,
    strict_collection: bool,
    fail_on: Severity,
) -> ExitCode {
    if summary.collector_failed || (strict_collection && summary.collection_incomplete) {
        ExitCode::from(2)
    } else if summary
        .highest_severity
        .is_some_and(|severity| severity >= fail_on)
    {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn signature_path(manifest: &Path) -> PathBuf {
    let mut path: OsString = manifest.as_os_str().to_owned();
    path.push(".sig");
    path.into()
}
