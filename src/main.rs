use std::{
    ffi::OsString,
    io,
    num::NonZeroUsize,
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
    #[arg(long, default_value_t = 60, value_name = "SECONDS")]
    timeout: u64,

    /// Maximum number of targets scanned concurrently.
    #[arg(long, default_value_t = NonZeroUsize::new(engine::DEFAULT_CONCURRENCY).unwrap(), value_name = "COUNT")]
    concurrency: NonZeroUsize,

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
    let cli = Cli::parse();
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

    let reports = engine::scan_all_with_probes(
        cli.target,
        Duration::from_secs(cli.timeout),
        cli.sudo,
        cli.concurrency,
        probes,
        probe_pack,
    );
    let stdout = io::stdout();
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
    if cli.strict_collection && reports.iter().any(|report| !report.errors.is_empty()) {
        return ExitCode::from(2);
    }
    if reports
        .iter()
        .filter_map(|report| report.highest_severity())
        .any(|severity| severity >= cli.fail_on)
    {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn signature_path(manifest: &Path) -> PathBuf {
    let mut path: OsString = manifest.as_os_str().to_owned();
    path.push(".sig");
    path.into()
}
