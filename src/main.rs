use std::{io, num::NonZeroUsize, process::ExitCode, time::Duration};

use clap::{Parser, ValueEnum};
use shuvscan::{
    engine,
    model::{Severity, Target},
    output,
    probes::BUILTINS,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Human,
    Json,
    Jsonl,
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

    /// List the built-in probes and exit.
    #[arg(long)]
    list_probes: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.list_probes {
        for probe in BUILTINS {
            println!(
                "{:<18} {:<9} {:<12} {}",
                probe.id,
                probe.severity.to_string(),
                probe.category,
                probe.title
            );
        }
        return ExitCode::SUCCESS;
    }

    let reports = engine::scan_all(
        cli.target,
        Duration::from_secs(cli.timeout),
        cli.sudo,
        cli.concurrency,
    );
    let stdout = io::stdout();
    let result = match cli.format {
        Format::Human => output::human(&reports, stdout.lock()),
        Format::Json => output::json(&reports, stdout.lock()),
        Format::Jsonl => output::jsonl(&reports, stdout.lock()),
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
