use std::{io, process::ExitCode};

use clap::{Parser, ValueEnum};
use shuvscan::{
    engine,
    model::{Severity, Target},
    output,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Human,
    Json,
    Jsonl,
}

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

    /// Return exit 2 if any probe could not be collected.
    #[arg(long)]
    strict_collection: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let reports = engine::scan_all(cli.target);
    let stdout = io::stdout();
    let result = match cli.format {
        Format::Human => output::human(&reports, stdout.lock()).map_err(|error| error.to_string()),
        Format::Json => output::json(&reports, stdout.lock()).map_err(|error| error.to_string()),
        Format::Jsonl => output::jsonl(&reports, stdout.lock()).map_err(|error| error.to_string()),
    };
    if let Err(error) = result {
        eprintln!("shuvscan: could not write report: {error}");
        return ExitCode::from(2);
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
