use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    num::{NonZeroU64, NonZeroUsize},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::Duration,
};

use clap::{Parser, ValueEnum};
use shuvscan::{
    engine,
    model::{ScanReport, Severity, Target},
    output, packs,
    probes::{BUILTINS, Probe},
    transport, tui,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Human,
    Json,
    Jsonl,
    Sarif,
    Ocsf,
    Html,
    Tui,
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

    /// Write the report to PATH instead of stdout. Not valid with --format tui.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Open the HTML report with xdg-open after writing.
    #[arg(long, requires = "output")]
    open: bool,

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
    if matches!(cli.format, Format::Tui) {
        if cli.output.is_some() {
            eprintln!("shuvscan: --format tui does not support --output");
            return ExitCode::from(2);
        }
        if cli.unordered {
            eprintln!("shuvscan: --format tui does not support --unordered");
            return ExitCode::from(2);
        }
    }
    if cli.unordered && !matches!(cli.format, Format::Jsonl) {
        eprintln!("shuvscan: --unordered requires --format jsonl");
        return ExitCode::from(2);
    }
    if cli.open && !matches!(cli.format, Format::Html) {
        eprintln!("shuvscan: --open requires --format html");
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

    if matches!(cli.format, Format::Tui) {
        if let Err(error) = tui::ensure_interactive() {
            eprintln!("shuvscan: {error}");
            return ExitCode::from(2);
        }
    }

    let mut writer = match report_writer(cli.output.as_deref(), cli.format) {
        Ok(writer) => writer,
        Err(error) => {
            eprintln!("shuvscan: could not write report: {error}");
            return ExitCode::from(2);
        }
    };

    if cli.unordered {
        let streamed = engine::scan_all_unordered_with_probes(
            cli.target,
            Duration::from_secs(cli.timeout.get()),
            cli.sudo,
            cli.concurrency,
            probes,
            probe_pack,
            |report| output::jsonl_report(report, &mut writer),
        );
        if streamed.is_ok() {
            if let Err(error) = writer.persist() {
                if error.kind() != io::ErrorKind::BrokenPipe {
                    eprintln!("shuvscan: could not write report: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        return streamed_exit(streamed, cli.strict_collection, cli.fail_on);
    }

    let targets_requested = cli.target.len();
    let reports = engine::scan_all_with_probes(
        cli.target,
        Duration::from_secs(cli.timeout.get()),
        cli.sudo,
        cli.concurrency,
        probes,
        probe_pack,
    );
    if matches!(cli.format, Format::Tui) {
        if let Err(error) = tui::run(&reports) {
            eprintln!("shuvscan: {error}");
            return ExitCode::from(2);
        }
        let mut summary = engine::ScanSummary::for_targets(targets_requested);
        for report in &reports {
            summary.include(report);
        }
        return report_exit(summary, cli.strict_collection, cli.fail_on);
    }

    let result = write_reports(cli.format, &reports, probes, &mut writer);
    if let Err(error) = result.and_then(|()| writer.persist()) {
        // A consumer closing the pipe early (`shuvscan | head`) is not a
        // scanner failure; still return the severity-based exit code below.
        if error.kind() != io::ErrorKind::BrokenPipe {
            eprintln!("shuvscan: could not write report: {error}");
            return ExitCode::from(2);
        }
    }
    if cli.open {
        if let Some(path) = &cli.output {
            open_html_report(path);
        }
    }
    let mut summary = engine::ScanSummary::for_targets(targets_requested);
    for report in &reports {
        summary.include(report);
    }
    report_exit(summary, cli.strict_collection, cli.fail_on)
}

enum ReportWriter {
    Stdout(io::Stdout),
    File(OutputFile),
    Sink,
}

impl Write for ReportWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stdout(writer) => writer.write(buf),
            Self::File(writer) => writer.write(buf),
            Self::Sink => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout(writer) => writer.flush(),
            Self::File(writer) => writer.flush(),
            Self::Sink => Ok(()),
        }
    }
}

impl ReportWriter {
    fn persist(self) -> io::Result<()> {
        match self {
            Self::File(file) => file.persist(),
            Self::Stdout(mut writer) => writer.flush(),
            Self::Sink => Ok(()),
        }
    }
}

struct OutputFile {
    inner: BufWriter<File>,
    tmp_path: PathBuf,
    dest: PathBuf,
    persisted: bool,
}

impl OutputFile {
    fn create(dest: &Path) -> io::Result<Self> {
        if dest.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "Is a directory",
            ));
        }
        let file_name = dest.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "output path has no file name")
        })?;
        let parent = dest.parent().filter(|path| !path.as_os_str().is_empty());
        for attempt in 0..16 {
            let mut tmp_name = file_name.to_os_string();
            tmp_name.push(format!(".{}.{attempt}.tmp", std::process::id()));
            let tmp_path = match parent {
                Some(parent) => parent.join(&tmp_name),
                None => PathBuf::from(&tmp_name),
            };
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
            {
                Ok(file) => {
                    let mut permissions = file.metadata()?.permissions();
                    permissions.set_mode(0o600);
                    file.set_permissions(permissions)?;
                    return Ok(Self {
                        inner: BufWriter::new(file),
                        tmp_path,
                        dest: dest.to_path_buf(),
                        persisted: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a private temporary report file",
        ))
    }

    fn persist(mut self) -> io::Result<()> {
        self.inner.flush()?;
        self.inner.get_ref().sync_all()?;
        fs::rename(&self.tmp_path, &self.dest)?;
        self.persisted = true;
        Ok(())
    }
}

impl Write for OutputFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Drop for OutputFile {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}

fn report_writer(path: Option<&Path>, format: Format) -> io::Result<ReportWriter> {
    if matches!(format, Format::Tui) {
        return Ok(ReportWriter::Sink);
    }
    match path {
        Some(path) => Ok(ReportWriter::File(OutputFile::create(path)?)),
        None => Ok(ReportWriter::Stdout(io::stdout())),
    }
}

fn write_reports(
    format: Format,
    reports: &[ScanReport],
    probes: &[Probe],
    writer: &mut dyn Write,
) -> io::Result<()> {
    match format {
        Format::Human => output::human(reports, writer),
        Format::Json => output::json(reports, writer),
        Format::Jsonl => output::jsonl(reports, writer),
        Format::Sarif => output::sarif_with_probes(reports, probes, writer),
        Format::Ocsf => output::ocsf(reports, writer),
        Format::Html => output::html(reports, writer),
        Format::Tui => Ok(()),
    }
}

fn open_html_report(path: &Path) {
    let absolute = match path.canonicalize() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("shuvscan: could not open report: {error}");
            return;
        }
    };
    if let Err(error) = Command::new("xdg-open")
        .arg(&absolute)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        eprintln!("shuvscan: could not open report: {error}");
    }
}

fn streamed_exit(
    streamed: Result<engine::ScanSummary, (io::Error, engine::ScanSummary)>,
    strict_collection: bool,
    fail_on: Severity,
) -> ExitCode {
    match streamed {
        Ok(summary) => report_exit(summary, strict_collection, fail_on),
        Err((error, summary)) if error.kind() == io::ErrorKind::BrokenPipe => {
            report_exit(summary, strict_collection, fail_on)
        }
        Err((error, _)) => {
            eprintln!("shuvscan: could not write report: {error}");
            ExitCode::from(2)
        }
    }
}

fn report_exit(
    summary: engine::ScanSummary,
    strict_collection: bool,
    fail_on: Severity,
) -> ExitCode {
    if !summary.coverage_complete()
        || summary.collector_failed
        || (strict_collection && summary.collection_incomplete)
    {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn summary(targets_requested: usize, targets_completed: usize) -> engine::ScanSummary {
        engine::ScanSummary {
            targets_requested,
            targets_completed,
            ..engine::ScanSummary::default()
        }
    }

    #[test]
    fn broken_pipe_with_incomplete_coverage_exits_two() {
        let streamed = Err((
            io::Error::new(io::ErrorKind::BrokenPipe, "consumer closed the pipe"),
            summary(2, 1),
        ));

        assert_eq!(
            streamed_exit(streamed, false, Severity::Critical),
            ExitCode::from(2)
        );
    }

    #[test]
    fn broken_pipe_after_complete_coverage_keeps_scan_result() {
        let streamed = Err((
            io::Error::new(io::ErrorKind::BrokenPipe, "consumer closed the pipe"),
            summary(2, 2),
        ));

        assert_eq!(
            streamed_exit(streamed, false, Severity::Critical),
            ExitCode::SUCCESS
        );
    }

    #[test]
    fn other_stream_write_errors_exit_two() {
        let streamed = Err((
            io::Error::new(io::ErrorKind::WriteZero, "could not write report"),
            summary(2, 2),
        ));

        assert_eq!(
            streamed_exit(streamed, false, Severity::Critical),
            ExitCode::from(2)
        );
    }

    #[test]
    fn report_file_stays_private_and_replaces_atomically() {
        let directory = std::env::temp_dir().join(format!(
            "shuvscan-main-atomic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let dest = directory.join("report.html");
        fs::write(&dest, "OLD").unwrap();

        let mut file = OutputFile::create(&dest).unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "OLD");
        file.write_all(b"NEW").unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "OLD");
        file.persist().unwrap();

        assert_eq!(fs::read_to_string(&dest).unwrap(), "NEW");
        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn report_file_drop_leaves_destination_untouched() {
        let directory = std::env::temp_dir().join(format!(
            "shuvscan-main-drop-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let dest = directory.join("report.html");
        fs::write(&dest, "OLD").unwrap();

        let mut file = OutputFile::create(&dest).unwrap();
        file.write_all(b"NEW").unwrap();
        let tmp_path = file.tmp_path.clone();
        drop(file);

        assert_eq!(fs::read_to_string(&dest).unwrap(), "OLD");
        assert!(!tmp_path.exists());
        let _ = fs::remove_dir_all(&directory);
    }
}
