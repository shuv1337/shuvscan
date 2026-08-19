use std::io::{self, Write};

use crate::model::ScanReport;

pub fn human(reports: &[ScanReport], mut writer: impl Write) -> io::Result<()> {
    for report in reports {
        writeln!(
            writer,
            "\nshuvscan {}  target={}  probes={}  {}ms",
            report.scanner_version, report.target, report.probes_run, report.duration_ms
        )?;
        writeln!(writer, "{}", "-".repeat(72))?;
        if report.findings.is_empty() {
            writeln!(
                writer,
                "PASS  No findings detected by the active probe pack."
            )?;
        }
        for finding in &report.findings {
            writeln!(
                writer,
                "{:<8} {}  {}",
                finding.severity.to_string().to_uppercase(),
                finding.id,
                finding.title
            )?;
            if !finding.evidence.output.is_empty() {
                for line in finding.evidence.output.lines().take(4) {
                    writeln!(writer, "         evidence: {line}")?;
                }
            }
            writeln!(writer, "         fix: {}", finding.remediation)?;
        }
        for error in &report.errors {
            writeln!(writer, "ERROR    {}  {}", error.probe, error.message)?;
        }
        writeln!(
            writer,
            "\n{} finding(s), {} collection error(s)",
            report.findings.len(),
            report.errors.len()
        )?;
    }
    Ok(())
}

pub fn json(reports: &[ScanReport], mut writer: impl Write) -> Result<(), serde_json::Error> {
    serde_json::to_writer_pretty(&mut writer, reports)?;
    writeln!(writer).map_err(serde_json::Error::io)
}

pub fn jsonl(reports: &[ScanReport], mut writer: impl Write) -> Result<(), serde_json::Error> {
    for report in reports {
        serde_json::to_writer(&mut writer, report)?;
        writeln!(writer).map_err(serde_json::Error::io)?;
    }
    Ok(())
}
