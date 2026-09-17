use std::io::{self, Write};

use serde_json::{Value, json};

use crate::{
    model::{ScanReport, Severity},
    probes::BUILTINS,
};

const OCSF_VERSION: &str = "1.8.0";

pub fn human(reports: &[ScanReport], mut writer: impl Write) -> io::Result<()> {
    for report in reports {
        writeln!(
            writer,
            "\nshuvscan {}  target={}  probes={}  {}ms",
            terminal_safe(report.scanner_version),
            terminal_safe(&report.target),
            report.probes_run,
            report.duration_ms
        )?;
        if let Some(pack) = &report.probe_pack {
            writeln!(
                writer,
                "pack {}@{}  signer={}  schema={}",
                terminal_safe(&pack.id),
                terminal_safe(&pack.version),
                terminal_safe(&pack.signer),
                pack.schema_version
            )?;
        }
        if let Some(host) = &report.host {
            writeln!(
                writer,
                "host {}  kernel {}  {}",
                terminal_safe(&host.hostname),
                terminal_safe(&host.kernel),
                terminal_safe(&host.os)
            )?;
            writeln!(
                writer,
                "capabilities root={}  sudo_present={}  tools={}",
                host.capabilities
                    .root
                    .map(|root| root.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                host.capabilities.sudo_present,
                terminal_safe(&host.capabilities.tools.join(","))
            )?;
        }
        writeln!(writer, "{}", "-".repeat(72))?;
        if report.findings.is_empty() && report.errors.is_empty() {
            writeln!(
                writer,
                "PASS  No findings detected by the active probe pack."
            )?;
        }
        if !report.errors.is_empty() {
            writeln!(
                writer,
                "INCOMPLETE  Collection errors prevent a complete verdict."
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
            if finding.evidence_truncated {
                writeln!(
                    writer,
                    "         evidence truncated: {} byte(s) omitted ({}-byte limit)",
                    finding.evidence_omitted_bytes, finding.evidence_limit_bytes
                )?;
            }
            if !finding.evidence.output.is_empty() {
                let line_count = finding.evidence.output.lines().count();
                for line in finding.evidence.output.lines().take(4) {
                    writeln!(writer, "         evidence: {}", terminal_safe(line))?;
                }
                if line_count > 4 {
                    writeln!(
                        writer,
                        "         ({} more evidence line(s); use --format json for the full evidence)",
                        line_count - 4
                    )?;
                }
            }
            writeln!(writer, "         fix: {}", finding.remediation)?;
        }
        for observation in &report.observations {
            writeln!(writer, "EVIDENCE {}  {}", observation.id, observation.title)?;
            if let Some(partial) = &observation.partial {
                writeln!(writer, "         partial: {}", terminal_safe(partial))?;
            }
            if observation.truncated {
                writeln!(writer, "         truncated: true")?;
            }
            for limit in &observation.collection_limits {
                writeln!(
                    writer,
                    "         collection limit: {}",
                    terminal_safe(limit)
                )?;
            }
            if observation.evidence_budget_exceeded {
                writeln!(writer, "         evidence budget exceeded: true")?;
            }
            let line_count = observation.evidence.output.lines().count();
            for line in observation.evidence.output.lines().take(2) {
                writeln!(writer, "         data: {}", terminal_safe(line))?;
            }
            if line_count > 2 {
                writeln!(writer, "         data: ... {} more line(s)", line_count - 2)?;
            }
        }
        for error in &report.errors {
            writeln!(
                writer,
                "ERROR    {}  {}",
                terminal_safe(error.probe),
                terminal_safe(&error.message)
            )?;
        }
        writeln!(
            writer,
            "\n{} finding(s), {} observation(s), {} collection error(s)",
            report.findings.len(),
            report.observations.len(),
            report.errors.len()
        )?;
    }
    Ok(())
}

pub(crate) fn terminal_safe(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() || is_bidi_control(character) {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

pub fn json(reports: &[ScanReport], mut writer: impl Write) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut writer, reports).map_err(io::Error::from)?;
    writeln!(writer)
}

pub fn jsonl(reports: &[ScanReport], mut writer: impl Write) -> io::Result<()> {
    for report in reports {
        jsonl_report(report, &mut writer)?;
    }
    Ok(())
}

pub fn jsonl_report(report: &ScanReport, mut writer: impl Write) -> io::Result<()> {
    serde_json::to_writer(&mut writer, report).map_err(io::Error::from)?;
    writeln!(writer)
}

pub fn sarif(reports: &[ScanReport], mut writer: impl Write) -> io::Result<()> {
    sarif_with_probes(reports, BUILTINS, &mut writer)
}

pub fn sarif_with_probes(
    reports: &[ScanReport],
    probes: &[crate::probes::Probe],
    mut writer: impl Write,
) -> io::Result<()> {
    let detection_probes = probes
        .iter()
        .filter(|probe| probe.evaluator().is_some())
        .collect::<Vec<_>>();
    let rules = detection_probes
        .iter()
        .map(|probe| {
            let severity = probe.severity().expect("filtered detection probe");
            let remediation = probe.remediation().expect("filtered detection probe");
            json!({
                "id": probe.id,
                "shortDescription": { "text": probe.title },
                "fullDescription": { "text": probe.description },
                "help": { "text": remediation },
                "defaultConfiguration": { "level": sarif_level(severity) },
                "properties": { "tags": ["security", probe.category] }
            })
        })
        .collect::<Vec<_>>();
    let results = reports
        .iter()
        .flat_map(|report| {
            report.findings.iter().map(|finding| {
                let mut result = json!({
                    "ruleId": finding.id,
                    "level": sarif_level(finding.severity),
                    "message": { "text": finding.description },
                    "locations": [{
                        "logicalLocations": [{
                            "name": report.target,
                            "fullyQualifiedName": report.target,
                            "kind": "host"
                        }]
                    }],
                    "properties": {
                        "scanId": report.scan_id,
                        "startedAt": report.started_at,
                        "completedAt": report.completed_at,
                        "target": report.target,
                        "category": finding.category,
                        "severity": finding.severity.to_string(),
                        "evidence": finding.evidence.output,
                        "evidenceTruncated": finding.evidence_truncated,
                        "evidenceOmittedBytes": finding.evidence_omitted_bytes,
                        "evidenceLimitBytes": finding.evidence_limit_bytes,
                        "remediation": finding.remediation
                    }
                });
                if let Some(index) = detection_probes
                    .iter()
                    .position(|probe| probe.id == finding.id)
                {
                    result["ruleIndex"] = json!(index);
                }
                result
            })
        })
        .collect::<Vec<_>>();
    let collection_failed = reports.iter().any(|report| !report.errors.is_empty());
    let mut notifications = reports
        .iter()
        .flat_map(|report| {
            report.errors.iter().map(|error| {
                json!({
                    "level": "error",
                    "message": {
                        "text": format!("{}: {}: {}", report.target, error.probe, error.message)
                    },
                    "properties": {
                        "scanId": report.scan_id,
                        "target": report.target,
                        "probe": error.probe
                    }
                })
            })
        })
        .collect::<Vec<_>>();
    notifications.extend(reports.iter().filter(|report| !report.observations.is_empty()).map(
        |report| {
            json!({
                "level": "note",
                "message": {
                    "text": format!(
                        "{}: {} evidence observation(s) omitted from SARIF; use JSON, JSONL, or OCSF",
                        report.target,
                        report.observations.len()
                    )
                },
                "properties": {
                    "target": report.target,
                    "observationsOmitted": report.observations.len()
                }
            })
        },
    ));
    let mut run = json!({
        "tool": {
            "driver": {
                "name": "shuvscan",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules
            }
        },
        "results": results,
        "invocations": [{
            "executionSuccessful": !collection_failed,
            "toolExecutionNotifications": notifications
        }]
    });
    if let Some(report) = reports.first() {
        run["properties"] = json!({ "scanId": report.scan_id });
        if let Some(pack) = report.probe_pack.as_ref() {
            run["properties"]["probePack"] = json!(pack);
        }
    }
    let log = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run]
    });

    serde_json::to_writer_pretty(&mut writer, &log).map_err(io::Error::from)?;
    writeln!(writer)
}

pub fn ocsf(reports: &[ScanReport], mut writer: impl Write) -> io::Result<()> {
    let mut events = Vec::new();
    for report in reports {
        let time = report.completed_at;
        let collection_failed = report.errors.iter().any(|error| error.probe == "collector");
        let activity_id = if collection_failed { 6 } else { 2 };
        let activity_name = if collection_failed {
            "Error"
        } else {
            "Completed"
        };
        let errors = report
            .errors
            .iter()
            .map(|error| json!({ "probe": error.probe, "message": error.message }))
            .collect::<Vec<_>>();
        let mut scan_event = json!({
            "activity_id": activity_id,
            "activity_name": activity_name,
            "category_uid": 6,
            "category_name": "Application Activity",
            "class_uid": 6007,
            "class_name": "Scan Activity",
            "duration": report.duration_ms,
            "message": format!("shuvscan {activity_name} target {}", report.target),
            "metadata": ocsf_metadata(report.scanner_version),
            "num_detections": report.findings.len(),
            "scan": { "name": "shuvscan target scan", "type_id": 0 },
            "severity_id": 1,
            "severity": "Informational",
            "status_id": if report.errors.is_empty() { 1 } else { 2 },
            "status": if report.errors.is_empty() { "Success" } else { "Failure" },
            "time": time,
            "total": if collection_failed { 0 } else { report.probes_run },
            "type_uid": 600700 + activity_id,
            "type_name": format!("Scan Activity: {activity_name}"),
            "unmapped": {
                "shuvscan": {
                    "target": report.target,
                    "scan_id": report.scan_id,
                    "started_at": report.started_at,
                    "completed_at": report.completed_at,
                    "collection_errors": errors
                }
            }
        });
        if let Some(pack) = &report.probe_pack {
            scan_event["unmapped"]["shuvscan"]["probe_pack"] = json!(pack);
        }
        if !report.observations.is_empty() {
            let observations = serde_json::to_string(&report.observations).map_err(|error| {
                io::Error::other(format!("could not encode observations: {error}"))
            })?;
            scan_event["unmapped"]["shuvscan"]["observations_json"] = json!(observations);
        }
        events.push(scan_event);

        for finding in &report.findings {
            let mut event = json!({
                "activity_id": 1,
                "activity_name": "Create",
                "category_uid": 2,
                "category_name": "Findings",
                "class_uid": 2004,
                "class_name": "Detection Finding",
                "evidences": [{
                    "name": "shuvscan collector stdout",
                    "data": {
                        "command": finding.evidence.command,
                        "output": finding.evidence.output
                    }
                }],
                "finding_info": {
                    "uid": format!("{}:{}:{}", report.scan_id, report.target, finding.id),
                    "title": finding.title,
                    "desc": finding.description,
                    "types": [finding.category]
                },
                "is_alert": true,
                "message": finding.description,
                "metadata": ocsf_metadata(report.scanner_version),
                "remediation": { "desc": finding.remediation },
                "severity_id": ocsf_severity_id(finding.severity),
                "severity": ocsf_severity(finding.severity),
                "status_id": 1,
                "status": "New",
                "time": time,
                "type_uid": 200401,
                "type_name": "Detection Finding: Create",
                "unmapped": {
                    "shuvscan": {
                        "target": report.target,
                        "scan_id": report.scan_id,
                        "rule_id": finding.id,
                        "evidence_truncated": finding.evidence_truncated,
                        "evidence_omitted_bytes": finding.evidence_omitted_bytes,
                        "evidence_limit_bytes": finding.evidence_limit_bytes
                    }
                }
            });
            if let Some(host) = &report.host {
                event["device"] = json!({
                    "hostname": host.hostname,
                    "type_id": 0
                });
            }
            if let Some(pack) = &report.probe_pack {
                event["unmapped"]["shuvscan"]["probe_pack"] = json!(pack);
            }
            events.push(event);
        }
    }

    serde_json::to_writer_pretty(&mut writer, &events).map_err(io::Error::from)?;
    writeln!(writer)
}

fn ocsf_metadata(scanner_version: &str) -> Value {
    json!({
        "version": OCSF_VERSION,
        "product": {
            "name": "shuvscan",
            "version": scanner_version
        }
    })
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Info | Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

fn ocsf_severity_id(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

fn ocsf_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "Informational",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

/// Self-contained HTML report: inline CSS, no JavaScript, no external resources.
/// Host-derived strings are first made terminal-safe, then HTML-escaped.
pub fn html(reports: &[ScanReport], mut writer: impl Write) -> io::Result<()> {
    writeln!(
        writer,
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; script-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'\">\n<title>shuvscan report</title>\n<style>"
    )?;
    writeln!(writer, "{}", HTML_STYLE)?;
    writeln!(writer, "</style>\n</head>\n<body>")?;
    writeln!(writer, "<header>")?;
    writeln!(writer, "<h1>shuvscan</h1>")?;
    let finding_count: usize = reports.iter().map(|report| report.findings.len()).sum();
    let observation_count: usize = reports.iter().map(|report| report.observations.len()).sum();
    let error_count: usize = reports.iter().map(|report| report.errors.len()).sum();
    let incomplete = reports.iter().any(|report| !report.errors.is_empty());
    writeln!(
        writer,
        "<p class=\"summary\">{} target(s), {} finding(s), {} observation(s), {} collection error(s)</p>",
        reports.len(),
        finding_count,
        observation_count,
        error_count
    )?;
    if incomplete {
        writeln!(
            writer,
            "<p class=\"verdict incomplete\">INCOMPLETE  Collection errors prevent a complete verdict.</p>"
        )?;
    } else if finding_count == 0 {
        writeln!(
            writer,
            "<p class=\"verdict pass\">PASS  No findings detected by the active probe pack.</p>"
        )?;
    } else {
        writeln!(writer, "<p class=\"verdict findings\">FINDINGS</p>")?;
    }
    if reports.len() > 1 {
        writeln!(writer, "<nav aria-label=\"Targets\"><ol>")?;
        for (index, report) in reports.iter().enumerate() {
            writeln!(
                writer,
                "<li><a href=\"#target-{index}\">{}</a> ({} finding(s), {} error(s))</li>",
                escape(&report.target),
                report.findings.len(),
                report.errors.len()
            )?;
        }
        writeln!(writer, "</ol></nav>")?;
    }
    writeln!(writer, "</header>")?;

    for (index, report) in reports.iter().enumerate() {
        write_html_target(&mut writer, index, report)?;
    }

    writeln!(writer, "</body>\n</html>")?;
    Ok(())
}

const HTML_STYLE: &str = "\
body{font:16px/1.45 system-ui,sans-serif;margin:0 auto;max-width:56rem;padding:1.5rem;color:#111;background:#fafafa}\n\
header{margin-bottom:2rem}\n\
h1{font-size:1.4rem;margin:0 0 .5rem}\n\
h2{font-size:1.15rem;margin:1.5rem 0 .5rem}\n\
h3{font-size:1rem;margin:1rem 0 .35rem}\n\
.summary,.meta{color:#444}\n\
.verdict{font-weight:700}\n\
.verdict.incomplete{color:#8a1c00}\n\
.verdict.pass{color:#0b5d1e}\n\
.verdict.findings{color:#8a1c00}\n\
article{background:#fff;border:1px solid #ddd;border-radius:.4rem;padding:1rem 1.25rem;margin:1rem 0}\n\
.finding,.observation,.error{border-top:1px solid #eee;padding:.75rem 0}\n\
.finding:first-of-type,.observation:first-of-type,.error:first-of-type{border-top:0}\n\
.sev{display:inline-block;min-width:5.5rem;font-weight:700;text-transform:uppercase}\n\
.sev.critical,.sev.high{color:#8a1c00}\n\
.sev.medium{color:#8a5a00}\n\
.sev.low,.sev.info{color:#1a4a7a}\n\
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f4;padding:.6rem .75rem;border-radius:.3rem}\n\
details>summary{cursor:pointer}\n\
.fix{margin:.4rem 0 0}\n\
nav ol{padding-left:1.25rem}";

fn write_html_target(writer: &mut impl Write, index: usize, report: &ScanReport) -> io::Result<()> {
    writeln!(writer, "<article id=\"target-{index}\">")?;
    writeln!(writer, "<h2>{}</h2>", escape(&report.target))?;
    writeln!(
        writer,
        "<p class=\"meta\">shuvscan {}  probes={}  {}ms  scan_id={}  collected {} – {}</p>",
        escape(report.scanner_version),
        report.probes_run,
        report.duration_ms,
        escape(&report.scan_id),
        escape(&unix_millis_utc(report.started_at)),
        escape(&unix_millis_utc(report.completed_at))
    )?;
    if let Some(pack) = &report.probe_pack {
        writeln!(
            writer,
            "<p class=\"meta\">pack {}@{}  signer={}  schema={}</p>",
            escape(&pack.id),
            escape(&pack.version),
            escape(&pack.signer),
            pack.schema_version
        )?;
    }
    if let Some(host) = &report.host {
        writeln!(
            writer,
            "<p class=\"meta\">host {}  kernel {}  {}</p>",
            escape(&host.hostname),
            escape(&host.kernel),
            escape(&host.os)
        )?;
        let root = host
            .capabilities
            .root
            .map(|root| root.to_string())
            .unwrap_or_else(|| "unknown".into());
        writeln!(
            writer,
            "<p class=\"meta\">capabilities root={}  sudo_present={}  tools={}</p>",
            escape(&root),
            host.capabilities.sudo_present,
            escape(&host.capabilities.tools.join(","))
        )?;
    }
    if !report.errors.is_empty() {
        writeln!(
            writer,
            "<p class=\"verdict incomplete\">INCOMPLETE  Collection errors prevent a complete verdict.</p>"
        )?;
    } else if report.findings.is_empty() {
        writeln!(
            writer,
            "<p class=\"verdict pass\">PASS  No findings detected by the active probe pack.</p>"
        )?;
    }

    for finding in &report.findings {
        writeln!(
            writer,
            "<section class=\"finding\"><h3><span class=\"sev {}\">{}</span> {}  {}</h3>",
            finding.severity,
            finding.severity.to_string().to_uppercase(),
            escape(finding.id),
            escape(finding.title)
        )?;
        writeln!(writer, "<p>{}</p>", escape(finding.description))?;
        if !finding.evidence.command.is_empty() {
            writeln!(
                writer,
                "<p class=\"meta\">command: {}</p>",
                escape(finding.evidence.command)
            )?;
        }
        if finding.evidence_truncated {
            writeln!(
                writer,
                "<p>evidence truncated: {} byte(s) omitted ({}-byte limit)</p>",
                finding.evidence_omitted_bytes, finding.evidence_limit_bytes
            )?;
        }
        if !finding.evidence.output.is_empty() {
            writeln!(writer, "<details open><summary>evidence</summary><pre>")?;
            write!(writer, "{}", escape(&finding.evidence.output))?;
            writeln!(writer, "</pre></details>")?;
        }
        writeln!(
            writer,
            "<p class=\"fix\">fix: {}</p></section>",
            escape(finding.remediation)
        )?;
    }

    for observation in &report.observations {
        writeln!(
            writer,
            "<section class=\"observation\"><h3>EVIDENCE {}  {}</h3>",
            escape(observation.id),
            escape(observation.title)
        )?;
        if !observation.evidence.command.is_empty() {
            writeln!(
                writer,
                "<p class=\"meta\">command: {}</p>",
                escape(observation.evidence.command)
            )?;
        }
        if let Some(partial) = &observation.partial {
            writeln!(writer, "<p>partial: {}</p>", escape(partial))?;
        }
        if observation.truncated {
            writeln!(writer, "<p>truncated: true</p>")?;
        }
        for limit in &observation.collection_limits {
            writeln!(writer, "<p>collection limit: {}</p>", escape(limit))?;
        }
        if observation.evidence_budget_exceeded {
            writeln!(writer, "<p>evidence budget exceeded: true</p>")?;
        }
        if !observation.evidence.output.is_empty() {
            writeln!(writer, "<details><summary>data</summary><pre>")?;
            write!(writer, "{}", escape(&observation.evidence.output))?;
            writeln!(writer, "</pre></details>")?;
        }
        writeln!(writer, "</section>")?;
    }

    for error in &report.errors {
        writeln!(
            writer,
            "<section class=\"error\"><h3>ERROR {}  {}</h3></section>",
            escape(error.probe),
            escape(&error.message)
        )?;
    }

    writeln!(
        writer,
        "<p class=\"summary\">{} finding(s), {} observation(s), {} collection error(s)</p>",
        report.findings.len(),
        report.observations.len(),
        report.errors.len()
    )?;
    writeln!(writer, "</article>")?;
    Ok(())
}

fn escape(value: &str) -> String {
    let safe = terminal_safe(value);
    let mut escaped = String::with_capacity(safe.len());
    for character in safe.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn unix_millis_utc(millis: u64) -> String {
    let seconds = millis / 1000;
    let (year, month, day, hour, minute, second) = civil_from_unix(seconds);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_unix(seconds: u64) -> (i32, u32, u32, u32, u32, u32) {
    let second = (seconds % 60) as u32;
    let minutes = seconds / 60;
    let minute = (minutes % 60) as u32;
    let hours = minutes / 60;
    let hour = (hours % 24) as u32;
    let days = hours / 24;
    let (year, month, day) = civil_from_days(days);
    (year, month, day, hour, minute, second)
}

/// Howard Hinnant's civil-from-days, for non-negative Unix day counts.
fn civil_from_days(days: u64) -> (i32, u32, u32) {
    let z = days.saturating_add(719_468);
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Evidence, Finding, HostCapabilities, HostInfo, Observation, ProbePackInfo, ScanError,
    };

    fn report() -> ScanReport {
        ScanReport {
            schema_version: 1,
            scanner_version: "0.1.0-test",
            scan_id: "scan-fixture".into(),
            started_at: 1_723_000_000_000,
            completed_at: 1_723_000_000_042,
            probe_pack: None,
            target: "host.example".into(),
            host: Some(HostInfo {
                hostname: "fixture-host".into(),
                kernel: "Linux 6.8.0".into(),
                os: "Fixture Linux".into(),
                capabilities: HostCapabilities {
                    root: Some(false),
                    sudo_present: true,
                    tools: vec!["find".into()],
                },
            }),
            duration_ms: 42,
            probes_run: 2,
            findings: vec![Finding {
                id: "SHUV-AUTH-001",
                title: "Non-root account has UID 0",
                severity: Severity::Critical,
                category: "identity",
                description: "An account other than root has UID 0.",
                remediation: "Assign a unique non-zero UID.",
                evidence_truncated: false,
                evidence_omitted_bytes: 0,
                evidence_limit_bytes: 8 * 1024,
                evidence: Evidence {
                    command: "awk fixture",
                    output: "maintenance:/root:/bin/sh\n".into(),
                },
            }],
            observations: vec![Observation {
                id: "SHUV-EVID-PROC-001",
                title: "Sampled PID and parent PID pairs",
                category: "process",
                partial: Some("root access unavailable".into()),
                truncated: false,
                collection_limits: Vec::new(),
                evidence_budget_exceeded: false,
                evidence: Evidence {
                    command: "proc fixture",
                    output: "pid=42\tppid=1".into(),
                },
            }],
            errors: vec![ScanError {
                probe: "SHUV-AUTH-002",
                message: "requires root".into(),
            }],
        }
    }

    #[test]
    fn sarif_maps_findings_and_collection_errors_separately() {
        let mut output = Vec::new();
        sarif(&[report()], &mut output).unwrap();
        let log: Value = serde_json::from_slice(&output).unwrap();
        let run = &log["runs"][0];

        assert_eq!(log["version"], "2.1.0");
        assert_eq!(
            run["tool"]["driver"]["rules"].as_array().unwrap().len(),
            BUILTINS
                .iter()
                .filter(|probe| probe.evaluator().is_some())
                .count()
        );
        assert_eq!(run["results"].as_array().unwrap().len(), 1);
        assert_eq!(run["results"][0]["ruleId"], "SHUV-AUTH-001");
        assert_eq!(run["results"][0]["level"], "error");
        assert_eq!(
            run["results"][0]["locations"][0]["logicalLocations"][0]["name"],
            "host.example"
        );
        assert_eq!(run["invocations"][0]["executionSuccessful"], false);
        assert_eq!(
            run["invocations"][0]["toolExecutionNotifications"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(run["properties"]["scanId"], "scan-fixture");
    }

    #[test]
    fn human_output_discloses_truncated_observations() {
        let mut report = report();
        report.observations[0].truncated = true;
        let mut output = Vec::new();

        human(&[report], &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("truncated: true"));
    }

    #[test]
    fn human_output_discloses_truncated_findings_before_the_evidence_preview() {
        let mut report = report();
        report.findings[0].evidence.output = "one\ntwo\nthree\nfour\n[truncated]".into();
        report.findings[0].evidence_truncated = true;
        report.findings[0].evidence_omitted_bytes = 23;
        let mut output = Vec::new();

        human(&[report], &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        let notice = output.find("evidence truncated:").unwrap();
        let preview = output.find("evidence: one").unwrap();
        assert!(notice < preview);
        assert!(output.contains("evidence truncated: 23 byte(s) omitted (8192-byte limit)"));
        assert!(!output.contains("[truncated]"));
    }

    #[test]
    fn human_output_discloses_finding_evidence_lines_beyond_the_preview() {
        let mut preview_report = report();
        preview_report.findings[0].evidence.output = "one\ntwo\nthree\nfour\nfive\nsix".into();
        let mut output = Vec::new();

        human(&[preview_report], &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("evidence: four\n"));
        assert!(!output.contains("evidence: five"));
        assert!(!output.contains("evidence: six"));
        assert!(output.contains("(2 more evidence line(s); use --format json"));

        let mut exact = report();
        exact.findings[0].evidence.output = "one\ntwo\nthree\nfour".into();
        let mut output = Vec::new();
        human(&[exact], &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("evidence: four\n"));
        assert!(!output.contains("more line(s)"));
    }

    #[test]
    fn machine_outputs_expose_finding_evidence_completeness() {
        let mut report = report();
        report.findings[0].evidence_truncated = true;
        report.findings[0].evidence_omitted_bytes = 23;

        let mut json_output = Vec::new();
        json(&[report.clone()], &mut json_output).unwrap();
        let json_value: Value = serde_json::from_slice(&json_output).unwrap();
        let native_finding = &json_value[0]["findings"][0];
        assert_eq!(native_finding["evidence_truncated"], true);
        assert_eq!(native_finding["evidence_omitted_bytes"], 23);
        assert_eq!(native_finding["evidence_limit_bytes"], 8 * 1024);

        let mut jsonl_output = Vec::new();
        jsonl(&[report.clone()], &mut jsonl_output).unwrap();
        let jsonl_value: Value = serde_json::from_slice(&jsonl_output).unwrap();
        assert_eq!(jsonl_value["findings"][0]["evidence_truncated"], true);

        let mut sarif_output = Vec::new();
        sarif(&[report.clone()], &mut sarif_output).unwrap();
        let sarif_value: Value = serde_json::from_slice(&sarif_output).unwrap();
        let sarif_properties = &sarif_value["runs"][0]["results"][0]["properties"];
        assert_eq!(sarif_properties["evidenceTruncated"], true);
        assert_eq!(sarif_properties["evidenceOmittedBytes"], 23);
        assert_eq!(sarif_properties["evidenceLimitBytes"], 8 * 1024);

        let mut ocsf_output = Vec::new();
        ocsf(&[report], &mut ocsf_output).unwrap();
        let ocsf_value: Value = serde_json::from_slice(&ocsf_output).unwrap();
        let ocsf_extension = &ocsf_value[1]["unmapped"]["shuvscan"];
        assert_eq!(ocsf_extension["evidence_truncated"], true);
        assert_eq!(ocsf_extension["evidence_omitted_bytes"], 23);
        assert_eq!(ocsf_extension["evidence_limit_bytes"], 8 * 1024);
    }

    #[test]
    fn human_output_does_not_flag_complete_finding_evidence() {
        let mut output = Vec::new();

        human(&[report()], &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains("evidence truncated:"));
    }

    #[test]
    fn human_output_never_calls_an_incomplete_scan_a_pass() {
        let mut report = report();
        report.findings.clear();
        let mut output = Vec::new();

        human(&[report], &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("INCOMPLETE"));
        assert!(!output.contains("PASS"));
    }

    #[test]
    fn human_output_escapes_terminal_control_characters() {
        let mut report = report();
        report.findings[0].evidence.output = "finding=\u{1b}[31mred".into();
        report.observations[0].evidence.output = "cmd=\u{1b}[2Jclear".into();
        report.host.as_mut().unwrap().capabilities.tools = vec!["awk\u{1b}[2J".into()];
        let mut output = Vec::new();

        human(&[report], &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains('\u{1b}'));
        assert!(output.contains(r"finding=\u{1b}[31mred"));
        assert!(output.contains(r"cmd=\u{1b}[2Jclear"));
        assert!(output.contains(r"tools=awk\u{1b}[2J"));
    }

    #[test]
    fn human_output_escapes_unicode_bidi_controls() {
        const BIDI_CONTROLS: [char; 12] = [
            '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
            '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ];

        for character in BIDI_CONTROLS {
            let mut report = report();
            report.target = format!("host{character}.example");
            report.findings[0].evidence.output = format!("finding={character}spoofed");
            report.errors[0].message = format!("error={character}spoofed");
            let mut output = Vec::new();

            human(&[report], &mut output).unwrap();

            let output = String::from_utf8(output).unwrap();
            let escaped = format!(r"\u{{{:x}}}", u32::from(character));
            assert!(!output.contains(character));
            assert!(output.contains(&escaped), "missing escape {escaped}");
        }

        assert_eq!(terminal_safe("café 東京 👩‍💻"), "café 東京 👩‍💻");
    }

    #[test]
    fn json_variants_preserve_unicode_bidi_controls() {
        let mut report = report();
        report.target = "host\u{202e}\u{2066}.example".into();
        let expected = report.target.clone();

        let mut json_output = Vec::new();
        json(&[report.clone()], &mut json_output).unwrap();
        let json_value: Value = serde_json::from_slice(&json_output).unwrap();
        assert_eq!(json_value[0]["target"], expected);

        let mut jsonl_output = Vec::new();
        jsonl(&[report], &mut jsonl_output).unwrap();
        let jsonl_value: Value = serde_json::from_slice(&jsonl_output).unwrap();
        assert_eq!(jsonl_value["target"], expected);
    }

    #[test]
    fn sarif_notes_that_observations_are_omitted_without_failing_execution() {
        let mut report = report();
        report.errors.clear();
        let mut output = Vec::new();

        sarif(&[report], &mut output).unwrap();

        let log: Value = serde_json::from_slice(&output).unwrap();
        let invocation = &log["runs"][0]["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], true);
        assert_eq!(invocation["toolExecutionNotifications"][0]["level"], "note");
        assert_eq!(
            invocation["toolExecutionNotifications"][0]["properties"]["observationsOmitted"],
            1
        );
    }

    #[test]
    fn sarif_records_pack_provenance_for_a_clean_run() {
        let mut report = report();
        report.findings.clear();
        report.probe_pack = Some(ProbePackInfo {
            schema_version: 1,
            id: "org.example.baseline".into(),
            version: "1.2.0".into(),
            signer: "example-security".into(),
        });
        let mut output = Vec::new();
        sarif_with_probes(&[report], &BUILTINS[..1], &mut output).unwrap();
        let log: Value = serde_json::from_slice(&output).unwrap();

        assert!(log["runs"][0]["results"].as_array().unwrap().is_empty());
        assert_eq!(
            log["runs"][0]["properties"]["probePack"]["id"],
            "org.example.baseline"
        );
    }

    #[test]
    fn ocsf_emits_scan_and_detection_events() {
        let mut output = Vec::new();
        ocsf(&[report()], &mut output).unwrap();
        let events: Value = serde_json::from_slice(&output).unwrap();
        let events = events.as_array().unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["class_uid"], 6007);
        assert_eq!(events[0]["type_uid"], 600702);
        assert_eq!(events[0]["num_detections"], 1);
        assert_eq!(events[0]["status"], "Failure");
        let observations: Value = serde_json::from_str(
            events[0]["unmapped"]["shuvscan"]["observations_json"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(observations[0]["id"], "SHUV-EVID-PROC-001");
        assert_eq!(
            events[0]["unmapped"]["shuvscan"]["collection_errors"][0]["probe"],
            "SHUV-AUTH-002"
        );
        assert_eq!(events[1]["class_uid"], 2004);
        assert_eq!(events[1]["type_uid"], 200401);
        assert_eq!(events[1]["severity_id"], 5);
        assert_eq!(events[1]["device"]["hostname"], "fixture-host");
        assert_eq!(events[1]["device"]["type_id"], 0);
        assert_eq!(events[1]["time"], 1_723_000_000_042_u64);
        assert_eq!(events[1]["metadata"]["version"], OCSF_VERSION);
    }

    #[test]
    fn ocsf_marks_target_collection_failure_as_scan_error() {
        let mut report = report();
        report.host = None;
        report.findings.clear();
        report.errors = vec![ScanError {
            probe: "collector",
            message: "transport timed out".into(),
        }];
        let mut output = Vec::new();
        ocsf(&[report], &mut output).unwrap();
        let events: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(events[0]["activity_id"], 6);
        assert_eq!(events[0]["activity_name"], "Error");
        assert_eq!(events[0]["type_uid"], 600706);
        assert_eq!(events[0]["total"], 0);
        assert_eq!(events.as_array().unwrap().len(), 1);
    }

    #[test]
    fn ocsf_uses_the_recorded_collection_time_and_scan_identity() {
        let report = report();
        let expected_time = report.completed_at;
        let expected_uid = format!(
            "{}:{}:{}",
            report.scan_id, report.target, report.findings[0].id
        );
        let mut output = Vec::new();

        ocsf(&[report], &mut output).unwrap();
        let events: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(events[0]["time"], expected_time);
        assert_eq!(events[1]["finding_info"]["uid"], expected_uid);
    }

    #[test]
    fn native_json_variants_validate_against_the_published_schema() {
        let schema: Value =
            serde_json::from_str(include_str!("../docs/report.schema.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();

        let finding = report();
        let mut clean = report();
        clean.findings.clear();
        clean.observations.clear();
        clean.errors.clear();
        let mut failed = clean.clone();
        failed.host = None;
        failed.errors.push(ScanError {
            probe: "collector",
            message: "fixture transport failure".into(),
        });
        let mut signed = clean.clone();
        signed.probe_pack = Some(ProbePackInfo {
            schema_version: 1,
            id: "org.example.baseline".into(),
            version: "1.0.0".into(),
            signer: "example-security".into(),
        });

        for report in [finding, clean, failed, signed] {
            let value = serde_json::to_value([report]).unwrap();
            assert!(
                validator.is_valid(&value),
                "schema rejected native report: {:?}",
                validator.iter_errors(&value).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn published_schema_accepts_additive_optional_fields() {
        let schema: Value =
            serde_json::from_str(include_str!("../docs/report.schema.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let mut value = serde_json::to_value([report()]).unwrap();
        value[0]["future_field"] = json!("added without a schema_version bump");
        value[0]["findings"][0]["future_field"] = json!(true);
        value[0]["host"]["capabilities"]["future_field"] = json!(1);

        assert!(
            validator.is_valid(&value),
            "schema must tolerate additive fields: {:?}",
            validator.iter_errors(&value).collect::<Vec<_>>()
        );
        value[0]["schema_version"] = json!(2);
        assert!(!validator.is_valid(&value));
    }

    #[test]
    fn html_escapes_host_derived_strings_and_sets_csp() {
        let mut report = report();
        report.target = "<script>alert(1)</script>".into();
        report.findings[0].title = "UID 0 & \"root\"";
        report.findings[0].evidence.output = "<img src=x onerror=alert(1)>".into();
        let mut output = Vec::new();

        html(&[report], &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains(
            "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; script-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'"
        ));
        assert!(output.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(output.contains("UID 0 &amp; &quot;root&quot;"));
        assert!(output.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(!output.contains("<script>"));
        assert!(!output.contains("http://"));
        assert!(!output.contains("https://"));
        assert!(!output.contains("<script src"));
    }

    #[test]
    fn html_never_labels_incomplete_collection_as_pass() {
        let mut output = Vec::new();
        html(&[report()], &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("INCOMPLETE"));
        assert!(!output.contains("class=\"verdict pass\""));
        assert!(!output.contains("PASS  No findings"));
        assert!(output.contains("id=\"target-0\""));
        assert!(output.contains("class=\"sev critical\""));
    }

    #[test]
    fn html_converts_unix_millis_to_utc() {
        assert_eq!(unix_millis_utc(1_723_000_000_000), "2024-08-07T03:06:40Z");

        let mut output = Vec::new();
        html(&[report()], &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("2024-08-07T03:06:40Z"));
    }

    #[test]
    fn html_includes_evidence_commands() {
        let mut output = Vec::new();
        html(&[report()], &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("command: awk fixture"));
        assert!(output.contains("command: proc fixture"));
    }

    #[test]
    fn html_pass_is_reserved_for_complete_scans_without_findings() {
        let mut clean = report();
        clean.findings.clear();
        clean.observations.clear();
        clean.errors.clear();
        let mut output = Vec::new();

        html(&[clean], &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("class=\"verdict pass\""));
        assert!(output.contains("PASS  No findings detected by the active probe pack."));
        assert!(!output.contains("INCOMPLETE"));
    }
}
