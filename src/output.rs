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
            if !finding.evidence.output.is_empty() {
                for line in finding.evidence.output.lines().take(4) {
                    writeln!(writer, "         evidence: {}", terminal_safe(line))?;
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

fn terminal_safe(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
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

pub fn ocsf(reports: &[ScanReport], writer: impl Write) -> io::Result<()> {
    ocsf_with_time(reports, None, writer)
}

#[cfg(test)]
fn ocsf_at(reports: &[ScanReport], time: u64, mut writer: impl Write) -> io::Result<()> {
    ocsf_with_time(reports, Some(time), &mut writer)
}

fn ocsf_with_time(
    reports: &[ScanReport],
    fixed_time: Option<u64>,
    mut writer: impl Write,
) -> io::Result<()> {
    let mut events = Vec::new();
    for report in reports {
        let time = fixed_time.unwrap_or(report.completed_at);
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
                        "rule_id": finding.id
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
    fn ocsf_emits_scan_and_detection_events_with_fixed_time() {
        let mut output = Vec::new();
        ocsf_at(&[report()], 1_723_000_000_000, &mut output).unwrap();
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
        assert_eq!(events[1]["time"], 1_723_000_000_000_u64);
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
        ocsf_at(&[report], 1_723_000_000_000, &mut output).unwrap();
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
}
