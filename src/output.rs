use std::{
    io::{self, Write},
    time::{SystemTime, UNIX_EPOCH},
};

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
            report.scanner_version, report.target, report.probes_run, report.duration_ms
        )?;
        if let Some(pack) = &report.probe_pack {
            writeln!(
                writer,
                "pack {}@{}  signer={}  schema={}",
                pack.id, pack.version, pack.signer, pack.schema_version
            )?;
        }
        if let Some(host) = &report.host {
            writeln!(
                writer,
                "host {}  kernel {}  {}",
                host.hostname, host.kernel, host.os
            )?;
            writeln!(
                writer,
                "capabilities root={}  sudo_present={}  tools={}",
                host.capabilities
                    .root
                    .map(|root| root.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                host.capabilities.sudo_present,
                host.capabilities.tools.join(",")
            )?;
        }
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

pub fn json(reports: &[ScanReport], mut writer: impl Write) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut writer, reports).map_err(io::Error::from)?;
    writeln!(writer)
}

pub fn jsonl(reports: &[ScanReport], mut writer: impl Write) -> io::Result<()> {
    for report in reports {
        serde_json::to_writer(&mut writer, report).map_err(io::Error::from)?;
        writeln!(writer)?;
    }
    Ok(())
}

pub fn sarif(reports: &[ScanReport], mut writer: impl Write) -> io::Result<()> {
    sarif_with_probes(reports, BUILTINS, &mut writer)
}

pub fn sarif_with_probes(
    reports: &[ScanReport],
    probes: &[crate::probes::Probe],
    mut writer: impl Write,
) -> io::Result<()> {
    let rules = probes
        .iter()
        .map(|probe| {
            json!({
                "id": probe.id,
                "shortDescription": { "text": probe.title },
                "fullDescription": { "text": probe.description },
                "help": { "text": probe.remediation },
                "defaultConfiguration": { "level": sarif_level(probe.severity) },
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
                        "target": report.target,
                        "category": finding.category,
                        "severity": finding.severity.to_string(),
                        "evidence": finding.evidence.output,
                        "remediation": finding.remediation
                    }
                });
                if let Some(index) = probes.iter().position(|probe| probe.id == finding.id) {
                    result["ruleIndex"] = json!(index);
                }
                result
            })
        })
        .collect::<Vec<_>>();
    let notifications = reports
        .iter()
        .flat_map(|report| {
            report.errors.iter().map(|error| {
                json!({
                    "level": "error",
                    "message": {
                        "text": format!("{}: {}: {}", report.target, error.probe, error.message)
                    },
                    "properties": {
                        "target": report.target,
                        "probe": error.probe
                    }
                })
            })
        })
        .collect::<Vec<_>>();
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
            "executionSuccessful": notifications.is_empty(),
            "toolExecutionNotifications": notifications
        }]
    });
    if let Some(pack) = reports
        .first()
        .and_then(|report| report.probe_pack.as_ref())
    {
        run["properties"] = json!({ "probePack": pack });
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
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| io::Error::other(format!("system clock is before Unix epoch: {error}")))?
        .as_millis();
    let time = u64::try_from(time)
        .map_err(|_| io::Error::other("system time does not fit an OCSF timestamp"))?;
    ocsf_at(reports, time, writer)
}

fn ocsf_at(reports: &[ScanReport], time: u64, mut writer: impl Write) -> io::Result<()> {
    let mut events = Vec::new();
    for report in reports {
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
                    "collection_errors": errors
                }
            }
        });
        if let Some(pack) = &report.probe_pack {
            scan_event["unmapped"]["shuvscan"]["probe_pack"] = json!(pack);
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
                    "uid": format!("{}:{}", report.target, finding.id),
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
    use crate::model::{Evidence, Finding, HostCapabilities, HostInfo, ProbePackInfo, ScanError};

    fn report() -> ScanReport {
        ScanReport {
            schema_version: 1,
            scanner_version: "0.1.0-test",
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
            BUILTINS.len()
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
            1
        );
        assert!(run.get("properties").is_none());
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
}
