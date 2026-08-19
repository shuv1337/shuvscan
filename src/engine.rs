use std::{
    thread,
    time::{Duration, Instant},
};

use crate::{
    model::{ScanError, ScanReport, Target, truncate_evidence},
    probes::BUILTINS,
    protocol, transport,
};

const EVIDENCE_LIMIT: usize = 8 * 1024;

/// Scan one target: a single transport session collects every probe, then each
/// section is evaluated independently. A probe with no parseable section, a
/// non-zero status, or an unavailability sentinel becomes a collection error —
/// never a silent pass.
pub fn scan(target: Target, timeout: Duration) -> ScanReport {
    let started = Instant::now();
    let nonce = protocol::nonce();
    let script = protocol::build_script(BUILTINS, &nonce);
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let mut host = None;

    match transport::execute(&target, &script, timeout) {
        Ok(raw) => {
            let transcript = protocol::parse(&raw, &nonce);
            host = transcript.host;
            for probe in BUILTINS {
                let Some(section) = transcript.sections.get(probe.id) else {
                    errors.push(ScanError {
                        probe: probe.id,
                        message: "collector returned no evidence section (session truncated or interrupted)".into(),
                    });
                    continue;
                };
                if let Some(message) = unavailable_reason(&section.output) {
                    errors.push(ScanError {
                        probe: probe.id,
                        message,
                    });
                } else if section.status != 0 {
                    errors.push(ScanError {
                        probe: probe.id,
                        message: format!("probe exited with status {}", section.status),
                    });
                } else if (probe.evaluate)(&section.output) {
                    findings.push(
                        probe.finding(truncate_evidence(section.output.clone(), EVIDENCE_LIMIT)),
                    );
                }
            }
        }
        Err(error) => errors.push(ScanError {
            probe: "collector",
            message: error.to_string(),
        }),
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.id.cmp(right.id))
    });

    ScanReport {
        schema_version: 1,
        scanner_version: env!("CARGO_PKG_VERSION"),
        target: target.label().to_owned(),
        host,
        duration_ms: started.elapsed().as_millis(),
        probes_run: BUILTINS.len(),
        findings,
        errors,
    }
}

fn unavailable_reason(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim().strip_prefix(protocol::UNAVAILABLE).map(|rest| {
            let reason = rest.trim();
            if reason.is_empty() {
                "evidence unavailable on this target".to_owned()
            } else {
                format!("evidence unavailable: {reason}")
            }
        })
    })
}

pub fn scan_all(targets: Vec<Target>, timeout: Duration) -> Vec<ScanReport> {
    let mut reports = thread::scope(|scope| {
        targets
            .into_iter()
            .map(|target| scope.spawn(move || scan(target, timeout)))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().expect("scan worker panicked"))
            .collect::<Vec<_>>()
    });
    reports.sort_by(|left, right| left.target.cmp(&right.target));
    reports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_scan_collects_every_probe_in_one_session() {
        let report = scan(Target::Local, Duration::from_secs(60));
        assert_eq!(report.probes_run, BUILTINS.len());
        assert!(report.host.is_some(), "host metadata should parse locally");
        assert!(
            report.errors.iter().all(|error| error.probe != "collector"),
            "local collection should not fail wholesale: {:?}",
            report.errors
        );
        assert!(
            report
                .errors
                .iter()
                .all(|error| !error.message.contains("no evidence section")),
            "every probe should produce a section: {:?}",
            report.errors
        );
    }
}
