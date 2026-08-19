use std::{thread, time::Instant};

use crate::{
    model::{ScanError, ScanReport, Target},
    probes::BUILTINS,
    transport,
};

pub fn scan(target: Target) -> ScanReport {
    let started = Instant::now();
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    for probe in BUILTINS {
        match transport::execute(&target, probe.script) {
            Ok(output) if (probe.evaluate)(&output) => findings.push(probe.finding(output)),
            Ok(_) => {}
            Err(error) => errors.push(ScanError {
                probe: probe.id,
                message: error.to_string(),
            }),
        }
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
        duration_ms: started.elapsed().as_millis(),
        probes_run: BUILTINS.len(),
        findings,
        errors,
    }
}

pub fn scan_all(targets: Vec<Target>) -> Vec<ScanReport> {
    let mut reports = thread::scope(|scope| {
        targets
            .into_iter()
            .map(|target| scope.spawn(move || scan(target)))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().expect("scan worker panicked"))
            .collect::<Vec<_>>()
    });
    reports.sort_by(|left, right| left.target.cmp(&right.target));
    reports
}
