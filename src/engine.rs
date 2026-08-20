use std::{
    num::NonZeroUsize,
    panic::{self, AssertUnwindSafe},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

use crate::{
    model::{ProbePackInfo, ScanError, ScanReport, Target, truncate_evidence},
    probes::{BUILTINS, Probe},
    protocol, transport,
};

const EVIDENCE_LIMIT: usize = 8 * 1024;
pub const DEFAULT_CONCURRENCY: usize = 16;

/// Scan one target: a single transport session collects every probe, then each
/// section is evaluated independently. A probe with no parseable section, a
/// non-zero status, or an unavailability sentinel becomes a collection error —
/// never a silent pass.
pub fn scan(target: Target, timeout: Duration, sudo: bool) -> ScanReport {
    scan_with_probes(target, timeout, sudo, BUILTINS, None)
}

pub fn scan_with_probes(
    target: Target,
    timeout: Duration,
    sudo: bool,
    probes: &[Probe],
    probe_pack: Option<&ProbePackInfo>,
) -> ScanReport {
    let started = Instant::now();
    let nonce = protocol::nonce();
    let script = protocol::build_script(probes, &nonce);
    let mut findings = Vec::new();
    let mut observations = Vec::new();
    let mut errors = Vec::new();
    let mut host = None;

    match transport::execute(&target, &script, timeout, sudo) {
        Ok(raw) => {
            let transcript = protocol::parse(&raw, &nonce);
            host = transcript.host;
            match transcript.sections.get(protocol::CAPABILITIES_ID) {
                None => errors.push(ScanError {
                    probe: "capabilities",
                    message: "collector returned no capability inventory".into(),
                }),
                Some(section) if section.status != 0 => errors.push(ScanError {
                    probe: "capabilities",
                    message: format!("capability inventory exited with status {}", section.status),
                }),
                Some(_) => {}
            }
            for probe in probes {
                let Some(section) = transcript.sections.get(probe.id) else {
                    errors.push(ScanError {
                        probe: probe.id,
                        message: "collector returned no evidence section (session truncated or interrupted)".into(),
                    });
                    continue;
                };
                if let Some(message) = &section.unavailable {
                    errors.push(ScanError {
                        probe: probe.id,
                        message: format!("evidence unavailable: {message}"),
                    });
                    continue;
                }
                if let Some(message) = &section.partial {
                    errors.push(ScanError {
                        probe: probe.id,
                        message: format!("partial evidence: {message}"),
                    });
                }
                if section.status != 0 {
                    errors.push(ScanError {
                        probe: probe.id,
                        message: format!("probe exited with status {}", section.status),
                    });
                } else {
                    let output = truncate_evidence(section.output.clone(), EVIDENCE_LIMIT);
                    if let Some(finding) = probe.finding(&section.output, output.clone()) {
                        findings.push(finding);
                    }
                    let evidence_budget_exceeded = section.output.len() > EVIDENCE_LIMIT;
                    if let Some(observation) = probe.observation(
                        output,
                        section.partial.clone(),
                        section.collection_limits.clone(),
                        evidence_budget_exceeded,
                    ) {
                        observations.push(observation);
                    }
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
        probe_pack: probe_pack.cloned(),
        target: target.label().to_owned(),
        host,
        duration_ms: started.elapsed().as_millis(),
        probes_run: probes.len(),
        findings,
        observations,
        errors,
    }
}

pub fn scan_all(
    targets: Vec<Target>,
    timeout: Duration,
    sudo: bool,
    concurrency: NonZeroUsize,
) -> Vec<ScanReport> {
    scan_all_with_probes(targets, timeout, sudo, concurrency, BUILTINS, None)
}

pub fn scan_all_with_probes(
    targets: Vec<Target>,
    timeout: Duration,
    sudo: bool,
    concurrency: NonZeroUsize,
    probes: &[Probe],
    probe_pack: Option<&ProbePackInfo>,
) -> Vec<ScanReport> {
    scan_all_with(targets, concurrency, probes.len(), probe_pack, |target| {
        scan_with_probes(target, timeout, sudo, probes, probe_pack)
    })
}

fn scan_all_with<F>(
    targets: Vec<Target>,
    concurrency: NonZeroUsize,
    probes_run: usize,
    probe_pack: Option<&ProbePackInfo>,
    scan_target: F,
) -> Vec<ScanReport>
where
    F: Fn(Target) -> ScanReport + Sync,
{
    let next = AtomicUsize::new(0);
    let worker_count = concurrency.get().min(targets.len());
    let mut reports = thread::scope(|scope| {
        let handles = (0..worker_count)
            .map(|_| {
                scope.spawn(|| {
                    let mut reports = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(target) = targets.get(index).cloned() else {
                            break;
                        };
                        let label = target.label().to_owned();
                        let started = Instant::now();
                        reports.push((
                            index,
                            panic::catch_unwind(AssertUnwindSafe(|| scan_target(target)))
                                .unwrap_or_else(|_| {
                                    panicked_report(
                                        label,
                                        started.elapsed(),
                                        probes_run,
                                        probe_pack.cloned(),
                                    )
                                }),
                        ));
                    }
                    reports
                })
            })
            .collect::<Vec<_>>();

        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("scheduler worker panicked"))
            .collect::<Vec<_>>()
    });
    reports.sort_by(|(left_index, left), (right_index, right)| {
        left.target
            .cmp(&right.target)
            .then(left_index.cmp(right_index))
    });
    reports.into_iter().map(|(_, report)| report).collect()
}

fn panicked_report(
    target: String,
    duration: Duration,
    probes_run: usize,
    probe_pack: Option<ProbePackInfo>,
) -> ScanReport {
    ScanReport {
        schema_version: 1,
        scanner_version: env!("CARGO_PKG_VERSION"),
        probe_pack,
        target,
        host: None,
        duration_ms: duration.as_millis(),
        probes_run,
        findings: Vec::new(),
        observations: Vec::new(),
        errors: vec![ScanError {
            probe: "collector",
            message: "scan worker panicked".into(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::Severity,
        probes::{Privilege, ProbeKind},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn report(target: String) -> ScanReport {
        ScanReport {
            schema_version: 1,
            scanner_version: env!("CARGO_PKG_VERSION"),
            probe_pack: None,
            target,
            host: None,
            duration_ms: 0,
            probes_run: BUILTINS.len(),
            findings: Vec::new(),
            observations: Vec::new(),
            errors: Vec::new(),
        }
    }

    #[test]
    fn local_scan_collects_every_probe_in_one_session() {
        let report = scan(Target::Local, Duration::from_secs(60), false);
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

    #[test]
    fn detections_evaluate_full_output_before_evidence_is_truncated() {
        fn ends_with_signal(output: &str) -> bool {
            output.ends_with("signal")
        }

        let probes = [Probe {
            id: "SHUV-TEST-001",
            title: "Large output test",
            category: "test",
            description: "Test-only probe.",
            required_tools: &["awk"],
            privilege: Privilege::Unprivileged,
            script: "awk 'BEGIN { for (i = 0; i < 9000; i++) printf \"x\"; print \"\"; print \"signal\" }'",
            kind: ProbeKind::Detection {
                severity: Severity::Low,
                remediation: "None.",
                evaluate: ends_with_signal,
            },
        }];

        let report = scan_with_probes(Target::Local, Duration::from_secs(10), false, &probes, None);

        assert!(report.errors.is_empty());
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].evidence.output.ends_with("[truncated]"));
    }

    #[test]
    fn fleet_scheduler_bounds_concurrency_and_sorts_reports() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let targets = (0..12)
            .rev()
            .map(|index| Target::Ssh(format!("host-{index:02}")))
            .collect();

        let reports = scan_all_with(
            targets,
            NonZeroUsize::new(3).unwrap(),
            BUILTINS.len(),
            None,
            {
                let active = Arc::clone(&active);
                let maximum = Arc::clone(&maximum);
                move |target| {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(now, Ordering::SeqCst);
                    let delay = target
                        .label()
                        .rsplit_once('-')
                        .unwrap()
                        .1
                        .parse::<u64>()
                        .unwrap();
                    thread::sleep(Duration::from_millis(delay));
                    active.fetch_sub(1, Ordering::SeqCst);
                    report(target.label().to_owned())
                }
            },
        );

        assert_eq!(reports.len(), 12);
        assert_eq!(maximum.load(Ordering::SeqCst), 3);
        assert!(
            reports
                .windows(2)
                .all(|pair| pair[0].target < pair[1].target)
        );
    }

    #[test]
    fn failed_and_panicked_scans_do_not_stop_queue() {
        let targets = ["good-b", "failure", "panic", "good-a"]
            .into_iter()
            .map(|target| Target::Ssh(target.into()))
            .collect();

        let reports = scan_all_with(
            targets,
            NonZeroUsize::new(1).unwrap(),
            BUILTINS.len(),
            None,
            |target| {
                assert_ne!(target.label(), "panic", "simulated scan panic");
                let mut report = report(target.label().to_owned());
                if target.label() == "failure" {
                    report.errors.push(ScanError {
                        probe: "collector",
                        message: "simulated transport failure".into(),
                    });
                }
                report
            },
        );

        assert_eq!(reports.len(), 4);
        assert_eq!(reports[0].target, "failure");
        assert_eq!(reports[0].errors[0].message, "simulated transport failure");
        assert_eq!(reports[1].target, "good-a");
        assert_eq!(reports[2].target, "good-b");
        assert_eq!(reports[3].target, "panic");
        assert_eq!(reports[3].errors[0].probe, "collector");
    }

    #[test]
    fn fleet_scheduler_handles_empty_and_single_target_inputs() {
        let concurrency = NonZeroUsize::new(4).unwrap();
        assert!(
            scan_all_with(
                Vec::new(),
                concurrency,
                BUILTINS.len(),
                None,
                |_| unreachable!()
            )
            .is_empty()
        );

        let reports = scan_all_with(
            vec![Target::Local],
            concurrency,
            BUILTINS.len(),
            None,
            |target| report(target.label().to_owned()),
        );
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].target, "local");
    }
}
