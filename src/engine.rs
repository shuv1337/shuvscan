use std::{
    num::NonZeroUsize,
    panic::{self, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    model::{
        Finding, Observation, ProbePackInfo, ScanError, ScanReport, Target, truncate_evidence,
    },
    probes::{BUILTINS, Probe},
    protocol, transport,
};

const EVIDENCE_LIMIT: usize = 8 * 1024;
pub const DEFAULT_CONCURRENCY: usize = 16;

#[derive(Clone, Copy, Debug, Default)]
pub struct ScanSummary {
    pub highest_severity: Option<crate::model::Severity>,
    pub collector_failed: bool,
    pub collection_incomplete: bool,
    pub targets_requested: usize,
    pub targets_completed: usize,
}

impl ScanSummary {
    pub fn for_targets(targets_requested: usize) -> Self {
        Self {
            targets_requested,
            ..Self::default()
        }
    }

    pub fn include(&mut self, report: &ScanReport) {
        self.targets_completed += 1;
        self.highest_severity = self.highest_severity.max(report.highest_severity());
        self.collector_failed |= report.errors.iter().any(|error| error.probe == "collector");
        self.collection_incomplete |= !report.errors.is_empty();
    }

    pub fn coverage_complete(&self) -> bool {
        self.targets_completed == self.targets_requested
    }
}

/// Scan one target: a single transport session collects every probe, then each
/// section is evaluated independently. A probe with no parseable section, a
/// non-zero status, or an unavailability sentinel becomes a collection error —
/// never a silent pass.
pub fn scan(target: Target, timeout: Duration, sudo: bool) -> ScanReport {
    scan_with_context(target, timeout, sudo, BUILTINS, None, &new_scan_id())
}

pub fn scan_with_probes(
    target: Target,
    timeout: Duration,
    sudo: bool,
    probes: &[Probe],
    probe_pack: Option<&ProbePackInfo>,
) -> ScanReport {
    scan_with_context(target, timeout, sudo, probes, probe_pack, &new_scan_id())
}

fn scan_with_context(
    target: Target,
    timeout: Duration,
    sudo: bool,
    probes: &[Probe],
    probe_pack: Option<&ProbePackInfo>,
    scan_id: &str,
) -> ScanReport {
    let started_at = unix_millis();
    let started = Instant::now();
    let mut findings = Vec::new();
    let mut observations = Vec::new();
    let mut errors = Vec::new();
    let mut host = None;

    let nonce = protocol::nonce();
    match nonce.and_then(|nonce| {
        let script = protocol::build_script(probes, &nonce);
        transport::execute(&target, &script, timeout, sudo)
            .map(|output| (nonce, output))
            .map_err(|error| std::io::Error::other(error.to_string()))
    }) {
        Ok((nonce, raw)) => {
            let transcript = protocol::parse(&raw.stdout, &nonce);
            include_os_release_error(&transcript, &mut errors);
            host = transcript.host;
            if raw.stdout_truncated {
                errors.push(ScanError {
                    probe: "collector",
                    message: format!(
                        "collector stdout exceeded the {}-byte transport limit; report is incomplete",
                        transport::STDOUT_LIMIT
                    ),
                });
            }
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
                    let (finding, observation) = evaluate_probe_output(
                        probe,
                        &section.output,
                        section.partial.clone(),
                        section.collection_limits.clone(),
                    );
                    if let Some(finding) = finding {
                        findings.push(finding);
                    }
                    if let Some(observation) = observation {
                        observations.push(observation);
                    }
                }
            }
        }
        Err(error) => errors.push(ScanError {
            probe: "collector",
            message: format!("collector setup or execution failed: {error}"),
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
        scan_id: scan_id.to_owned(),
        started_at,
        completed_at: unix_millis(),
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

fn evaluate_probe_output(
    probe: &Probe,
    output: &str,
    partial: Option<String>,
    collection_limits: Vec<String>,
) -> (Option<Finding>, Option<Observation>) {
    let retained_evidence = truncate_evidence(output.to_owned(), EVIDENCE_LIMIT);
    (
        probe.finding(output, &retained_evidence),
        probe.observation(&retained_evidence, partial, collection_limits),
    )
}

fn include_os_release_error(transcript: &protocol::Transcript, errors: &mut Vec<ScanError>) {
    match transcript.sections.get(protocol::OS_RELEASE_ID) {
        None => errors.push(ScanError {
            probe: protocol::OS_RELEASE_ID,
            message: "collector returned no os-release metadata section".into(),
        }),
        Some(section) if section.unavailable.is_some() => errors.push(ScanError {
            probe: protocol::OS_RELEASE_ID,
            message: format!(
                "metadata unavailable: {}",
                section.unavailable.as_deref().unwrap_or_default()
            ),
        }),
        Some(section) if section.status != 0 => errors.push(ScanError {
            probe: protocol::OS_RELEASE_ID,
            message: format!("metadata collection exited with status {}", section.status),
        }),
        Some(_) => {}
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
    let scan_id = new_scan_id();
    scan_all_with(
        targets,
        concurrency,
        probes.len(),
        probe_pack,
        &scan_id,
        |target| scan_with_context(target, timeout, sudo, probes, probe_pack, &scan_id),
    )
}

fn scan_all_with<F>(
    targets: Vec<Target>,
    concurrency: NonZeroUsize,
    probes_run: usize,
    probe_pack: Option<&ProbePackInfo>,
    scan_id: &str,
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
                                        scan_id.to_owned(),
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
    scan_id: String,
) -> ScanReport {
    ScanReport {
        schema_version: 1,
        scanner_version: env!("CARGO_PKG_VERSION"),
        scan_id,
        started_at: unix_millis()
            .saturating_sub(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
        completed_at: unix_millis(),
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

pub fn scan_all_unordered_with_probes<E, F>(
    targets: Vec<Target>,
    timeout: Duration,
    sudo: bool,
    concurrency: NonZeroUsize,
    probes: &[Probe],
    probe_pack: Option<&ProbePackInfo>,
    on_report: F,
) -> Result<ScanSummary, (E, ScanSummary)>
where
    F: FnMut(&ScanReport) -> Result<(), E>,
{
    let scan_id = new_scan_id();
    scan_all_unordered_with(
        targets,
        concurrency,
        probes.len(),
        probe_pack,
        &scan_id,
        |target| scan_with_context(target, timeout, sudo, probes, probe_pack, &scan_id),
        on_report,
    )
}

/// Stream reports in completion order. The first `on_report` error stops the
/// dispatch of further targets; in-flight targets still finish and count toward
/// the returned summary.
fn scan_all_unordered_with<E, F, S>(
    targets: Vec<Target>,
    concurrency: NonZeroUsize,
    probes_run: usize,
    probe_pack: Option<&ProbePackInfo>,
    scan_id: &str,
    scan_target: S,
    mut on_report: F,
) -> Result<ScanSummary, (E, ScanSummary)>
where
    S: Fn(Target) -> ScanReport + Sync,
    F: FnMut(&ScanReport) -> Result<(), E>,
{
    let next = AtomicUsize::new(0);
    let stopped = AtomicBool::new(false);
    let worker_count = concurrency.get().min(targets.len());
    let (sender, receiver) = mpsc::sync_channel(worker_count.max(1));
    let mut summary = ScanSummary::for_targets(targets.len());
    let mut first_error = None;

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let sender = sender.clone();
            let next = &next;
            let stopped = &stopped;
            let targets = &targets;
            let scan_target = &scan_target;
            scope.spawn(move || {
                loop {
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(target) = targets.get(index).cloned() else {
                        break;
                    };
                    let label = target.label().to_owned();
                    let started = Instant::now();
                    let report = panic::catch_unwind(AssertUnwindSafe(|| scan_target(target)))
                        .unwrap_or_else(|_| {
                            panicked_report(
                                label,
                                started.elapsed(),
                                probes_run,
                                probe_pack.cloned(),
                                scan_id.to_owned(),
                            )
                        });
                    if sender.send(report).is_err() {
                        break;
                    }
                }
            });
        }
        drop(sender);
        for report in receiver {
            summary.include(&report);
            if first_error.is_none() {
                if let Err(error) = on_report(&report) {
                    stopped.store(true, Ordering::Release);
                    first_error = Some(error);
                }
            }
        }
    });

    first_error.map_or(Ok(summary), |error| Err((error, summary)))
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn new_scan_id() -> String {
    static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
    protocol::random_hex(16).unwrap_or_else(|_| {
        format!(
            "{:013x}-{:x}-{:x}",
            unix_millis(),
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::Severity,
        probes::{Privilege, ProbeKind},
    };
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    fn report(target: String) -> ScanReport {
        ScanReport {
            schema_version: 1,
            scanner_version: env!("CARGO_PKG_VERSION"),
            scan_id: "test-scan".into(),
            started_at: 1_723_000_000_000,
            completed_at: 1_723_000_000_042,
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
    fn scan_ids_are_random_128_bit_hex_values() {
        let first = new_scan_id();
        let second = new_scan_id();

        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
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
    fn os_release_collection_failures_are_visible() {
        let mut errors = Vec::new();
        let missing = protocol::Transcript {
            host: None,
            sections: std::collections::HashMap::new(),
        };
        include_os_release_error(&missing, &mut errors);
        assert_eq!(errors[0].probe, protocol::OS_RELEASE_ID);
        assert_eq!(
            errors[0].message,
            "collector returned no os-release metadata section"
        );

        errors.clear();
        let unavailable = protocol::Transcript {
            host: None,
            sections: std::collections::HashMap::from([(
                protocol::OS_RELEASE_ID.into(),
                protocol::Section {
                    status: 0,
                    output: String::new(),
                    unavailable: Some("od is required to read os-release safely".into()),
                    partial: None,
                    collection_limits: Vec::new(),
                },
            )]),
        };
        include_os_release_error(&unavailable, &mut errors);
        assert_eq!(
            errors[0].message,
            "metadata unavailable: od is required to read os-release safely"
        );
    }

    #[test]
    fn detections_evaluate_full_output_before_evidence_is_truncated() {
        fn ends_with_signal(output: &str) -> bool {
            output.ends_with("signal")
        }

        let probe = Probe {
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
        };
        let output = format!("{}signal", "x".repeat(EVIDENCE_LIMIT));

        let (finding, observation) = evaluate_probe_output(&probe, &output, None, Vec::new());

        let finding = finding.expect("full output should raise a finding");
        assert!(observation.is_none());
        assert!(finding.evidence.output.ends_with("[truncated]"));
        assert!(finding.evidence_truncated);
        assert_eq!(finding.evidence_omitted_bytes, "signal".len());
        assert_eq!(finding.evidence_limit_bytes, EVIDENCE_LIMIT);
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
            "test-scan",
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
            "test-scan",
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
                "test-scan",
                |_| unreachable!()
            )
            .is_empty()
        );

        let reports = scan_all_with(
            vec![Target::Local],
            concurrency,
            BUILTINS.len(),
            None,
            "test-scan",
            |target| report(target.label().to_owned()),
        );
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].target, "local");
    }

    #[test]
    fn unordered_stream_stops_dispatching_after_a_write_failure() {
        let scanned = Arc::new(AtomicUsize::new(0));
        let targets = (0..40)
            .map(|index| Target::Ssh(format!("host-{index:02}")))
            .collect();
        let worker_count = 2;
        let mut delivered = 0;

        let result = scan_all_unordered_with(
            targets,
            NonZeroUsize::new(worker_count).unwrap(),
            BUILTINS.len(),
            None,
            "test-scan",
            {
                let scanned = Arc::clone(&scanned);
                move |target| {
                    scanned.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(5));
                    report(target.label().to_owned())
                }
            },
            |_| {
                delivered += 1;
                Err("consumer closed the pipe")
            },
        );

        let (error, summary) = result.unwrap_err();
        assert_eq!(error, "consumer closed the pipe");
        assert_eq!(delivered, 1);
        assert!(!summary.collector_failed);
        let scanned = scanned.load(Ordering::SeqCst);
        assert_eq!(summary.targets_requested, 40);
        assert_eq!(summary.targets_completed, scanned);
        assert!(!summary.coverage_complete());
        assert!(
            scanned <= worker_count * 2,
            "workers kept dispatching after the write failure: {scanned} targets scanned"
        );
    }

    #[test]
    fn unordered_stream_can_finish_coverage_after_a_write_failure() {
        let ready = Arc::new(Barrier::new(2));
        let targets = ["host-a", "host-b"]
            .into_iter()
            .map(|target| Target::Ssh(target.into()))
            .collect();

        let result = scan_all_unordered_with(
            targets,
            NonZeroUsize::new(2).unwrap(),
            BUILTINS.len(),
            None,
            "test-scan",
            {
                let ready = Arc::clone(&ready);
                move |target| {
                    ready.wait();
                    report(target.label().to_owned())
                }
            },
            |_| Err("consumer closed the pipe"),
        );

        let (_, summary) = result.unwrap_err();
        assert_eq!(summary.targets_requested, 2);
        assert_eq!(summary.targets_completed, 2);
        assert!(summary.coverage_complete());
    }
}
