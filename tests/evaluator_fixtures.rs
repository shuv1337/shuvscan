use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use serde::Deserialize;
use shuvscan::probes::{BUILTINS, ProbeKind};

const EXPECTED_DISTROS: &[&str] = &["alpine-3.20", "debian-12", "rhel-9", "ubuntu-24.04"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    distro: String,
    cases: Vec<Case>,
    #[serde(default)]
    omitted: Vec<Omission>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    probe: String,
    non_finding: String,
    finding: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Omission {
    probe: String,
    reason: String,
}

#[test]
fn distro_fixtures_match_builtin_evaluators() {
    let probes = BUILTINS
        .iter()
        .filter(|probe| matches!(probe.kind, ProbeKind::Detection { .. }))
        .map(|probe| (probe.id, probe))
        .collect::<BTreeMap<_, _>>();
    let mut covered = BTreeSet::new();
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/evaluators");
    let mut fixture_paths = fs::read_dir(fixture_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    fixture_paths.sort();
    let mut distros = BTreeSet::new();

    for path in fixture_paths {
        let source = fs::read_to_string(&path).unwrap();
        let fixture: Fixture = serde_json::from_str(&source)
            .unwrap_or_else(|error| panic!("invalid {} fixture: {error}", path.display()));
        let expected_distro = path.file_stem().unwrap().to_str().unwrap();
        assert_eq!(fixture.distro, expected_distro);
        assert!(distros.insert(fixture.distro.clone()), "duplicate distro");
        assert!(!fixture.cases.is_empty(), "{expected_distro} has no cases");

        let mut accounted_for = BTreeSet::new();
        for case in fixture.cases {
            assert!(
                accounted_for.insert(case.probe.clone()),
                "duplicate {} case in {expected_distro}",
                case.probe
            );
            let probe = probes
                .get(case.probe.as_str())
                .unwrap_or_else(|| panic!("unknown probe {} in {expected_distro}", case.probe));
            let evaluate = probe.evaluator().expect("fixture probe is a detection");
            assert!(
                !evaluate(&case.non_finding),
                "{} false positive in {expected_distro}",
                case.probe
            );
            assert!(
                evaluate(&case.finding),
                "{} missed finding in {expected_distro}",
                case.probe
            );
            covered.insert(case.probe);
        }

        for omission in fixture.omitted {
            assert!(
                probes.contains_key(omission.probe.as_str()),
                "unknown omitted probe {} in {expected_distro}",
                omission.probe
            );
            assert!(
                accounted_for.insert(omission.probe.clone()),
                "duplicate or tested-and-omitted probe {} in {expected_distro}",
                omission.probe
            );
            assert!(
                !omission.reason.trim().is_empty(),
                "{} omission in {expected_distro} needs a reason",
                omission.probe
            );
        }

        assert_eq!(
            accounted_for,
            probes.keys().map(|id| (*id).to_owned()).collect(),
            "{expected_distro} must test or explicitly omit every built-in probe"
        );
    }

    assert_eq!(
        distros,
        EXPECTED_DISTROS
            .iter()
            .map(|distro| (*distro).to_owned())
            .collect(),
        "fixture corpus must contain the supported distro families"
    );
    assert_eq!(
        covered,
        probes.keys().map(|id| (*id).to_owned()).collect(),
        "every built-in probe needs fixture coverage"
    );
}
