use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_describes_agentless_targets() {
    Command::cargo_bin("shuvscan")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("OpenSSH destination"));
}

#[test]
fn list_probes_prints_stable_ids_without_scanning() {
    Command::cargo_bin("shuvscan")
        .unwrap()
        .arg("--list-probes")
        .assert()
        .success()
        .stdout(predicate::str::contains("SHUV-PERSIST-001"))
        .stdout(predicate::str::contains("SHUV-PROC-001"));
}

#[test]
fn json_output_has_versioned_schema() {
    Command::cargo_bin("shuvscan")
        .unwrap()
        .args(["--format", "json", "--fail-on", "critical"])
        .assert()
        .code(predicate::eq(0).or(predicate::eq(1)))
        .stdout(predicate::str::contains("\"schema_version\": 1"));
}
