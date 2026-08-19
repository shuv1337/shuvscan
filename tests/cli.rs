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
fn json_output_has_versioned_schema() {
    Command::cargo_bin("shuvscan")
        .unwrap()
        .args(["--format", "json", "--fail-on", "critical"])
        .assert()
        .code(predicate::eq(0).or(predicate::eq(1)))
        .stdout(predicate::str::contains("\"schema_version\": 1"));
}
