use std::{
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use assert_cmd::Command;
use ed25519_dalek::{Signer, SigningKey};
use predicates::prelude::*;

static TEMP_PACK_ID: AtomicUsize = AtomicUsize::new(0);

struct SignedPack {
    directory: PathBuf,
    manifest: PathBuf,
    key: PathBuf,
}

struct StubSsh {
    directory: PathBuf,
}

impl StubSsh {
    fn failing() -> Self {
        let id = TEMP_PACK_ID.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("shuvscan-cli-ssh-{}-{id}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("ssh");
        fs::write(
            &path,
            "#!/bin/sh\nprintf 'fixture connection failure\\n' >&2\nexit 7\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
        Self { directory }
    }

    fn path(&self) -> String {
        format!(
            "{}:{}",
            self.directory.display(),
            std::env::var("PATH").unwrap_or_default()
        )
    }
}

impl Drop for StubSsh {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

impl SignedPack {
    fn create(source: &[u8]) -> Self {
        let id = TEMP_PACK_ID.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("shuvscan-cli-pack-{}-{id}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let manifest = directory.join("pack.json");
        let key = directory.join("trusted-key.hex");
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let signature = signing_key.sign(source);
        fs::write(&manifest, source).unwrap();
        fs::write(&key, encode_hex(signing_key.verifying_key().as_bytes())).unwrap();
        let mut signature_path: OsString = manifest.as_os_str().to_owned();
        signature_path.push(".sig");
        fs::write(
            PathBuf::from(signature_path),
            encode_hex(&signature.to_bytes()),
        )
        .unwrap();
        Self {
            directory,
            manifest,
            key,
        }
    }
}

impl Drop for SignedPack {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn help_describes_agentless_targets() {
    Command::cargo_bin("shuvscan")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("OpenSSH destination"))
        .stdout(predicate::str::contains("--concurrency"))
        .stdout(predicate::str::contains("--sudo"))
        .stdout(predicate::str::contains("sudo -n"));
}

#[test]
fn invalid_concurrency_is_rejected() {
    Command::cargo_bin("shuvscan")
        .unwrap()
        .args(["--concurrency", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value '0'"));

    Command::cargo_bin("shuvscan")
        .unwrap()
        .args(["--concurrency", "many"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value 'many'"));
}

#[test]
fn zero_timeout_is_rejected() {
    Command::cargo_bin("shuvscan")
        .unwrap()
        .args(["--timeout", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value '0'"));
}

#[test]
fn total_collection_failure_is_incomplete_and_exits_two() {
    let ssh = StubSsh::failing();
    Command::cargo_bin("shuvscan")
        .unwrap()
        .args(["--target", "fixture-host"])
        .env("PATH", ssh.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("INCOMPLETE"))
        .stdout(predicate::str::contains("PASS").not())
        .stdout(predicate::str::contains("fixture connection failure"));
}

#[test]
fn total_collection_failure_keeps_json_machine_clean() {
    let ssh = StubSsh::failing();
    let assert = Command::cargo_bin("shuvscan")
        .unwrap()
        .args(["--target", "fixture-host", "--format", "json"])
        .env("PATH", ssh.path())
        .assert()
        .code(2)
        .stderr(predicate::str::is_empty());
    let reports: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert!(reports[0]["findings"].as_array().unwrap().is_empty());
    assert_eq!(reports[0]["errors"][0]["probe"], "collector");
}

#[test]
fn write_failure_uses_stderr_and_exit_two() {
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("shuvscan"))
        .args(["--format", "json", "--fail-on", "critical"])
        .stdout(full)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not write report"));
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

#[test]
fn json_output_includes_capability_inventory() {
    Command::cargo_bin("shuvscan")
        .unwrap()
        .args(["--format", "json", "--fail-on", "critical"])
        .assert()
        .code(predicate::eq(0).or(predicate::eq(1)))
        .stdout(predicate::str::contains("\"capabilities\""))
        .stdout(predicate::str::contains("\"tools\""));
}

#[test]
fn sarif_output_is_parseable_and_versioned() {
    let assert = Command::cargo_bin("shuvscan")
        .unwrap()
        .args(["--format", "sarif", "--fail-on", "critical"])
        .assert()
        .code(predicate::eq(0).or(predicate::eq(1)));
    let output: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();

    assert_eq!(output["version"], "2.1.0");
    assert_eq!(output["runs"][0]["tool"]["driver"]["name"], "shuvscan");
}

#[test]
fn ocsf_output_is_parseable_and_versioned() {
    let assert = Command::cargo_bin("shuvscan")
        .unwrap()
        .args(["--format", "ocsf", "--fail-on", "critical"])
        .assert()
        .code(predicate::eq(0).or(predicate::eq(1)));
    let output: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let events = output.as_array().unwrap();

    assert!(!events.is_empty());
    assert_eq!(events[0]["class_uid"], 6007);
    assert_eq!(events[0]["metadata"]["version"], "1.8.0");
}

#[test]
fn unordered_jsonl_streams_reports_with_one_invocation_id() {
    let assert = Command::cargo_bin("shuvscan")
        .unwrap()
        .args([
            "--target",
            "local",
            "--target",
            "local",
            "--format",
            "jsonl",
            "--unordered",
            "--fail-on",
            "critical",
        ])
        .assert()
        .code(predicate::eq(0).or(predicate::eq(1)));
    let reports = assert
        .get_output()
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0]["scan_id"], reports[1]["scan_id"]);
}

#[test]
fn signed_probe_pack_limits_scan_and_records_provenance() {
    let pack = SignedPack::create(
        br#"{"schema_version":1,"id":"org.example.test","version":"1.0.0","signer":"test-security","probes":["SHUV-KERN-001"]}"#,
    );
    let assert = Command::cargo_bin("shuvscan")
        .unwrap()
        .args(["--format", "json", "--fail-on", "critical"])
        .arg("--probe-pack")
        .arg(&pack.manifest)
        .arg("--probe-pack-key")
        .arg(&pack.key)
        .assert()
        .success();
    let reports: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();

    assert_eq!(reports[0]["probes_run"], 1);
    assert_eq!(reports[0]["probe_pack"]["schema_version"], 1);
    assert_eq!(reports[0]["probe_pack"]["id"], "org.example.test");
    assert_eq!(reports[0]["probe_pack"]["version"], "1.0.0");
    assert_eq!(reports[0]["probe_pack"]["signer"], "test-security");
}

#[test]
fn tampered_probe_pack_is_rejected_before_scanning() {
    let pack = SignedPack::create(
        br#"{"schema_version":1,"id":"org.example.test","version":"1.0.0","signer":"test-security","probes":["SHUV-KERN-001"]}"#,
    );
    fs::write(&pack.manifest, b"{}").unwrap();

    Command::cargo_bin("shuvscan")
        .unwrap()
        .arg("--list-probes")
        .arg("--probe-pack")
        .arg(&pack.manifest)
        .arg("--probe-pack-key")
        .arg(&pack.key)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("signature verification failed"));
}
