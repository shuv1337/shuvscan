use std::{
    ffi::OsString,
    fs,
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
