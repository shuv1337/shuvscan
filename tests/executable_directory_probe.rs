use std::{
    env, fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use shuvscan::probes::{BUILTINS, Probe};

fn probe() -> &'static Probe {
    BUILTINS
        .iter()
        .find(|probe| probe.id == "SHUV-EXEC-001")
        .unwrap()
}

fn stub_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "shuvscan-executable-directory-test-{}-{suffix}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn run_probe(directory: &Path, roots: &[&Path]) -> std::process::Output {
    const ROOTS: &str = "/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin";
    let roots = roots
        .iter()
        .map(|root| root.display().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let script = probe().script.replacen(ROOTS, &roots, 1);
    assert_ne!(script, probe().script);
    let path = format!(
        "{}:{}",
        directory.display(),
        env::var("PATH").unwrap_or_default()
    );
    Command::new("sh")
        .args(["-c", &script])
        .env("PATH", path)
        .env("SHUVSCAN_PARTIAL", "PARTIAL:")
        .output()
        .unwrap()
}

#[test]
fn checks_effective_targets_once() {
    let directory = stub_dir();
    let effective_writable = directory.join("effective-writable");
    let effective_safe = directory.join("effective-safe");
    let direct_writable = directory.join("direct-writable");
    for path in [&effective_writable, &effective_safe, &direct_writable] {
        fs::create_dir(path).unwrap();
    }
    for path in [&effective_writable, &direct_writable] {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o777);
        fs::set_permissions(path, permissions).unwrap();
    }

    let writable_link = directory.join("writable-link");
    let writable_alias = directory.join("writable-alias");
    let safe_link = directory.join("safe-link");
    symlink(&effective_writable, &writable_link).unwrap();
    symlink(&effective_writable, &writable_alias).unwrap();
    symlink(&effective_safe, &safe_link).unwrap();

    let output = run_probe(
        &directory,
        &[
            &writable_link,
            &writable_alias,
            &effective_writable,
            &safe_link,
            &effective_safe,
            &direct_writable,
        ],
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    fs::remove_dir_all(directory).unwrap();

    assert!(output.status.success());
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        [
            writable_link.to_str().unwrap(),
            direct_writable.to_str().unwrap()
        ]
    );
}

#[test]
fn reports_unresolved_links_as_partial() {
    let directory = stub_dir();
    let dangling = directory.join("dangling");
    let looped = directory.join("looped");
    symlink("missing", &dangling).unwrap();
    symlink("looped", &looped).unwrap();

    let output = run_probe(&directory, &[&dangling, &looped]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    fs::remove_dir_all(directory).unwrap();

    assert!(output.status.success());
    assert!(stdout.contains(dangling.to_str().unwrap()), "{stdout}");
    assert!(stdout.contains(looped.to_str().unwrap()), "{stdout}");
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with("PARTIAL:"))
            .count(),
        2
    );
}

#[test]
fn distinguishes_newline_ending_targets() {
    let directory = stub_dir();
    let safe = directory.join("effective\n");
    let writable = directory.join("effective");
    fs::create_dir(&safe).unwrap();
    fs::create_dir(&writable).unwrap();
    let mut permissions = fs::metadata(&writable).unwrap().permissions();
    permissions.set_mode(0o777);
    fs::set_permissions(&writable, permissions).unwrap();

    let safe_link = directory.join("safe-link");
    let writable_link = directory.join("writable-link");
    symlink(&safe, &safe_link).unwrap();
    symlink(&writable, &writable_link).unwrap();

    let output = run_probe(&directory, &[&safe_link, &writable_link]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    fs::remove_dir_all(directory).unwrap();

    assert!(output.status.success());
    assert_eq!(stdout.trim(), writable_link.to_str().unwrap());
}
