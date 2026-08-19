use std::{
    io::{ErrorKind, Read, Write},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use thiserror::Error;
use wait_timeout::ChildExt;

use crate::model::{Target, truncate_evidence};

const STDOUT_LIMIT: usize = 512 * 1024;
const STDERR_LIMIT: usize = 4 * 1024;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("collector I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("collector timed out after {0:?}")]
    Timeout(Duration),
    #[error("collector exited with status {status}: {stderr}")]
    Failed { status: i32, stderr: String },
}

/// Run one collection script on the target through a single `sh -s` session
/// (local, or remote over one OpenSSH connection). Read-only by contract: the
/// script is a static scanner asset and target data is never interpolated.
pub fn execute(
    target: &Target,
    script: &str,
    timeout: Duration,
    sudo: bool,
) -> Result<String, TransportError> {
    let mut child = build_command(target, sudo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Drain both pipes on threads so a chatty collector can never fill a pipe
    // buffer and deadlock against our stdin write or the timeout wait.
    let stdout_pipe = child.stdout.take().expect("piped stdout");
    let stderr_pipe = child.stderr.take().expect("piped stderr");
    let stdout_reader = thread::spawn(move || drain(stdout_pipe));
    let stderr_reader = thread::spawn(move || drain(stderr_pipe));

    let mut stdin = child.stdin.take().expect("piped stdin");
    if let Err(error) = stdin.write_all(script.as_bytes()) {
        // A child that dies before reading stdin (for example ssh refusing to
        // authenticate) yields EPIPE here; fall through so the child's exit
        // status and stderr are reported instead of the useless write error.
        if error.kind() != ErrorKind::BrokenPipe {
            reap(&mut child);
            return Err(error.into());
        }
    }
    drop(stdin);

    let Some(status) = child.wait_timeout(timeout)? else {
        reap(&mut child);
        return Err(TransportError::Timeout(timeout));
    };
    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();

    if !status.success() {
        return Err(TransportError::Failed {
            status: status.code().unwrap_or(-1),
            stderr: truncate_evidence(
                String::from_utf8_lossy(&stderr).trim().to_owned(),
                STDERR_LIMIT,
            ),
        });
    }
    Ok(truncate_evidence(
        String::from_utf8_lossy(&stdout).into_owned(),
        STDOUT_LIMIT,
    ))
}

fn build_command(target: &Target, sudo: bool) -> Command {
    match target {
        Target::Local => {
            let mut command = Command::new(if sudo { "sudo" } else { "sh" });
            if sudo {
                command.args(["-n", "--", "sh", "-s"]);
            } else {
                command.arg("-s");
            }
            command
        }
        Target::Ssh(destination) => {
            let mut command = Command::new("ssh");
            command.args([
                "-oBatchMode=yes",
                "-oConnectionAttempts=1",
                "-oConnectTimeout=10",
                "-oServerAliveInterval=5",
                "-oServerAliveCountMax=3",
                "-oStrictHostKeyChecking=yes",
                "--",
                destination,
            ]);
            if sudo {
                command.args(["sudo", "-n", "--", "sh", "-s"]);
            } else {
                command.args(["sh", "-s"]);
            }
            command
        }
    }
}

fn drain(mut pipe: impl Read) -> Vec<u8> {
    let mut buffer = Vec::new();
    let _ = pipe.read_to_end(&mut buffer);
    buffer
}

fn reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn local_execution_captures_stdout() {
        let output = execute(
            &Target::Local,
            "printf 'hello'",
            Duration::from_secs(10),
            false,
        )
        .unwrap();
        assert_eq!(output, "hello");
    }

    #[test]
    fn failing_collector_reports_status_and_stderr() {
        let error = execute(
            &Target::Local,
            "echo boom >&2; exit 7",
            Duration::from_secs(10),
            false,
        )
        .unwrap_err();
        match error {
            TransportError::Failed { status, stderr } => {
                assert_eq!(status, 7);
                assert_eq!(stderr, "boom");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn hung_collector_times_out() {
        let error =
            execute(&Target::Local, "sleep 5", Duration::from_millis(200), false).unwrap_err();
        assert!(matches!(error, TransportError::Timeout(_)));
    }

    #[test]
    fn sudo_is_non_interactive_and_executes_only_sh_stdin() {
        let local = build_command(&Target::Local, true);
        assert_eq!(local.get_program(), OsStr::new("sudo"));
        assert_eq!(
            local.get_args().collect::<Vec<_>>(),
            ["-n", "--", "sh", "-s"]
                .iter()
                .map(OsStr::new)
                .collect::<Vec<_>>()
        );

        let remote = build_command(&Target::Ssh("host".into()), true);
        let args = remote.get_args().collect::<Vec<_>>();
        assert!(
            args.ends_with(
                ["host", "sudo", "-n", "--", "sh", "-s"]
                    .iter()
                    .map(OsStr::new)
                    .collect::<Vec<_>>()
                    .as_slice()
            )
        );
    }
}
