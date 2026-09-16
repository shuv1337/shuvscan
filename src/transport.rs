use std::{
    io::{ErrorKind, Read, Write},
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use thiserror::Error;
use wait_timeout::ChildExt;

use crate::model::Target;

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

#[derive(Debug)]
pub struct TransportOutput {
    pub stdout: String,
    pub stdout_truncated: bool,
}

#[derive(Debug)]
struct CappedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Run one collection script on the target through a single `sh -s` session
/// (local, or remote over one OpenSSH connection). Read-only by contract: the
/// script is a static scanner asset and target data is never interpolated.
pub fn execute(
    target: &Target,
    script: &str,
    timeout: Duration,
    sudo: bool,
) -> Result<TransportOutput, TransportError> {
    let mut command = build_command(target, sudo);
    command.process_group(0);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Drain both pipes on threads so a chatty collector can never fill a pipe
    // buffer and deadlock against our stdin write or the timeout wait.
    let stdout_pipe = child.stdout.take().expect("piped stdout");
    let stderr_pipe = child.stderr.take().expect("piped stderr");
    let stdout_reader = thread::spawn(move || drain_capped(stdout_pipe, STDOUT_LIMIT));
    let stderr_reader = thread::spawn(move || drain_capped(stderr_pipe, STDERR_LIMIT));

    let mut stdin = child.stdin.take().expect("piped stdin");
    let script = script.as_bytes().to_vec();
    let stdin_writer = thread::spawn(move || stdin.write_all(&script));

    let status = match child.wait_timeout(timeout) {
        Ok(Some(status)) => status,
        Ok(None) => {
            reap_group(&mut child);
            let _ = stdin_writer.join();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(TransportError::Timeout(timeout));
        }
        Err(error) => {
            reap_group(&mut child);
            let _ = stdin_writer.join();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(error.into());
        }
    };
    // A collector must not leave background descendants holding our pipes.
    terminate_group(child.id());
    let write_result = stdin_writer
        .join()
        .unwrap_or_else(|_| Err(std::io::Error::other("collector stdin writer panicked")));
    let stdout = stdout_reader
        .join()
        .map_err(|_| std::io::Error::other("collector stdout reader panicked"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| std::io::Error::other("collector stderr reader panicked"))?;
    let stdout = stdout?;
    let stderr = stderr?;

    if !status.success() {
        let stderr_truncated = stderr.truncated;
        let mut stderr_text = String::from_utf8_lossy(&stderr.bytes).trim().to_owned();
        if stderr_text.is_empty() && stderr_truncated {
            stderr_text.push_str("[stderr truncated]");
        } else if stderr_truncated {
            stderr_text.push_str("\n[stderr truncated]");
        }
        return Err(TransportError::Failed {
            status: status.code().unwrap_or(-1),
            stderr: stderr_text,
        });
    }
    if let Err(error) = write_result {
        if error.kind() != ErrorKind::BrokenPipe {
            return Err(error.into());
        }
    }
    Ok(TransportOutput {
        stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
        stdout_truncated: stdout.truncated,
    })
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

fn drain_capped(mut pipe: impl Read, limit: usize) -> std::io::Result<CappedOutput> {
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
    let mut chunk = [0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        match pipe.read(&mut chunk)? {
            0 => break,
            read => {
                let remaining = limit.saturating_sub(bytes.len());
                let retained = remaining.min(read);
                bytes.extend_from_slice(&chunk[..retained]);
                truncated |= retained < read;
            }
        }
    }
    Ok(CappedOutput { bytes, truncated })
}

fn terminate_group(pid: u32) {
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: `pid` is the positive PID returned by `Child::id`; negating
        // it addresses only the dedicated process group configured at spawn.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

fn reap_group(child: &mut Child) {
    terminate_group(child.id());
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsStr, fs};

    #[test]
    fn local_execution_captures_stdout() {
        let output = execute(
            &Target::Local,
            "printf 'hello'",
            Duration::from_secs(10),
            false,
        )
        .unwrap();
        assert_eq!(output.stdout, "hello");
        assert!(!output.stdout_truncated);
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
    fn stdout_is_bounded_while_the_pipe_is_drained() {
        let output = execute(
            &Target::Local,
            "awk 'BEGIN { for (i = 0; i < 600000; i++) printf \"x\" }'",
            Duration::from_secs(10),
            false,
        )
        .unwrap();

        assert_eq!(output.stdout.len(), STDOUT_LIMIT);
        assert!(output.stdout_truncated);
    }

    #[test]
    fn timeout_includes_a_blocked_script_writer() {
        let mut script = String::from("exec sleep 30\n");
        script.push_str(&"# filler\n".repeat(200_000));

        let error =
            execute(&Target::Local, &script, Duration::from_millis(200), false).unwrap_err();

        assert!(matches!(error, TransportError::Timeout(_)));
    }

    #[test]
    fn timeout_kills_collector_descendants() {
        let pid_file = std::env::temp_dir().join(format!(
            "shuvscan-descendant-{}-{}",
            std::process::id(),
            crate::protocol::nonce().unwrap()
        ));
        let script = format!(
            "sleep 30 & child=$!; printf '%s' \"$child\" > '{}'; wait",
            pid_file.display()
        );

        let error =
            execute(&Target::Local, &script, Duration::from_millis(300), false).unwrap_err();
        assert!(matches!(error, TransportError::Timeout(_)));
        let pid = fs::read_to_string(&pid_file)
            .unwrap()
            .parse::<i32>()
            .unwrap();
        let _ = fs::remove_file(pid_file);

        // A freshly killed orphan can briefly remain as a zombie until PID 1
        // reaps it; either absence or zombie state proves it is no longer live.
        let state = fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| stat.rsplit_once(") ").map(|(_, tail)| tail.to_owned()))
            .and_then(|tail| tail.chars().next());
        assert!(
            state.is_none() || state == Some('Z'),
            "descendant state: {state:?}"
        );
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
