use std::{
    io::{ErrorKind, Read, Write},
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::{
        Mutex,
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;

use crate::model::Target;

pub const STDOUT_LIMIT: usize = 512 * 1024;
const STDERR_LIMIT: usize = 4 * 1024;

static ACTIVE_GROUPS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static INTERRUPT_CLEANUP: Mutex<Option<fn()>> = Mutex::new(None);

/// Run `cleanup` on the interrupt watcher thread before it re-raises SIGINT or
/// SIGTERM. Used by the TUI to restore the terminal when Drop cannot run.
pub fn set_interrupt_cleanup(cleanup: Option<fn()>) {
    *INTERRUPT_CLEANUP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = cleanup;
}

fn run_interrupt_cleanup() {
    let cleanup = INTERRUPT_CLEANUP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(cleanup) = cleanup {
        cleanup();
    }
}

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
    let mut group = ActiveGroup::register(child.id());
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);

    // Drain both pipes on threads so a chatty collector can never fill a pipe
    // buffer and deadlock against our stdin write or the timeout wait.
    let stdout_pipe = child.stdout.take().expect("piped stdout");
    let stderr_pipe = child.stderr.take().expect("piped stderr");
    let (stdout_sender, stdout_reader) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = stdout_sender.send(drain_capped(stdout_pipe, STDOUT_LIMIT));
    });
    let (stderr_sender, stderr_reader) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = stderr_sender.send(drain_capped(stderr_pipe, STDERR_LIMIT));
    });

    let mut stdin = child.stdin.take().expect("piped stdin");
    let script = script.as_bytes().to_vec();
    let (stdin_sender, stdin_writer) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = stdin_sender.send(stdin.write_all(&script));
    });

    match wait_for_exit_without_reaping(child.id(), deadline) {
        Ok(true) => {
            // Kill the group while the exited leader is still a zombie. Its PID
            // cannot be reused until `wait`, so the group ID still identifies
            // only this collector and any descendants it left behind.
            terminate_group(child.id());
            group.unregister();
        }
        Ok(false) => {
            terminate_group(child.id());
            group.unregister();
            let _ = child.wait();
            return Err(TransportError::Timeout(timeout));
        }
        Err(error) => {
            terminate_group(child.id());
            group.unregister();
            let _ = child.wait();
            return Err(error.into());
        }
    }
    let status = child.wait()?;
    let write_result = receive_before(stdin_writer, deadline, timeout, "stdin writer")?;
    let stdout = receive_before(stdout_reader, deadline, timeout, "stdout reader")?;
    let stderr = receive_before(stderr_reader, deadline, timeout, "stderr reader")?;
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
        match pipe.read(&mut chunk) {
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
            Ok(0) => break,
            Ok(read) => {
                let remaining = limit.saturating_sub(bytes.len());
                let retained = remaining.min(read);
                bytes.extend_from_slice(&chunk[..retained]);
                truncated |= retained < read;
            }
        }
    }
    Ok(CappedOutput { bytes, truncated })
}

fn wait_for_exit_without_reaping(pid: u32, deadline: Instant) -> std::io::Result<bool> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| std::io::Error::other("collector PID does not fit pid_t"))?;
    loop {
        // `WNOWAIT` leaves the exited leader as a zombie, reserving its PID and
        // process-group ID until the caller has killed descendants.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` points to valid writable storage and `pid` is the
        // positive PID returned by `Child::id`.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as _,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            // SAFETY: `waitid` initialized `info`; `si_pid` is valid for a
            // reported child state and zero when no state was available.
            if unsafe { info.si_pid() } == pid {
                return Ok(true);
            }
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }

        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        thread::sleep((deadline - now).min(Duration::from_millis(10)));
    }
}

fn receive_before<T>(
    receiver: Receiver<T>,
    deadline: Instant,
    timeout: Duration,
    worker: &str,
) -> Result<T, TransportError> {
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(result) => Ok(result),
        Err(RecvTimeoutError::Timeout) => Err(TransportError::Timeout(timeout)),
        Err(RecvTimeoutError::Disconnected) => {
            Err(std::io::Error::other(format!("collector {worker} stopped unexpectedly")).into())
        }
    }
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

/// Registration of one collector process group for the lifetime of its
/// session; dropping it kills the group so nothing outlives the transport.
struct ActiveGroup(Option<u32>);

impl ActiveGroup {
    fn register(pid: u32) -> Self {
        active_groups().push(pid);
        Self(Some(pid))
    }

    fn unregister(&mut self) {
        if let Some(pid) = self.0.take() {
            active_groups().retain(|active| *active != pid);
        }
    }
}

impl Drop for ActiveGroup {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            terminate_group(pid);
            active_groups().retain(|active| *active != pid);
        }
    }
}

fn active_groups() -> std::sync::MutexGuard<'static, Vec<u32>> {
    ACTIVE_GROUPS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn terminate_active_groups() {
    let groups = active_groups().clone();
    for pid in groups {
        terminate_group(pid);
    }
}

/// Route SIGINT and SIGTERM through a watcher thread that kills every in-flight
/// collector process group before the signal terminates the scanner. Collectors
/// run in their own groups for timeout containment, so the terminal's job
/// control no longer reaches them on its own. Call before spawning any thread.
pub fn forward_interrupts_to_collectors() {
    // SAFETY: plain libc signal-mask calls on a zero-initialised sigset_t; the
    // set is built and consumed only through the libc API.
    unsafe {
        let mut signals: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut signals);
        libc::sigaddset(&mut signals, libc::SIGINT);
        libc::sigaddset(&mut signals, libc::SIGTERM);
        if libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) != 0 {
            return;
        }
        thread::spawn(move || {
            let mut signal = 0;
            if libc::sigwait(&signals, &mut signal) != 0 {
                return;
            }
            terminate_active_groups();
            run_interrupt_cleanup();
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut());
            libc::raise(signal);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsStr,
        fs,
        io::{Cursor, Error},
        time::Instant,
    };

    struct InterruptedOnce {
        interrupted: bool,
        remaining: Cursor<Vec<u8>>,
    }

    impl Read for InterruptedOnce {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(Error::from(ErrorKind::Interrupted));
            }
            self.remaining.read(buffer)
        }
    }

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
    fn interrupted_pipe_reads_are_retried() {
        let output = drain_capped(
            InterruptedOnce {
                interrupted: false,
                remaining: Cursor::new(b"complete".to_vec()),
            },
            32,
        )
        .unwrap();

        assert_eq!(output.bytes, b"complete");
        assert!(!output.truncated);
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
    fn escaped_pipe_holder_cannot_extend_the_timeout() {
        if Command::new("setsid").arg("--help").output().is_err() {
            return;
        }
        let pid_file = std::env::temp_dir().join(format!(
            "shuvscan-escaped-descendant-{}-{}",
            std::process::id(),
            crate::protocol::nonce().unwrap()
        ));
        let script = format!(
            "setsid sh -c 'printf %s \"$$\" > \"{}\"; sleep 30' &",
            pid_file.display()
        );
        let started = Instant::now();

        let error =
            execute(&Target::Local, &script, Duration::from_millis(300), false).unwrap_err();
        assert!(matches!(error, TransportError::Timeout(_)));
        assert!(started.elapsed() < Duration::from_secs(3));

        if let Ok(pid) = fs::read_to_string(&pid_file).and_then(|pid| {
            pid.parse::<i32>()
                .map_err(|error| std::io::Error::other(error.to_string()))
        }) {
            // SAFETY: best-effort cleanup of the fixture's escaped process
            // group, including the foreground `sleep`.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        let _ = fs::remove_file(pid_file);
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
