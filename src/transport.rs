use std::{
    io::Write,
    process::{Command, Stdio},
};

use thiserror::Error;

use crate::model::Target;

const OUTPUT_LIMIT: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("could not launch collector: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("collector exited with status {status}: {stderr}")]
    Failed { status: i32, stderr: String },
}

pub fn execute(target: &Target, script: &str) -> Result<String, TransportError> {
    let mut command = match target {
        Target::Local => {
            let mut command = Command::new("sh");
            command.arg("-s");
            command
        }
        Target::Ssh(destination) => {
            let mut command = Command::new("ssh");
            command.args([
                "-oBatchMode=yes",
                "-oConnectionAttempts=1",
                "-oConnectTimeout=10",
                "-oStrictHostKeyChecking=yes",
                "--",
                destination,
                "sh",
                "-s",
            ]);
            command
        }
    };

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(script.as_bytes())?;
    let output = child.wait_with_output()?;

    if !output.status.success() {
        return Err(TransportError::Failed {
            status: output.status.code().unwrap_or(-1),
            stderr: truncate(String::from_utf8_lossy(&output.stderr).into_owned()),
        });
    }
    Ok(truncate(
        String::from_utf8_lossy(&output.stdout).trim().to_owned(),
    ))
}

fn truncate(mut value: String) -> String {
    if value.len() > OUTPUT_LIMIT {
        value.truncate(OUTPUT_LIMIT);
        value.push_str("\n[output truncated]");
    }
    value
}
