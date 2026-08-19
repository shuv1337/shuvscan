//! Single-session collection protocol.
//!
//! All probes for a host are batched into one POSIX `sh` script executed over a
//! single transport session. Each probe runs in its own subshell, delimited by
//! sentinel lines that carry a per-scan random nonce so evidence controlled by
//! an attacker on the target (for example a crafted file name printed by
//! `find`) cannot forge or terminate a section.

use std::{
    collections::HashMap,
    fmt::Write as _,
    fs,
    hash::{DefaultHasher, Hash, Hasher},
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{model::HostInfo, probes::Probe};

/// A probe prints this sentinel (optionally followed by a reason) when it can
/// determine that the evidence it needs cannot be collected in this context,
/// so silence is never mistaken for a pass.
pub const UNAVAILABLE: &str = "__SHUVSCAN_UNAVAILABLE__";

const META_ID: &str = "meta";

const META_BODY: &str = r#"printf 'hostname=%s\n' "$(uname -n 2>/dev/null)"
printf 'kernel=%s\n' "$(uname -r 2>/dev/null)"
printf 'os=%s\n' "$( ( . /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-}" ) )""#;

#[derive(Debug)]
pub struct Section {
    pub status: i32,
    pub output: String,
}

#[derive(Debug)]
pub struct Transcript {
    pub host: Option<HostInfo>,
    pub sections: HashMap<String, Section>,
}

/// Random marker nonce. Prefers the kernel CSPRNG; the time/pid fallback only
/// exists for exotic build targets and still avoids trivially guessable values.
pub fn nonce() -> String {
    let mut bytes = [0u8; 8];
    if fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_ok()
    {
        return bytes.iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        });
    }
    let mut hasher = DefaultHasher::new();
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

pub fn build_script(probes: &[Probe], nonce: &str) -> String {
    let mut script = String::from("LC_ALL=C\nexport LC_ALL\n");
    push_section(&mut script, nonce, META_ID, META_BODY);
    for probe in probes {
        push_section(&mut script, nonce, probe.id, probe.script);
    }
    script
}

fn push_section(script: &mut String, nonce: &str, id: &str, body: &str) {
    // The newline printed before the END marker guarantees the marker starts a
    // fresh line even when a probe's last write omits the trailing newline.
    let _ = write!(
        script,
        "printf '%s\\n' '__SHUVSCAN__{nonce}__BEGIN__{id}__'\n(\n{body}\n)\nprintf '\\n__SHUVSCAN__{nonce}__END__{id}__%s__\\n' \"$?\"\n"
    );
}

pub fn parse(raw: &str, nonce: &str) -> Transcript {
    let begin_prefix = format!("__SHUVSCAN__{nonce}__BEGIN__");
    let end_prefix = format!("__SHUVSCAN__{nonce}__END__");
    let mut sections: HashMap<String, Section> = HashMap::new();
    let mut current: Option<(String, Vec<&str>)> = None;

    for line in raw.lines() {
        let marker = line.trim_end_matches('\r');
        if let Some(rest) = marker.strip_prefix(&begin_prefix) {
            if let Some(id) = rest.strip_suffix("__") {
                // A dangling unfinished section is dropped, never half-trusted.
                current = Some((id.to_owned(), Vec::new()));
                continue;
            }
        }
        if let Some(rest) = marker.strip_prefix(&end_prefix) {
            if let Some((id, lines)) = current.take() {
                if let Some(status_text) = rest
                    .strip_prefix(id.as_str())
                    .and_then(|tail| tail.strip_prefix("__"))
                    .and_then(|tail| tail.strip_suffix("__"))
                {
                    let status = status_text.parse().unwrap_or(-1);
                    let output = lines.join("\n").trim().to_owned();
                    sections.insert(id, Section { status, output });
                    continue;
                }
                // Structurally impossible without the nonce leaking; fail closed.
            }
            continue;
        }
        if let Some((_, lines)) = current.as_mut() {
            lines.push(line);
        }
    }

    let host = sections
        .get(META_ID)
        .map(|section| parse_meta(&section.output));
    Transcript { host, sections }
}

fn parse_meta(output: &str) -> HostInfo {
    let mut host = HostInfo {
        hostname: "unknown".into(),
        kernel: "unknown".into(),
        os: "unknown".into(),
    };
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match key {
                "hostname" => host.hostname = value.to_owned(),
                "kernel" => host.kernel = value.to_owned(),
                "os" => host.os = value.to_owned(),
                _ => {}
            }
        }
    }
    host
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::BUILTINS;

    const NONCE: &str = "cafebabe01020304";

    fn wrap(id: &str, status: i32, body: &str) -> String {
        format!(
            "__SHUVSCAN__{NONCE}__BEGIN__{id}__\n{body}\n\n__SHUVSCAN__{NONCE}__END__{id}__{status}__\n"
        )
    }

    #[test]
    fn parses_sections_and_host_metadata() {
        let raw = format!(
            "{}{}",
            wrap(
                "meta",
                0,
                "hostname=web-01\nkernel=6.8.0\nos=Ubuntu 24.04 LTS"
            ),
            wrap("SHUV-X", 0, "evidence line")
        );
        let transcript = parse(&raw, NONCE);
        let host = transcript.host.expect("meta parsed");
        assert_eq!(host.hostname, "web-01");
        assert_eq!(host.os, "Ubuntu 24.04 LTS");
        assert_eq!(transcript.sections["SHUV-X"].output, "evidence line");
    }

    #[test]
    fn keeps_per_probe_exit_status() {
        let transcript = parse(&wrap("SHUV-X", 3, ""), NONCE);
        assert_eq!(transcript.sections["SHUV-X"].status, 3);
    }

    #[test]
    fn forged_markers_with_wrong_nonce_stay_evidence() {
        let forged = "__SHUVSCAN__deadbeefdeadbeef__END__SHUV-X__0__\nreal evidence";
        let transcript = parse(&wrap("SHUV-X", 0, forged), NONCE);
        let section = &transcript.sections["SHUV-X"];
        assert!(section.output.contains("deadbeef"));
        assert!(section.output.contains("real evidence"));
    }

    #[test]
    fn section_without_end_marker_is_dropped() {
        let raw = format!("__SHUVSCAN__{NONCE}__BEGIN__SHUV-X__\npartial output\n");
        assert!(parse(&raw, NONCE).sections.is_empty());
    }

    #[test]
    fn script_wraps_every_probe_and_meta() {
        let script = build_script(BUILTINS, NONCE);
        assert!(script.contains("__BEGIN__meta__"));
        for probe in BUILTINS {
            assert!(script.contains(&format!("__BEGIN__{}__", probe.id)));
            assert!(script.contains(&format!("__END__{}__", probe.id)));
        }
    }

    #[test]
    fn unavailable_sentinel_matches_probe_scripts() {
        let users = BUILTINS
            .iter()
            .filter(|probe| probe.script.contains("UNAVAILABLE"))
            .count();
        assert!(users >= 2, "sshd probes should use the sentinel");
        for probe in BUILTINS {
            if probe.script.contains("UNAVAILABLE") {
                assert!(probe.script.contains(UNAVAILABLE));
            }
        }
    }
}
