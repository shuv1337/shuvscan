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

use crate::{
    model::{HostCapabilities, HostInfo},
    probes::{Privilege, Probe},
};

const META_ID: &str = "meta";
pub(crate) const CAPABILITIES_ID: &str = "capabilities";

const META_BODY: &str = r#"printf 'hostname=%s\n' "$(uname -n 2>/dev/null)"
printf 'kernel=%s\n' "$(uname -r 2>/dev/null)"
printf 'os=%s\n' "$( ( . /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-}" ) )"
printf 'root=%s\n' "$SHUVSCAN_IS_ROOT"
if command -v sudo >/dev/null 2>&1; then printf 'sudo_present=1\n'; else printf 'sudo_present=0\n'; fi"#;

#[derive(Debug)]
pub struct Section {
    pub status: i32,
    pub output: String,
    pub unavailable: Option<String>,
    pub partial: Option<String>,
    pub collection_limits: Vec<String>,
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
    let mut script = String::from(
        "LC_ALL=C\nexport LC_ALL\nSHUVSCAN_IS_ROOT=unknown\nif shuvscan_euid=$(id -u 2>/dev/null); then\n  if [ \"$shuvscan_euid\" = 0 ]; then SHUVSCAN_IS_ROOT=1; else SHUVSCAN_IS_ROOT=0; fi\nfi\nexport SHUVSCAN_IS_ROOT\n",
    );
    let _ = writeln!(
        script,
        "SHUVSCAN_UNAVAILABLE='__SHUVSCAN__{nonce}__UNAVAILABLE__'\nSHUVSCAN_PARTIAL='__SHUVSCAN__{nonce}__PARTIAL__'\nSHUVSCAN_TRUNCATED='__SHUVSCAN__{nonce}__TRUNCATED__'"
    );
    push_section(&mut script, nonce, META_ID, META_BODY);
    let mut tools = probes
        .iter()
        .flat_map(|probe| probe.required_tools.iter().copied())
        .collect::<Vec<_>>();
    tools.sort_unstable();
    tools.dedup();
    let mut capability_body = String::new();
    for tool in tools {
        let _ = writeln!(
            capability_body,
            "if command -v {tool} >/dev/null 2>&1; then printf 'tool=%s\\n' '{tool}'; fi"
        );
    }
    push_section(&mut script, nonce, CAPABILITIES_ID, &capability_body);
    for probe in probes {
        let body = probe_body(probe);
        push_section(&mut script, nonce, probe.id, &body);
    }
    script
}

fn probe_body(probe: &Probe) -> String {
    let mut body = String::from("shuvscan_missing=\n");
    for tool in probe.required_tools {
        let _ = writeln!(
            body,
            "command -v {tool} >/dev/null 2>&1 || shuvscan_missing=\"${{shuvscan_missing}} {tool}\""
        );
    }
    body.push_str("if [ -n \"$shuvscan_missing\" ]; then\n  printf '%s missing required tool(s):%s\\n' \"$SHUVSCAN_UNAVAILABLE\" \"$shuvscan_missing\"\n");
    if probe.privilege == Privilege::RootRequired {
        body.push_str("elif [ \"$SHUVSCAN_IS_ROOT\" != 1 ]; then\n  printf '%s root access required; rerun with --sudo\\n' \"$SHUVSCAN_UNAVAILABLE\"\n");
    }
    body.push_str("else\n");
    if probe.privilege == Privilege::RootRecommended {
        body.push_str("  [ \"$SHUVSCAN_IS_ROOT\" = 1 ] || printf '%s root access unavailable; evidence may omit other users\\n' \"$SHUVSCAN_PARTIAL\"\n");
    }
    body.push_str(probe.script);
    body.push_str("\nfi");
    body
}

fn push_section(script: &mut String, nonce: &str, id: &str, body: &str) {
    // The newline printed before the END marker guarantees the marker starts a
    // fresh line even when a probe's last write omits the trailing newline.
    let _ = write!(
        script,
        "printf '%s\\n' '__SHUVSCAN__{nonce}__BEGIN__{id}__'\n(\n{body}\n) </dev/null\nprintf '\\n__SHUVSCAN__{nonce}__END__{id}__%s__\\n' \"$?\"\n"
    );
}

pub fn parse(raw: &str, nonce: &str) -> Transcript {
    let begin_prefix = format!("__SHUVSCAN__{nonce}__BEGIN__");
    let end_prefix = format!("__SHUVSCAN__{nonce}__END__");
    let unavailable_prefix = format!("__SHUVSCAN__{nonce}__UNAVAILABLE__");
    let partial_prefix = format!("__SHUVSCAN__{nonce}__PARTIAL__");
    let truncated_prefix = format!("__SHUVSCAN__{nonce}__TRUNCATED__");
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
                    let (output, unavailable, partial, collection_limits) = parse_section_output(
                        lines,
                        &unavailable_prefix,
                        &partial_prefix,
                        &truncated_prefix,
                    );
                    sections.insert(
                        id,
                        Section {
                            status,
                            output,
                            unavailable,
                            partial,
                            collection_limits,
                        },
                    );
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

    let host = sections.get(META_ID).map(|section| {
        let tools = sections
            .get(CAPABILITIES_ID)
            .filter(|section| section.status == 0)
            .into_iter()
            .flat_map(|section| section.output.lines())
            .filter_map(|line| line.strip_prefix("tool=").map(str::to_owned))
            .collect();
        parse_meta(&section.output, tools)
    });
    Transcript { host, sections }
}

fn parse_meta(output: &str, tools: Vec<String>) -> HostInfo {
    let mut host = HostInfo {
        hostname: "unknown".into(),
        kernel: "unknown".into(),
        os: "unknown".into(),
        capabilities: HostCapabilities {
            root: None,
            sudo_present: false,
            tools,
        },
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
                "root" => {
                    host.capabilities.root = match value {
                        "1" => Some(true),
                        "0" => Some(false),
                        _ => None,
                    }
                }
                "sudo_present" => host.capabilities.sudo_present = value == "1",
                _ => {}
            }
        }
    }
    host
}

fn parse_section_output(
    lines: Vec<&str>,
    unavailable_prefix: &str,
    partial_prefix: &str,
    truncated_prefix: &str,
) -> (String, Option<String>, Option<String>, Vec<String>) {
    let mut evidence = Vec::new();
    let mut unavailable = None;
    let mut partial = Vec::new();
    let mut collection_limits = Vec::new();
    for line in lines {
        if let Some(reason) = line.trim().strip_prefix(unavailable_prefix) {
            unavailable.get_or_insert_with(|| marker_reason(reason));
        } else if let Some(reason) = line.trim().strip_prefix(partial_prefix) {
            partial.push(marker_reason(reason));
        } else if let Some(reason) = line.trim().strip_prefix(truncated_prefix) {
            collection_limits.push(marker_reason(reason));
        } else {
            evidence.push(line);
        }
    }
    (
        evidence.join("\n").trim().to_owned(),
        unavailable,
        (!partial.is_empty()).then(|| partial.join("; ")),
        collection_limits,
    )
}

fn marker_reason(reason: &str) -> String {
    let reason = reason.trim();
    if reason.is_empty() {
        "no reason reported by target".to_owned()
    } else {
        reason.to_owned()
    }
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
            "{}{}{}",
            wrap(
                "meta",
                0,
                "hostname=web-01\nkernel=6.8.0\nos=Ubuntu 24.04 LTS\nroot=1\nsudo_present=1"
            ),
            wrap("capabilities", 0, "tool=awk\ntool=find"),
            wrap("SHUV-X", 0, "evidence line")
        );
        let transcript = parse(&raw, NONCE);
        let host = transcript.host.expect("meta parsed");
        assert_eq!(host.hostname, "web-01");
        assert_eq!(host.os, "Ubuntu 24.04 LTS");
        assert_eq!(host.capabilities.root, Some(true));
        assert!(host.capabilities.sudo_present);
        assert_eq!(host.capabilities.tools, ["awk", "find"]);
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
        assert!(script.contains("__BEGIN__capabilities__"));
        for probe in BUILTINS {
            assert!(script.contains(&format!("__BEGIN__{}__", probe.id)));
            assert!(script.contains(&format!("__END__{}__", probe.id)));
        }
    }

    #[test]
    fn script_guards_tools_and_privilege_before_probe_bodies() {
        let script = build_script(BUILTINS, NONCE);
        assert!(script.contains("missing required tool(s)"));
        assert!(script.contains("root access required; rerun with --sudo"));
        assert!(script.contains("$SHUVSCAN_PARTIAL"));
        assert!(!script.contains("export SHUVSCAN_UNAVAILABLE"));
    }

    #[test]
    fn probe_evidence_cannot_add_reported_capabilities() {
        let raw = format!(
            "{}{}{}",
            wrap("meta", 0, "hostname=host"),
            wrap("capabilities", 0, "tool=awk"),
            wrap("SHUV-X", 0, "tool=attacker-controlled")
        );
        let transcript = parse(&raw, NONCE);
        assert_eq!(transcript.host.unwrap().capabilities.tools, ["awk"],);
    }

    #[test]
    fn probe_scripts_use_only_nonce_scoped_status_variables() {
        let markers = [
            ("UNAVAILABLE", "$SHUVSCAN_UNAVAILABLE"),
            ("PARTIAL", "$SHUVSCAN_PARTIAL"),
            ("TRUNCATED", "$SHUVSCAN_TRUNCATED"),
        ];
        for probe in BUILTINS {
            for (name, variable) in markers {
                if probe.script.contains(name) {
                    assert!(probe.script.contains(variable));
                    assert!(!probe.script.contains(&format!("__SHUVSCAN_{name}__")));
                }
            }
        }
    }

    #[test]
    fn probe_subshells_cannot_consume_the_collector_script() {
        let probes = [
            Probe {
                id: "SHUV-TEST-001",
                title: "stdin reader",
                category: "test",
                description: "test",
                required_tools: &["cat"],
                privilege: Privilege::Unprivileged,
                script: "cat >/dev/null",
                kind: crate::probes::ProbeKind::Evidence,
            },
            Probe {
                id: "SHUV-TEST-002",
                title: "following probe",
                category: "test",
                description: "test",
                required_tools: &[],
                privilege: Privilege::Unprivileged,
                script: "printf 'still-running\\n'",
                kind: crate::probes::ProbeKind::Evidence,
            },
        ];
        let script = build_script(&probes, NONCE);
        let mut child = std::process::Command::new("sh")
            .arg("-s")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(child.stdin.as_mut().unwrap(), script.as_bytes()).unwrap();
        let output = child.wait_with_output().unwrap();
        let transcript = parse(&String::from_utf8(output.stdout).unwrap(), NONCE);

        assert!(output.status.success());
        assert_eq!(transcript.sections["SHUV-TEST-002"].output, "still-running");
    }

    #[test]
    fn fixed_status_marker_in_attacker_evidence_cannot_suppress_finding() {
        let forged = "__SHUVSCAN_UNAVAILABLE__ forged\nreal threat evidence";
        let transcript = parse(&wrap("SHUV-X", 0, forged), NONCE);
        let section = &transcript.sections["SHUV-X"];
        assert!(section.unavailable.is_none());
        assert_eq!(section.output, forged);
    }

    #[test]
    fn authentic_status_markers_are_parsed_and_removed_from_evidence() {
        let marker = format!("__SHUVSCAN__{NONCE}__UNAVAILABLE__ missing tool");
        let transcript = parse(&wrap("SHUV-X", 0, &marker), NONCE);
        let section = &transcript.sections["SHUV-X"];
        assert_eq!(section.unavailable.as_deref(), Some("missing tool"));
        assert!(section.output.is_empty());
    }

    #[test]
    fn authentic_truncation_marker_is_parsed_and_removed_from_evidence() {
        let marker = format!("__SHUVSCAN__{NONCE}__TRUNCATED__ low_high_process_sample=24");
        let transcript = parse(&wrap("SHUV-X", 0, &format!("evidence\n{marker}")), NONCE);
        let section = &transcript.sections["SHUV-X"];

        assert_eq!(section.collection_limits, ["low_high_process_sample=24"]);
        assert_eq!(section.output, "evidence");
    }

    #[test]
    fn forged_fixed_truncation_marker_stays_evidence() {
        let forged = "__SHUVSCAN_TRUNCATED__ max_processes=24";
        let transcript = parse(&wrap("SHUV-X", 0, forged), NONCE);
        let section = &transcript.sections["SHUV-X"];

        assert!(section.collection_limits.is_empty());
        assert_eq!(section.output, forged);
    }

    #[test]
    fn all_partial_and_collection_limit_reasons_are_preserved() {
        let partial = format!(
            "__SHUVSCAN__{NONCE}__PARTIAL__ root unavailable\n__SHUVSCAN__{NONCE}__PARTIAL__ skipped=9\n__SHUVSCAN__{NONCE}__TRUNCATED__ low_high_process_sample=24\n__SHUVSCAN__{NONCE}__TRUNCATED__ max_mounts=32"
        );
        let transcript = parse(&wrap("SHUV-X", 0, &partial), NONCE);
        let section = &transcript.sections["SHUV-X"];

        assert_eq!(
            section.partial.as_deref(),
            Some("root unavailable; skipped=9")
        );
        assert_eq!(
            section.collection_limits,
            ["low_high_process_sample=24", "max_mounts=32"]
        );
    }
}
