use crate::model::{Evidence, Finding, Severity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Privilege {
    Unprivileged,
    RootRecommended,
    RootRequired,
}

/// One read-only check. `script` is a static POSIX `sh` fragment executed in a
/// subshell on the target; it must exit 0 whenever collection itself succeeded
/// (a non-zero status is reported as a collection error, never as a pass), and
/// it prints `$SHUVSCAN_UNAVAILABLE` when it can tell that evidence cannot be
/// gathered in the current context. That variable contains a per-scan nonce;
/// never print a fixed protocol marker. `evaluate` inspects stdout only and
/// decides whether to raise a finding.
///
/// `required_tools` and `privilege` are enforced by the protocol wrapper before
/// the fragment runs. Root-recommended probes still run unprivileged but report
/// partial collection.
#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub category: &'static str,
    pub description: &'static str,
    pub remediation: &'static str,
    pub required_tools: &'static [&'static str],
    pub privilege: Privilege,
    pub script: &'static str,
    pub evaluate: fn(&str) -> bool,
}

impl Probe {
    pub fn finding(&self, output: String) -> Finding {
        Finding {
            id: self.id,
            title: self.title,
            severity: self.severity,
            category: self.category,
            description: self.description,
            remediation: self.remediation,
            evidence: Evidence {
                command: self.script,
                output,
            },
        }
    }
}

fn has_output(output: &str) -> bool {
    !output.trim().is_empty()
}

fn is_zero(output: &str) -> bool {
    output.trim() == "0"
}

pub static BUILTINS: &[Probe] = &[
    Probe {
        id: "SHUV-AUTH-001",
        title: "Additional UID 0 account",
        severity: Severity::Critical,
        category: "identity",
        description: "An account other than root has superuser privileges.",
        remediation: "Disable the account and investigate its creation, keys, and recent activity.",
        required_tools: &["awk"],
        privilege: Privilege::Unprivileged,
        script: "awk -F: '$3 == 0 && $1 != \"root\" {print $1 \":\" $6 \":\" $7}' /etc/passwd 2>/dev/null",
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-AUTH-002",
        title: "SSH permits direct root login",
        severity: Severity::High,
        category: "ssh",
        description: "The effective SSH daemon configuration permits direct root authentication.",
        remediation: "Set PermitRootLogin no, validate with sshd -T, and reload sshd.",
        required_tools: &["awk", "sshd"],
        privilege: Privilege::RootRequired,
        script: r#"if cfg=$(sshd -T 2>/dev/null); then
  printf '%s\n' "$cfg" | awk '$1 == "permitrootlogin" && $2 == "yes"'
else
  printf '%s sshd -T failed\n' "$SHUVSCAN_UNAVAILABLE"
fi"#,
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-AUTH-003",
        title: "SSH password authentication enabled",
        severity: Severity::Medium,
        category: "ssh",
        description: "The SSH daemon accepts password authentication, increasing credential attack exposure.",
        remediation: "Deploy tested key-based access, then set PasswordAuthentication no.",
        required_tools: &["awk", "sshd"],
        privilege: Privilege::RootRequired,
        script: r#"if cfg=$(sshd -T 2>/dev/null); then
  printf '%s\n' "$cfg" | awk '$1 == "passwordauthentication" && $2 == "yes"'
else
  printf '%s sshd -T failed\n' "$SHUVSCAN_UNAVAILABLE"
fi"#,
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-PERSIST-001",
        title: "Dynamic linker preload configured",
        severity: Severity::Critical,
        category: "persistence",
        description: "LD_PRELOAD is configured system-wide, a technique frequently used for userland rootkits.",
        remediation: "Isolate the host and validate every referenced library before removing the entry.",
        required_tools: &["sed"],
        privilege: Privilege::Unprivileged,
        script: "if [ -s /etc/ld.so.preload ]; then sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' /etc/ld.so.preload 2>/dev/null; fi",
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-PERSIST-002",
        title: "World-writable cron entry",
        severity: Severity::High,
        category: "persistence",
        description: "A cron file or directory can be modified by any local user, allowing scheduled code execution as root.",
        remediation: "Restore root:root ownership and strict permissions, then audit the entries for planted jobs.",
        required_tools: &["find"],
        privilege: Privilege::Unprivileged,
        script: r#"for d in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
  [ -e "$d" ] && find "$d" -xdev -perm -0002 \( -type f -o -type d \) -print 2>/dev/null
done
:"#,
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-FS-001",
        title: "World-writable systemd unit",
        severity: Severity::Critical,
        category: "persistence",
        description: "A system service definition can be modified by any local user.",
        remediation: "Restore package-owned permissions and inspect the unit and its recent changes.",
        required_tools: &["find"],
        privilege: Privilege::Unprivileged,
        script: r#"for d in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
  [ -d "$d" ] && ! [ -L "$d" ] && find "$d" -xdev -type f -perm -0002 -print 2>/dev/null
done
:"#,
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-FS-002",
        title: "SUID/SGID binary in a temporary directory",
        severity: Severity::Critical,
        category: "filesystem",
        description: "A set-uid or set-gid executable exists in a world-writable temporary directory; no legitimate software installs there.",
        remediation: "Capture the binary for analysis, remove it, and hunt for the process or account that created it.",
        required_tools: &["find"],
        privilege: Privilege::Unprivileged,
        script: r#"for d in /tmp /var/tmp /dev/shm; do
  [ -d "$d" ] && find "$d" -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null
done
:"#,
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-PROC-001",
        title: "Process running a deleted executable",
        severity: Severity::Medium,
        category: "process",
        description: "A running process executes a binary that no longer exists on disk. Malware deletes itself to evade file scans; package upgrades that replaced the binary are the common benign cause.",
        remediation: "Correlate the PID with recent package upgrades; restart legitimately upgraded services and capture /proc/<pid>/ for anything unexplained.",
        required_tools: &["readlink"],
        privilege: Privilege::RootRecommended,
        script: r#"for exe in /proc/[0-9]*/exe; do
  target=$(readlink "$exe" 2>/dev/null) || continue
  case "$target" in
  *' (deleted)')
    pid=${exe#/proc/}
    printf '%s %s\n' "${pid%/exe}" "$target"
    ;;
  esac
done
:"#,
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-KERN-001",
        title: "Kernel pointer addresses exposed",
        severity: Severity::Medium,
        category: "kernel",
        description: "Kernel pointer restrictions are disabled, weakening exploit mitigations.",
        remediation: "Set kernel.kptr_restrict=2 unless a documented workload requires otherwise.",
        required_tools: &["cat"],
        privilege: Privilege::Unprivileged,
        script: "cat /proc/sys/kernel/kptr_restrict 2>/dev/null || :",
        evaluate: is_zero,
    },
    Probe {
        id: "SHUV-KERN-002",
        title: "Unprivileged BPF enabled",
        severity: Severity::High,
        category: "kernel",
        description: "Unprivileged users can load BPF programs, expanding kernel attack surface.",
        remediation: "Set kernel.unprivileged_bpf_disabled=1 or 2 and document exceptions.",
        required_tools: &["cat"],
        privilege: Privilege::Unprivileged,
        script: "cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || :",
        evaluate: is_zero,
    },
    Probe {
        id: "SHUV-EXEC-001",
        title: "World-writable system executable directory",
        severity: Severity::High,
        category: "execution",
        description: "A standard executable directory is writable by any local user, enabling trivial binary planting.",
        remediation: "Restore root ownership and 0755 permissions, then audit the directory for planted binaries.",
        required_tools: &["find"],
        privilege: Privilege::Unprivileged,
        script: r#"for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
  [ -d "$d" ] && ! [ -L "$d" ] && find "$d" -maxdepth 0 -perm -0002 -print 2>/dev/null
done
:"#,
        evaluate: has_output,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_have_unique_stable_ids() {
        let mut ids = BUILTINS.iter().map(|probe| probe.id).collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), BUILTINS.len());
    }

    #[test]
    fn kernel_probes_flag_only_the_permissive_value() {
        for id in ["SHUV-KERN-001", "SHUV-KERN-002"] {
            let probe = BUILTINS.iter().find(|probe| probe.id == id).unwrap();
            assert!((probe.evaluate)("0"));
            assert!(!(probe.evaluate)("1"));
            assert!(!(probe.evaluate)("2"));
            assert!(!(probe.evaluate)(""), "missing sysctl must not flag");
        }
    }

    #[test]
    fn silence_is_a_pass_only_for_output_probes() {
        for probe in BUILTINS {
            assert!(
                !(probe.evaluate)(""),
                "{} must not fire on empty output",
                probe.id
            );
        }
    }

    #[test]
    fn every_builtin_declares_its_runtime_requirements() {
        for probe in BUILTINS {
            assert!(
                !probe.required_tools.is_empty(),
                "{} must declare required tools",
                probe.id
            );
        }
    }
}
