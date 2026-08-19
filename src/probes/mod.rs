use crate::model::{Evidence, Finding, Severity};

pub struct Probe {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub category: &'static str,
    pub description: &'static str,
    pub remediation: &'static str,
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

fn nonzero(output: &str) -> bool {
    output.trim().parse::<u64>().is_ok_and(|value| value != 0)
}

pub static BUILTINS: &[Probe] = &[
    Probe {
        id: "SHUV-AUTH-001",
        title: "Additional UID 0 account",
        severity: Severity::Critical,
        category: "identity",
        description: "An account other than root has superuser privileges.",
        remediation: "Disable the account and investigate its creation, keys, and recent activity.",
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
        script: "if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | awk '$1 == \"permitrootlogin\" && $2 == \"yes\"'; fi",
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-AUTH-003",
        title: "SSH password authentication enabled",
        severity: Severity::Medium,
        category: "ssh",
        description: "The SSH daemon accepts password authentication, increasing credential attack exposure.",
        remediation: "Deploy tested key-based access, then set PasswordAuthentication no.",
        script: "if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | awk '$1 == \"passwordauthentication\" && $2 == \"yes\"'; fi",
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-PERSIST-001",
        title: "Dynamic linker preload configured",
        severity: Severity::Critical,
        category: "persistence",
        description: "LD_PRELOAD is configured system-wide, a technique frequently used for userland rootkits.",
        remediation: "Isolate the host and validate every referenced library before removing the entry.",
        script: "if [ -s /etc/ld.so.preload ]; then sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' /etc/ld.so.preload 2>/dev/null; fi",
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-FS-001",
        title: "World-writable systemd unit",
        severity: Severity::Critical,
        category: "persistence",
        description: "A system service definition can be modified by any local user.",
        remediation: "Restore package-owned permissions and inspect the unit and its recent changes.",
        script: "find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -xdev -type f -perm -0002 -print 2>/dev/null",
        evaluate: has_output,
    },
    Probe {
        id: "SHUV-KERN-001",
        title: "Kernel pointer addresses exposed",
        severity: Severity::Medium,
        category: "kernel",
        description: "Kernel pointer restrictions are disabled, weakening exploit mitigations.",
        remediation: "Set kernel.kptr_restrict=2 unless a documented workload requires otherwise.",
        script: "cat /proc/sys/kernel/kptr_restrict 2>/dev/null || true",
        evaluate: |output| output.trim() == "0",
    },
    Probe {
        id: "SHUV-KERN-002",
        title: "Unprivileged BPF enabled",
        severity: Severity::High,
        category: "kernel",
        description: "Unprivileged users can load BPF programs, expanding kernel attack surface.",
        remediation: "Set kernel.unprivileged_bpf_disabled=1 or 2 and document exceptions.",
        script: "if [ -r /proc/sys/kernel/unprivileged_bpf_disabled ]; then awk '{print ($1 == 0 ? 1 : 0)}' /proc/sys/kernel/unprivileged_bpf_disabled; else echo 0; fi",
        evaluate: nonzero,
    },
    Probe {
        id: "SHUV-EXEC-001",
        title: "World-writable directory in system PATH",
        severity: Severity::High,
        category: "execution",
        description: "A command search path directory is writable by any local user.",
        remediation: "Remove the directory from PATH or restore trusted ownership and permissions.",
        script: "oldifs=$IFS; IFS=:; for d in $PATH; do [ -n \"$d\" ] || d=.; [ -d \"$d\" ] && [ -w \"$d\" ] && find \"$d\" -maxdepth 0 -perm -0002 -print 2>/dev/null; done; IFS=$oldifs",
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
    fn unprivileged_bpf_evaluator_only_flags_one() {
        let probe = BUILTINS
            .iter()
            .find(|probe| probe.id == "SHUV-KERN-002")
            .unwrap();
        assert!((probe.evaluate)("1"));
        assert!(!(probe.evaluate)("0"));
    }
}
