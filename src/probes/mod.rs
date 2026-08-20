use crate::model::{Evidence, Finding, Observation, Severity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Privilege {
    Unprivileged,
    RootRecommended,
    RootRequired,
}

/// One read-only probe. `script` is a static POSIX `sh` fragment executed in a
/// subshell on the target; it must exit 0 whenever collection itself succeeded
/// (a non-zero status is reported as a collection error, never as a pass), and
/// it prints `$SHUVSCAN_UNAVAILABLE` when it can tell that evidence cannot be
/// gathered in the current context. That variable contains a per-scan nonce;
/// never print a fixed protocol marker. Detection probes evaluate stdout and
/// may raise a finding; evidence probes retain successful stdout as an
/// observation without assigning a verdict.
///
/// `required_tools` and `privilege` are enforced by the protocol wrapper before
/// the fragment runs. Root-recommended probes still run unprivileged but report
/// partial collection.
#[derive(Clone, Copy, Debug)]
pub enum ProbeKind {
    Detection {
        severity: Severity,
        remediation: &'static str,
        evaluate: fn(&str) -> bool,
    },
    Evidence,
}

#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub required_tools: &'static [&'static str],
    pub privilege: Privilege,
    pub script: &'static str,
    pub kind: ProbeKind,
}

impl Probe {
    pub fn finding(&self, evaluation_output: &str, evidence_output: String) -> Option<Finding> {
        let ProbeKind::Detection {
            severity,
            remediation,
            evaluate,
        } = self.kind
        else {
            return None;
        };
        evaluate(evaluation_output).then_some(Finding {
            id: self.id,
            title: self.title,
            severity,
            category: self.category,
            description: self.description,
            remediation,
            evidence: Evidence {
                command: self.script,
                output: evidence_output,
            },
        })
    }

    pub fn observation(
        &self,
        output: String,
        partial: Option<String>,
        collection_limits: Vec<String>,
        evidence_budget_exceeded: bool,
    ) -> Option<Observation> {
        matches!(self.kind, ProbeKind::Evidence).then_some(Observation {
            id: self.id,
            title: self.title,
            category: self.category,
            partial,
            truncated: evidence_budget_exceeded || !collection_limits.is_empty(),
            collection_limits,
            evidence_budget_exceeded,
            evidence: Evidence {
                command: self.script,
                output,
            },
        })
    }

    pub fn severity(&self) -> Option<Severity> {
        match self.kind {
            ProbeKind::Detection { severity, .. } => Some(severity),
            ProbeKind::Evidence => None,
        }
    }

    pub fn remediation(&self) -> Option<&'static str> {
        match self.kind {
            ProbeKind::Detection { remediation, .. } => Some(remediation),
            ProbeKind::Evidence => None,
        }
    }

    pub fn evaluator(&self) -> Option<fn(&str) -> bool> {
        match self.kind {
            ProbeKind::Detection { evaluate, .. } => Some(evaluate),
            ProbeKind::Evidence => None,
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
        category: "identity",
        description: "An account other than root has superuser privileges.",
        required_tools: &["awk"],
        privilege: Privilege::Unprivileged,
        script: "awk -F: '$3 == 0 && $1 != \"root\" {print $1 \":\" $6 \":\" $7}' /etc/passwd 2>/dev/null",
        kind: ProbeKind::Detection {
            severity: Severity::Critical,
            remediation: "Disable the account and investigate its creation, keys, and recent activity.",
            evaluate: has_output,
        },
    },
    Probe {
        id: "SHUV-AUTH-002",
        title: "SSH permits direct root login",
        category: "ssh",
        description: "The effective SSH daemon configuration permits direct root authentication.",
        required_tools: &["awk", "sshd"],
        privilege: Privilege::RootRequired,
        script: r#"if cfg=$(sshd -T 2>/dev/null); then
  printf '%s\n' "$cfg" | awk '$1 == "permitrootlogin" && $2 == "yes"'
else
  printf '%s sshd -T failed\n' "$SHUVSCAN_UNAVAILABLE"
fi"#,
        kind: ProbeKind::Detection {
            severity: Severity::High,
            remediation: "Set PermitRootLogin no, validate with sshd -T, and reload sshd.",
            evaluate: has_output,
        },
    },
    Probe {
        id: "SHUV-AUTH-003",
        title: "SSH password authentication enabled",
        category: "ssh",
        description: "The SSH daemon accepts password authentication, increasing credential attack exposure.",
        required_tools: &["awk", "sshd"],
        privilege: Privilege::RootRequired,
        script: r#"if cfg=$(sshd -T 2>/dev/null); then
  printf '%s\n' "$cfg" | awk '$1 == "passwordauthentication" && $2 == "yes"'
else
  printf '%s sshd -T failed\n' "$SHUVSCAN_UNAVAILABLE"
fi"#,
        kind: ProbeKind::Detection {
            severity: Severity::Medium,
            remediation: "Deploy tested key-based access, then set PasswordAuthentication no.",
            evaluate: has_output,
        },
    },
    Probe {
        id: "SHUV-PERSIST-001",
        title: "Dynamic linker preload configured",
        category: "persistence",
        description: "LD_PRELOAD is configured system-wide, a technique frequently used for userland rootkits.",
        required_tools: &["sed"],
        privilege: Privilege::Unprivileged,
        script: "if [ -s /etc/ld.so.preload ]; then sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' /etc/ld.so.preload 2>/dev/null; fi",
        kind: ProbeKind::Detection {
            severity: Severity::Critical,
            remediation: "Isolate the host and validate every referenced library before removing the entry.",
            evaluate: has_output,
        },
    },
    Probe {
        id: "SHUV-PERSIST-002",
        title: "World-writable cron entry",
        category: "persistence",
        description: "A cron file or directory can be modified by any local user, allowing scheduled code execution as root.",
        required_tools: &["find"],
        privilege: Privilege::Unprivileged,
        script: r#"for d in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
  [ -e "$d" ] && find "$d" -xdev -perm -0002 \( -type f -o -type d \) -print 2>/dev/null
done
:"#,
        kind: ProbeKind::Detection {
            severity: Severity::High,
            remediation: "Restore root:root ownership and strict permissions, then audit the entries for planted jobs.",
            evaluate: has_output,
        },
    },
    Probe {
        id: "SHUV-FS-001",
        title: "World-writable systemd unit",
        category: "persistence",
        description: "A system service definition can be modified by any local user.",
        required_tools: &["find"],
        privilege: Privilege::Unprivileged,
        script: r#"for d in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
  [ -d "$d" ] && ! [ -L "$d" ] && find "$d" -xdev -type f -perm -0002 -print 2>/dev/null
done
:"#,
        kind: ProbeKind::Detection {
            severity: Severity::Critical,
            remediation: "Restore package-owned permissions and inspect the unit and its recent changes.",
            evaluate: has_output,
        },
    },
    Probe {
        id: "SHUV-FS-002",
        title: "SUID/SGID binary in a temporary directory",
        category: "filesystem",
        description: "A set-uid or set-gid executable exists in a world-writable temporary directory; no legitimate software installs there.",
        required_tools: &["find"],
        privilege: Privilege::Unprivileged,
        script: r#"for d in /tmp /var/tmp /dev/shm; do
  [ -d "$d" ] && find "$d" -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null
done
:"#,
        kind: ProbeKind::Detection {
            severity: Severity::Critical,
            remediation: "Capture the binary for analysis, remove it, and hunt for the process or account that created it.",
            evaluate: has_output,
        },
    },
    Probe {
        id: "SHUV-PROC-001",
        title: "Process running a deleted executable",
        category: "process",
        description: "A running process executes a binary that no longer exists on disk. Malware deletes itself to evade file scans; package upgrades that replaced the binary are the common benign cause.",
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
        kind: ProbeKind::Detection {
            severity: Severity::Medium,
            remediation: "Correlate the PID with recent package upgrades; restart legitimately upgraded services and capture /proc/<pid>/ for anything unexplained.",
            evaluate: has_output,
        },
    },
    Probe {
        id: "SHUV-KERN-001",
        title: "Kernel pointer addresses exposed",
        category: "kernel",
        description: "Kernel pointer restrictions are disabled, weakening exploit mitigations.",
        required_tools: &["cat"],
        privilege: Privilege::Unprivileged,
        script: "cat /proc/sys/kernel/kptr_restrict 2>/dev/null || :",
        kind: ProbeKind::Detection {
            severity: Severity::Medium,
            remediation: "Set kernel.kptr_restrict=2 unless a documented workload requires otherwise.",
            evaluate: is_zero,
        },
    },
    Probe {
        id: "SHUV-KERN-002",
        title: "Unprivileged BPF enabled",
        category: "kernel",
        description: "Unprivileged users can load BPF programs, expanding kernel attack surface.",
        required_tools: &["cat"],
        privilege: Privilege::Unprivileged,
        script: "cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || :",
        kind: ProbeKind::Detection {
            severity: Severity::High,
            remediation: "Set kernel.unprivileged_bpf_disabled=1 or 2 and document exceptions.",
            evaluate: is_zero,
        },
    },
    Probe {
        id: "SHUV-EXEC-001",
        title: "World-writable system executable directory",
        category: "execution",
        description: "A standard executable directory is writable by any local user, enabling trivial binary planting.",
        required_tools: &["find"],
        privilege: Privilege::Unprivileged,
        script: r#"for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
  [ -d "$d" ] && ! [ -L "$d" ] && find "$d" -maxdepth 0 -perm -0002 -print 2>/dev/null
done
:"#,
        kind: ProbeKind::Detection {
            severity: Severity::High,
            remediation: "Restore root ownership and 0755 permissions, then audit the directory for planted binaries.",
            evaluate: has_output,
        },
    },
    Probe {
        id: "SHUV-EVID-PKG-001",
        title: "Running executable package ownership",
        category: "package",
        description: "Maps a bounded sample of running executable paths to the owning dpkg, RPM, apk, or pacman package.",
        required_tools: &["awk", "readlink", "sort", "tr"],
        privilege: Privilege::RootRecommended,
        script: r#"shuvscan_package_manager=
if command -v dpkg-query >/dev/null 2>&1; then
  shuvscan_manager_path=$(command -v dpkg-query)
  dpkg-query -S -- "$shuvscan_manager_path" >/dev/null 2>&1 && shuvscan_package_manager=dpkg
fi
if [ -z "$shuvscan_package_manager" ] && command -v apk >/dev/null 2>&1; then
  shuvscan_manager_path=$(command -v apk)
  apk info -W "$shuvscan_manager_path" >/dev/null 2>&1 && shuvscan_package_manager=apk
fi
if [ -z "$shuvscan_package_manager" ] && command -v pacman >/dev/null 2>&1; then
  shuvscan_manager_path=$(command -v pacman)
  pacman -Qo -- "$shuvscan_manager_path" >/dev/null 2>&1 && shuvscan_package_manager=pacman
fi
if [ -z "$shuvscan_package_manager" ] && command -v rpm >/dev/null 2>&1; then
  shuvscan_manager_path=$(command -v rpm)
  rpm -qf -- "$shuvscan_manager_path" >/dev/null 2>&1 && shuvscan_package_manager=rpm
fi
if [ -z "$shuvscan_package_manager" ]; then
  printf '%s no supported package database tool found (dpkg-query, rpm, apk, or pacman)\n' "$SHUVSCAN_UNAVAILABLE"
  exit 0
fi
printf 'package_manager=%s\n' "$shuvscan_package_manager"
[ -d /proc ] || {
  printf '%s /proc is unavailable\n' "$SHUVSCAN_UNAVAILABLE"
  exit 0
}
shuvscan_skipped=0
shuvscan_pids=$(for shuvscan_path in /proc/[0-9]*; do printf '%s\n' "${shuvscan_path#/proc/}"; done | sort -n | awk 'NR <= 12 {low[NR]=$0} {high[(NR-1)%12]=$0} END {for(i=1;i<=NR && i<=12;i++) print low[i]; start=NR-11; if(start<13) start=13; for(i=start;i<=NR;i++) print high[(i-1)%12]; if(NR>24) print "SHUVSCAN_MORE"}')
for shuvscan_pid in $shuvscan_pids; do
  if [ "$shuvscan_pid" = SHUVSCAN_MORE ]; then
    printf '%s low_high_process_sample=24\n' "$SHUVSCAN_TRUNCATED"
    break
  fi
  shuvscan_target=$(readlink "/proc/$shuvscan_pid/exe" 2>/dev/null) || {
    shuvscan_skipped=$((shuvscan_skipped + 1))
    continue
  }
  shuvscan_deleted=0
  case "$shuvscan_target" in
    *' (deleted)')
      shuvscan_deleted=1
      shuvscan_query_target=${shuvscan_target%' (deleted)'}
      ;;
    *) shuvscan_query_target=$shuvscan_target ;;
  esac
  shuvscan_owner=unresolved
  case "$shuvscan_package_manager" in
    dpkg) if shuvscan_raw=$(dpkg-query -S -- "$shuvscan_query_target" 2>/dev/null); then shuvscan_owner=$shuvscan_raw; fi ;;
    rpm) if shuvscan_raw=$(rpm -qf -- "$shuvscan_query_target" 2>/dev/null); then shuvscan_owner=$shuvscan_raw; fi ;;
    apk) if shuvscan_raw=$(apk info -W "$shuvscan_query_target" 2>/dev/null); then shuvscan_owner=$shuvscan_raw; fi ;;
    pacman) if shuvscan_raw=$(pacman -Qo -- "$shuvscan_query_target" 2>/dev/null); then shuvscan_owner=$shuvscan_raw; fi ;;
  esac
  [ -n "$shuvscan_owner" ] || shuvscan_owner=unresolved
  shuvscan_target=$(printf '%s' "$shuvscan_target" | tr '\n\t' '  ')
  shuvscan_owner=$(printf '%s' "$shuvscan_owner" | tr '\n\t' '  ')
  printf 'pid=%s\tdeleted=%s\texe=%s\towner=%s\n' "$shuvscan_pid" "$shuvscan_deleted" "$shuvscan_target" "$shuvscan_owner"
done
[ "$shuvscan_skipped" -eq 0 ] || printf '%s skipped_unreadable_processes=%s\n' "$SHUVSCAN_PARTIAL" "$shuvscan_skipped"
:"#,
        kind: ProbeKind::Evidence,
    },
    Probe {
        id: "SHUV-EVID-PROC-001",
        title: "Sampled PID and parent PID pairs",
        category: "process",
        description: "Records PID, parent PID, real and effective UIDs, name, and command line for a bounded process sample.",
        required_tools: &["awk", "sort", "tr"],
        privilege: Privilege::RootRecommended,
        script: r#"[ -d /proc ] || {
  printf '%s /proc is unavailable\n' "$SHUVSCAN_UNAVAILABLE"
  exit 0
}
shuvscan_skipped=0
shuvscan_pids=$(for shuvscan_path in /proc/[0-9]*; do printf '%s\n' "${shuvscan_path#/proc/}"; done | sort -n | awk 'NR <= 12 {low[NR]=$0} {high[(NR-1)%12]=$0} END {for(i=1;i<=NR && i<=12;i++) print low[i]; start=NR-11; if(start<13) start=13; for(i=start;i<=NR;i++) print high[(i-1)%12]; if(NR>24) print "SHUVSCAN_MORE"}')
for shuvscan_pid in $shuvscan_pids; do
  if [ "$shuvscan_pid" = SHUVSCAN_MORE ]; then
    printf '%s low_high_process_sample=24\n' "$SHUVSCAN_TRUNCATED"
    break
  fi
  shuvscan_status=/proc/$shuvscan_pid/status
  if [ ! -r "$shuvscan_status" ]; then
    shuvscan_skipped=$((shuvscan_skipped + 1))
    continue
  fi
  shuvscan_name=$(awk '$1 == "Name:" {sub(/^[^:]*:[[:space:]]*/, ""); print; exit}' "$shuvscan_status" 2>/dev/null | tr '\n\t' '  ')
  shuvscan_name=${shuvscan_name% }
  shuvscan_ppid=$(awk '$1 == "PPid:" {print $2; exit}' "$shuvscan_status" 2>/dev/null)
  shuvscan_ruid=$(awk '$1 == "Uid:" {print $2; exit}' "$shuvscan_status" 2>/dev/null)
  shuvscan_euid=$(awk '$1 == "Uid:" {print $3; exit}' "$shuvscan_status" 2>/dev/null)
  shuvscan_cmd=
  if [ -r "/proc/$shuvscan_pid/cmdline" ]; then
    shuvscan_cmd=$(tr '\000\n\t' '   ' < "/proc/$shuvscan_pid/cmdline" 2>/dev/null | awk '{print substr($0, 1, 160)}')
  else
    shuvscan_skipped=$((shuvscan_skipped + 1))
  fi
  printf 'pid=%s\tppid=%s\truid=%s\teuid=%s\tname=%s\tcmd=%s\n' "$shuvscan_pid" "$shuvscan_ppid" "$shuvscan_ruid" "$shuvscan_euid" "$shuvscan_name" "$shuvscan_cmd"
done
[ "$shuvscan_skipped" -eq 0 ] || printf '%s skipped_unreadable_files=%s\n' "$SHUVSCAN_PARTIAL" "$shuvscan_skipped"
:"#,
        kind: ProbeKind::Evidence,
    },
    Probe {
        id: "SHUV-EVID-NET-001",
        title: "Listening sockets",
        category: "network",
        description: "Records a bounded snapshot of listening TCP and UDP sockets with process data when visible.",
        required_tools: &["awk"],
        privilege: Privilege::RootRecommended,
        script: r#"if command -v ss >/dev/null 2>&1 && ss -H -ltnp >/dev/null 2>&1 && ss -H -lunp >/dev/null 2>&1; then
  printf 'socket_tool=ss\n'
  printf 'socket_protocol=tcp\n'
  ss -H -ltnp 2>/dev/null | awk 'NR <= 16 {print} NR == 17 {exit 42}'
  [ "$?" -ne 42 ] || printf '%s max_tcp_sockets=16\n' "$SHUVSCAN_TRUNCATED"
  printf 'socket_protocol=udp\n'
  ss -H -lunp 2>/dev/null | awk 'NR <= 16 {print} NR == 17 {exit 42}'
  [ "$?" -ne 42 ] || printf '%s max_udp_sockets=16\n' "$SHUVSCAN_TRUNCATED"
elif command -v netstat >/dev/null 2>&1 && netstat -lntp >/dev/null 2>&1 && netstat -lnup >/dev/null 2>&1; then
  printf 'socket_tool=netstat\n'
  printf 'socket_protocol=tcp\n'
  netstat -lntp 2>/dev/null | awk 'NR <= 18 {print} NR == 19 {exit 42}'
  [ "$?" -ne 42 ] || printf '%s max_tcp_lines=18\n' "$SHUVSCAN_TRUNCATED"
  printf 'socket_protocol=udp\n'
  netstat -lnup 2>/dev/null | awk 'NR <= 18 {print} NR == 19 {exit 42}'
  [ "$?" -ne 42 ] || printf '%s max_udp_lines=18\n' "$SHUVSCAN_TRUNCATED"
else
  printf '%s no working socket inventory tool found (ss or netstat)\n' "$SHUVSCAN_UNAVAILABLE"
fi
:"#,
        kind: ProbeKind::Evidence,
    },
    Probe {
        id: "SHUV-EVID-NS-001",
        title: "Process Linux namespaces",
        category: "namespace",
        description: "Records namespace identities for a bounded process sample so isolation boundaries can be correlated.",
        required_tools: &["awk", "readlink", "sort", "tr"],
        privilege: Privilege::RootRecommended,
        script: r#"if [ ! -d /proc/self/ns ]; then
  printf '%s Linux namespace links are unavailable\n' "$SHUVSCAN_UNAVAILABLE"
  exit 0
fi
shuvscan_skipped=0
shuvscan_pids=$(for shuvscan_path in /proc/[0-9]*; do printf '%s\n' "${shuvscan_path#/proc/}"; done | sort -n | awk 'NR <= 12 {low[NR]=$0} {high[(NR-1)%12]=$0} END {for(i=1;i<=NR && i<=12;i++) print low[i]; start=NR-11; if(start<13) start=13; for(i=start;i<=NR;i++) print high[(i-1)%12]; if(NR>24) print "SHUVSCAN_MORE"}')
for shuvscan_pid in $shuvscan_pids; do
  if [ "$shuvscan_pid" = SHUVSCAN_MORE ]; then
    printf '%s low_high_process_sample=24\n' "$SHUVSCAN_TRUNCATED"
    break
  fi
  shuvscan_nsdir=/proc/$shuvscan_pid/ns
  shuvscan_mnt=$(readlink "$shuvscan_nsdir/mnt" 2>/dev/null) || {
    shuvscan_skipped=$((shuvscan_skipped + 1))
    continue
  }
  shuvscan_mnt=$(printf '%s' "$shuvscan_mnt" | tr '\n\t' '  ')
  shuvscan_mnt=${shuvscan_mnt% }
  shuvscan_pidns=$(readlink "$shuvscan_nsdir/pid" 2>/dev/null | tr '\n\t' '  ' || :)
  shuvscan_net=$(readlink "$shuvscan_nsdir/net" 2>/dev/null | tr '\n\t' '  ' || :)
  shuvscan_user=$(readlink "$shuvscan_nsdir/user" 2>/dev/null | tr '\n\t' '  ' || :)
  shuvscan_uts=$(readlink "$shuvscan_nsdir/uts" 2>/dev/null | tr '\n\t' '  ' || :)
  shuvscan_ipc=$(readlink "$shuvscan_nsdir/ipc" 2>/dev/null | tr '\n\t' '  ' || :)
  shuvscan_pidns=${shuvscan_pidns% }
  shuvscan_net=${shuvscan_net% }
  shuvscan_user=${shuvscan_user% }
  shuvscan_uts=${shuvscan_uts% }
  shuvscan_ipc=${shuvscan_ipc% }
  printf 'pid=%s\tmnt=%s\tpidns=%s\tnet=%s\tuser=%s\tuts=%s\tipc=%s\n' "$shuvscan_pid" "$shuvscan_mnt" "$shuvscan_pidns" "$shuvscan_net" "$shuvscan_user" "$shuvscan_uts" "$shuvscan_ipc"
done
[ "$shuvscan_skipped" -eq 0 ] || printf '%s skipped_unreadable_namespaces=%s\n' "$SHUVSCAN_PARTIAL" "$shuvscan_skipped"
:"#,
        kind: ProbeKind::Evidence,
    },
    Probe {
        id: "SHUV-EVID-CONT-001",
        title: "Container and cgroup context",
        category: "container",
        description: "Records host container markers and bounded process cgroup memberships without entering namespaces.",
        required_tools: &["awk", "sort", "tr"],
        privilege: Privilege::RootRecommended,
        script: r#"[ ! -e /.dockerenv ] || printf 'host_marker=/.dockerenv\n'
[ ! -e /run/.containerenv ] || printf 'host_marker=/run/.containerenv\n'
if [ -r /proc/1/cgroup ]; then
  awk 'NR <= 32 {print "pid1_cgroup=" $0} NR == 33 {exit 42}' /proc/1/cgroup 2>/dev/null
  [ "$?" -ne 42 ] || printf '%s max_pid1_cgroups=32\n' "$SHUVSCAN_TRUNCATED"
else
  printf '%s /proc/1/cgroup is unreadable\n' "$SHUVSCAN_PARTIAL"
fi
if [ -r /proc/1/mountinfo ]; then
  awk '{sep=0; for (i=7; i<=NF; i++) if ($i == "-") {sep=i; break} if (sep && ($5 ~ /^\/var\/lib\/(docker|containers|containerd)(\/|$)/ || $(sep+2) ~ /(^|\/)(docker|containerd|kubepods|libpod|lxc)(\/|$)/ || $0 ~ /machine[.]slice/)) {count++; if (count <= 32) print "pid1_mount=" $5 " fstype=" $(sep+1) " source=" $(sep+2); else exit 42}}' /proc/1/mountinfo 2>/dev/null
  [ "$?" -ne 42 ] || printf '%s max_container_mounts=32\n' "$SHUVSCAN_TRUNCATED"
else
  printf '%s /proc/1/mountinfo is unreadable\n' "$SHUVSCAN_PARTIAL"
fi
shuvscan_skipped=0
[ -d /proc ] || {
  printf '%s /proc is unavailable\n' "$SHUVSCAN_PARTIAL"
  exit 0
}
shuvscan_pids=$(for shuvscan_path in /proc/[0-9]*; do printf '%s\n' "${shuvscan_path#/proc/}"; done | sort -n | awk 'NR <= 12 {low[NR]=$0} {high[(NR-1)%12]=$0} END {for(i=1;i<=NR && i<=12;i++) print low[i]; start=NR-11; if(start<13) start=13; for(i=start;i<=NR;i++) print high[(i-1)%12]; if(NR>24) print "SHUVSCAN_MORE"}')
for shuvscan_pid in $shuvscan_pids; do
  if [ "$shuvscan_pid" = SHUVSCAN_MORE ]; then
    printf '%s low_high_process_sample=24\n' "$SHUVSCAN_TRUNCATED"
    break
  fi
  shuvscan_cgroup=/proc/$shuvscan_pid/cgroup
  if [ ! -r "$shuvscan_cgroup" ]; then
    shuvscan_skipped=$((shuvscan_skipped + 1))
    continue
  fi
  shuvscan_membership=$(tr '\n\t' '; ' < "$shuvscan_cgroup" 2>/dev/null)
  shuvscan_membership=${shuvscan_membership%';'}
  printf 'pid=%s\tcgroup=%s\n' "$shuvscan_pid" "$shuvscan_membership"
done
[ "$shuvscan_skipped" -eq 0 ] || printf '%s skipped_unreadable_cgroups=%s\n' "$SHUVSCAN_PARTIAL" "$shuvscan_skipped"
:"#,
        kind: ProbeKind::Evidence,
    },
];

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    fn probe(id: &str) -> &'static Probe {
        BUILTINS.iter().find(|probe| probe.id == id).unwrap()
    }

    fn stub_dir() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "shuvscan-probe-test-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn write_stub(directory: &Path, name: &str, body: &str) {
        let path = directory.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn run_with_stubs(probe: &Probe, directory: &Path) -> std::process::Output {
        let path = format!(
            "{}:{}",
            directory.display(),
            env::var("PATH").unwrap_or_default()
        );
        Command::new("sh")
            .args(["-c", probe.script])
            .env("PATH", path)
            .env("SHUVSCAN_UNAVAILABLE", "UNAVAILABLE:")
            .env("SHUVSCAN_PARTIAL", "PARTIAL:")
            .env("SHUVSCAN_TRUNCATED", "TRUNCATED:")
            .output()
            .unwrap()
    }

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
            let evaluate = probe.evaluator().unwrap();
            assert!(evaluate("0"));
            assert!(!evaluate("1"));
            assert!(!evaluate("2"));
            assert!(!evaluate(""), "missing sysctl must not flag");
        }
    }

    #[test]
    fn silence_is_a_pass_only_for_output_probes() {
        for probe in BUILTINS.iter().filter(|probe| probe.evaluator().is_some()) {
            let evaluate = probe.evaluator().unwrap();
            assert!(!evaluate(""), "{} must not fire on empty output", probe.id);
        }
    }

    #[test]
    fn evidence_probes_cannot_create_findings() {
        for probe in BUILTINS
            .iter()
            .filter(|probe| matches!(probe.kind, ProbeKind::Evidence))
        {
            assert!(
                probe
                    .finding("arbitrary output", "arbitrary output".into())
                    .is_none()
            );
            assert!(
                probe
                    .observation("inventory".into(), None, Vec::new(), false)
                    .is_some()
            );
        }
    }

    #[test]
    fn socket_collector_falls_back_when_ss_fails() {
        let directory = stub_dir();
        write_stub(&directory, "ss", "exit 1");
        write_stub(
            &directory,
            "netstat",
            "printf '%s\\n' 'Proto Local Address State' 'tcp 0.0.0.0:22 LISTEN'",
        );

        let output = run_with_stubs(probe("SHUV-EVID-NET-001"), &directory);
        fs::remove_dir_all(directory).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(output.status.success());
        assert!(stdout.contains("socket_tool=netstat"));
        assert!(stdout.contains("0.0.0.0:22"));
        assert!(!stdout.contains("UNAVAILABLE:"));
    }

    #[test]
    fn package_query_failure_is_not_reported_as_unowned() {
        let directory = stub_dir();
        for manager in ["dpkg-query", "rpm", "apk", "pacman"] {
            write_stub(&directory, manager, "exit 1");
        }

        let output = run_with_stubs(probe("SHUV-EVID-PKG-001"), &directory);
        fs::remove_dir_all(directory).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(output.status.success());
        assert!(!stdout.contains("owner=unowned"));
        assert!(stdout.contains("UNAVAILABLE:"));
        assert!(!stdout.contains("owner="));
    }

    #[test]
    fn package_collector_selects_each_supported_native_database() {
        for selected in ["dpkg-query", "apk", "pacman", "rpm"] {
            let directory = stub_dir();
            for manager in ["dpkg-query", "apk", "pacman", "rpm"] {
                let body = if manager == selected {
                    "printf '%s\\n' fixture-owner"
                } else {
                    "exit 1"
                };
                write_stub(&directory, manager, body);
            }

            let output = run_with_stubs(probe("SHUV-EVID-PKG-001"), &directory);
            fs::remove_dir_all(directory).unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let expected = if selected == "dpkg-query" {
                "package_manager=dpkg"
            } else {
                &format!("package_manager={selected}")
            };

            assert!(output.status.success());
            assert!(stdout.contains(expected), "{selected}: {stdout}");
            assert!(stdout.contains("owner=fixture-owner"));
        }
    }

    #[test]
    fn successful_empty_package_query_is_reported_as_unresolved() {
        let directory = stub_dir();
        write_stub(
            &directory,
            "dpkg-query",
            "case \"$*\" in *shuvscan-probe-test-*/dpkg-query) printf '%s\\n' fixture-owner ;; *) : ;; esac",
        );
        for manager in ["rpm", "apk", "pacman"] {
            write_stub(&directory, manager, "exit 1");
        }

        let output = run_with_stubs(probe("SHUV-EVID-PKG-001"), &directory);
        fs::remove_dir_all(directory).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(output.status.success());
        assert!(stdout.contains("package_manager=dpkg"));
        assert!(stdout.contains("owner=unresolved"));
        assert!(!stdout.lines().any(|line| line.ends_with("owner=")));
    }

    #[test]
    fn socket_collector_reports_each_protocol_bound() {
        let directory = stub_dir();
        write_stub(
            &directory,
            "ss",
            "i=0; while [ \"$i\" -lt 20 ]; do printf 'tcp fixture-%s\\n' \"$i\"; i=$((i + 1)); done",
        );
        write_stub(&directory, "netstat", "exit 1");

        let output = run_with_stubs(probe("SHUV-EVID-NET-001"), &directory);
        fs::remove_dir_all(directory).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(output.status.success());
        assert!(stdout.contains("TRUNCATED: max_tcp_sockets=16"));
        assert!(stdout.contains("TRUNCATED: max_udp_sockets=16"));
    }

    #[test]
    fn process_sample_includes_pid_one() {
        let directory = stub_dir();
        let output = run_with_stubs(probe("SHUV-EVID-PROC-001"), &directory);
        fs::remove_dir_all(directory).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(output.status.success());
        assert!(
            stdout.lines().any(|line| line.starts_with("pid=1\t"))
                || stdout.contains("UNAVAILABLE:")
                || stdout.contains("PARTIAL:")
        );
    }

    #[test]
    fn namespace_collector_returns_evidence_or_an_explicit_status() {
        let directory = stub_dir();
        let output = run_with_stubs(probe("SHUV-EVID-NS-001"), &directory);
        fs::remove_dir_all(directory).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(output.status.success());
        assert!(
            stdout.lines().any(|line| line.starts_with("pid="))
                || stdout.contains("UNAVAILABLE:")
                || stdout.contains("PARTIAL:")
        );
    }

    #[test]
    fn container_collector_returns_cgroup_evidence_or_an_explicit_status() {
        let directory = stub_dir();
        let output = run_with_stubs(probe("SHUV-EVID-CONT-001"), &directory);
        fs::remove_dir_all(directory).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(output.status.success());
        assert!(
            stdout.lines().any(|line| line.starts_with("pid=1\t")) || stdout.contains("PARTIAL:")
        );
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
