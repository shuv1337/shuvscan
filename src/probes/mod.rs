use crate::model::{Evidence, Finding, Observation, RetainedEvidence, Severity};

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
    pub fn finding(&self, evaluation_output: &str, evidence: &RetainedEvidence) -> Option<Finding> {
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
            evidence_truncated: evidence.truncated,
            evidence_omitted_bytes: evidence.omitted_bytes,
            evidence_limit_bytes: evidence.limit_bytes,
            evidence: Evidence {
                command: self.script,
                output: evidence.output.clone(),
            },
        })
    }

    pub fn observation(
        &self,
        retained_evidence: &RetainedEvidence,
        partial: Option<String>,
        collection_limits: Vec<String>,
    ) -> Option<Observation> {
        matches!(self.kind, ProbeKind::Evidence).then_some(Observation {
            id: self.id,
            title: self.title,
            category: self.category,
            partial,
            truncated: retained_evidence.truncated || !collection_limits.is_empty(),
            collection_limits,
            evidence_budget_exceeded: retained_evidence.truncated,
            evidence: Evidence {
                command: self.script,
                output: retained_evidence.output.clone(),
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

/// Shared bounded process sampler used by the `/proc`-walking evidence probes.
/// Leaves `$shuvscan_pids` holding the 12 lowest and 12 highest live user-space
/// PIDs plus a trailing `SHUVSCAN_MORE` sentinel when the host has more.
///
/// Kernel threads (`PF_KTHREAD` in the `/proc/<pid>/stat` flags field) and
/// zombies have no executable, command line, or namespaces worth retaining;
/// sampling them only manufactured `skipped_unreadable_*` partials on every
/// root scan because their `exe` links do not exist. A `stat` that cannot be
/// read keeps the PID in the sample so the probe reports it as unreadable.
///
/// Expands to `concat!($before, <sampler>, $after)` so each probe script stays
/// one `&'static str`.
macro_rules! with_process_sample {
    ($before:literal, $after:literal) => {
        concat!(
            $before,
            r#"shuvscan_pids=$(for shuvscan_path in /proc/[0-9]*; do
  if IFS= read -r shuvscan_stat < "$shuvscan_path/stat"; then
    shuvscan_stat=${shuvscan_stat##*') '}
    set -f
    set -- $shuvscan_stat
    set +f
    case "$1" in Z) continue ;; esac
    case "$7" in ''|*[!0-9]*) ;; *) [ $(( ($7 / 2097152) % 2 )) -eq 0 ] || continue ;; esac
  elif [ ! -d "$shuvscan_path" ]; then
    continue
  fi
  printf '%s\n' "${shuvscan_path#/proc/}"
done 2>/dev/null | sort -n | awk 'NR <= 12 {low[NR]=$0} {high[(NR-1)%12]=$0} END {for(i=1;i<=NR && i<=12;i++) print low[i]; start=NR-11; if(start<13) start=13; for(i=start;i<=NR;i++) print high[(i-1)%12]; if(NR>24) print "SHUVSCAN_MORE"}')"#,
            $after
        )
    };
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
  printf '%s\n' "$cfg" | awk 'tolower($1) == "permitrootlogin" && tolower($2) != "no"'
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
  printf '%s\n' "$cfg" | awk 'tolower($1) == "passwordauthentication" && tolower($2) == "yes"'
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
        privilege: Privilege::RootRecommended,
        script: r#"for d in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
  if [ -e "$d" ] && ! find "$d" -xdev -perm -0002 \( -type f -o -type d \) -print 2>/dev/null; then
    printf '%s could not completely inspect %s\n' "$SHUVSCAN_PARTIAL" "$d"
  fi
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
  if [ -d "$d" ]; then
    if ! find -H "$d" -xdev \( -type f -o -type l \) -exec sh -c '
      find -H "$@" -xdev \( ! -type f -prune -o -perm -0002 -print \) 2>/dev/null
    ' sh {} +; then
      printf '%s could not completely inspect %s\n' "$SHUVSCAN_PARTIAL" "$d"
    fi
  elif [ -L "$d" ]; then
    printf '%s could not resolve %s\n' "$SHUVSCAN_PARTIAL" "$d"
  fi
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
        title: "Effective root set-ID executable in a temporary directory",
        category: "filesystem",
        description: "An executable can assume UID 0 or GID 0 through set-ID bits on a world-writable temporary filesystem.",
        required_tools: &["awk", "find"],
        privilege: Privilege::Unprivileged,
        script: r#"for d in /tmp /var/tmp /dev/shm; do
  [ -d "$d" ] || continue
  if [ ! -r /proc/self/mountinfo ]; then
    printf '%s could not read mount options for %s\n' "$SHUVSCAN_PARTIAL" "$d"
    continue
  fi
  if ! shuvscan_root=$(CDPATH= cd "$d" 2>/dev/null && pwd -P); then
    printf '%s could not resolve %s\n' "$SHUVSCAN_PARTIAL" "$d"
    continue
  fi
  exec 3>&1
  shuvscan_find_errors=$(find "$shuvscan_root" -xdev -type f \
    \( -perm -0100 -o -perm -0010 -o -perm -0001 \) \
    \( \( -user 0 -perm -4000 \) -o \( -group 0 -perm -2000 \) \) \
    -exec sh -c '
      shuvscan_mount_options_for() {
        shuvscan_mount_target=$1
        shuvscan_mount_best=-1
        shuvscan_mount_result=
        while IFS=" " read -r shuvscan_mount_id shuvscan_mount_parent shuvscan_mount_device shuvscan_mount_root shuvscan_mount_point shuvscan_mount_options shuvscan_mount_rest; do
          shuvscan_mount_point=$(printf "%b" "$shuvscan_mount_point") || continue
          shuvscan_mount_matches=0
          if [ "$shuvscan_mount_point" = / ]; then
            shuvscan_mount_matches=1
          else
            case "$shuvscan_mount_target" in
            "$shuvscan_mount_point"|"$shuvscan_mount_point"/*) shuvscan_mount_matches=1 ;;
            esac
          fi
          if [ "$shuvscan_mount_matches" -eq 1 ] && [ "${#shuvscan_mount_point}" -ge "$shuvscan_mount_best" ]; then
            shuvscan_mount_best=${#shuvscan_mount_point}
            shuvscan_mount_result=$shuvscan_mount_options
          fi
        done < /proc/self/mountinfo
        [ "$shuvscan_mount_best" -ge 0 ] || return 1
        printf "%s\n" "$shuvscan_mount_result"
      }

      shuvscan_failed=0
      for shuvscan_candidate do
        if ! shuvscan_mount_options=$(shuvscan_mount_options_for "$shuvscan_candidate" 2>/dev/null) || [ -z "$shuvscan_mount_options" ]; then
          shuvscan_failed=1
          continue
        fi
        case ",$shuvscan_mount_options," in
        *,nosuid,*|*,noexec,*) continue ;;
        esac
        printf "%s\n" "$shuvscan_candidate"
      done
      [ "$shuvscan_failed" -eq 0 ] || printf "shuvscan: could not resolve mount options for every candidate\n" >&2
      exit "$shuvscan_failed"
    ' sh {} + 2>&1 1>&3 3>&-)
  shuvscan_find_status=$?
  exec 3>&-
  [ "$shuvscan_find_status" -ne 0 ] || continue
  if [ -z "$shuvscan_find_errors" ]; then
    printf '%s could not completely inspect %s\n' "$SHUVSCAN_PARTIAL" "$d"
    continue
  fi
  if ! shuvscan_unexplained=$(SHUVSCAN_ROOT="$shuvscan_root" SHUVSCAN_FIND_ERRORS="$shuvscan_find_errors" awk '
    {
      mp = $5
      out = ""
      while (match(mp, /\\[0-7][0-7][0-7]/)) {
        out = out substr(mp, 1, RSTART - 1)
        code = substr(mp, RSTART + 1, 3)
        val = 0
        for (i = 1; i <= 3; i++) val = val * 8 + (substr(code, i, 1) + 0)
        out = out sprintf("%c", val)
        mp = substr(mp, RSTART + 4)
      }
      mounts[out mp] = 1
    }
    END {
      root = ENVIRON["SHUVSCAN_ROOT"]
      n = split(ENVIRON["SHUVSCAN_FIND_ERRORS"], lines, "\n")
      for (i = 1; i <= n; i++) {
        line = lines[i]
        if (line == "") continue
        if (substr(line, 1, 6) != "find: " || substr(line, length(line) - 18) != ": Permission denied") {
          print line
          continue
        }
        path = substr(line, 7, length(line) - 25)
        if (substr(path, 1, 1) == "\047" && substr(path, length(path)) == "\047") path = substr(path, 2, length(path) - 2)
        if (substr(path, 1, length(root) + 1) != root "/" || !(path in mounts)) print line
      }
    }' /proc/self/mountinfo) || [ -n "$shuvscan_unexplained" ]; then
    printf '%s could not completely inspect %s\n' "$SHUVSCAN_PARTIAL" "$d"
  fi
done
:"#,
        kind: ProbeKind::Detection {
            severity: Severity::Critical,
            remediation: "Capture the executable for analysis, remove it, and hunt for the process or account that created it.",
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
        script: r#"if ! cat /proc/sys/kernel/kptr_restrict 2>/dev/null; then
  printf '%s /proc/sys/kernel/kptr_restrict is unreadable\n' "$SHUVSCAN_UNAVAILABLE"
fi"#,
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
        script: r#"if ! cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null; then
  printf '%s /proc/sys/kernel/unprivileged_bpf_disabled is unreadable\n' "$SHUVSCAN_UNAVAILABLE"
fi"#,
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
        script: r#"shuvscan_seen=
for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
  if [ -d "$d" ]; then
    shuvscan_duplicate=0
    for shuvscan_previous in $shuvscan_seen; do
      if [ "$d" -ef "$shuvscan_previous" ]; then
        shuvscan_duplicate=1
        break
      fi
    done
    [ "$shuvscan_duplicate" -eq 0 ] || continue
    shuvscan_seen="$shuvscan_seen $d"
    if ! find -H "$d" -maxdepth 0 -perm -0002 -print 2>/dev/null; then
      printf '%s could not inspect %s\n' "$SHUVSCAN_PARTIAL" "$d"
    fi
  elif [ -L "$d" ]; then
    printf '%s could not resolve %s as an executable directory\n' "$SHUVSCAN_PARTIAL" "$d"
  fi
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
        script: with_process_sample!(
            r#"shuvscan_package_manager=
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
"#,
            r#"
for shuvscan_pid in $shuvscan_pids; do
  if [ "$shuvscan_pid" = SHUVSCAN_MORE ]; then
    printf '%s low_high_process_sample=24\n' "$SHUVSCAN_TRUNCATED"
    break
  fi
  shuvscan_target=$(readlink "/proc/$shuvscan_pid/exe" 2>/dev/null) || {
    [ ! -d "/proc/$shuvscan_pid" ] || shuvscan_skipped=$((shuvscan_skipped + 1))
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
:"#
        ),
        kind: ProbeKind::Evidence,
    },
    Probe {
        id: "SHUV-EVID-PROC-001",
        title: "Sampled PID and parent PID pairs",
        category: "process",
        description: "Records PID, parent PID, real and effective UIDs, name, and command line for a bounded process sample.",
        required_tools: &["awk", "sort", "tr"],
        privilege: Privilege::RootRecommended,
        script: with_process_sample!(
            r#"[ -d /proc ] || {
  printf '%s /proc is unavailable\n' "$SHUVSCAN_UNAVAILABLE"
  exit 0
}
shuvscan_skipped=0
"#,
            r#"
for shuvscan_pid in $shuvscan_pids; do
  if [ "$shuvscan_pid" = SHUVSCAN_MORE ]; then
    printf '%s low_high_process_sample=24\n' "$SHUVSCAN_TRUNCATED"
    break
  fi
  shuvscan_status=/proc/$shuvscan_pid/status
  if [ ! -r "$shuvscan_status" ]; then
    [ ! -d "/proc/$shuvscan_pid" ] || shuvscan_skipped=$((shuvscan_skipped + 1))
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
:"#
        ),
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
        script: with_process_sample!(
            r#"if [ ! -d /proc/self/ns ]; then
  printf '%s Linux namespace links are unavailable\n' "$SHUVSCAN_UNAVAILABLE"
  exit 0
fi
shuvscan_skipped=0
"#,
            r#"
for shuvscan_pid in $shuvscan_pids; do
  if [ "$shuvscan_pid" = SHUVSCAN_MORE ]; then
    printf '%s low_high_process_sample=24\n' "$SHUVSCAN_TRUNCATED"
    break
  fi
  shuvscan_nsdir=/proc/$shuvscan_pid/ns
  shuvscan_mnt=$(readlink "$shuvscan_nsdir/mnt" 2>/dev/null) || {
    [ ! -d "/proc/$shuvscan_pid" ] || shuvscan_skipped=$((shuvscan_skipped + 1))
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
:"#
        ),
        kind: ProbeKind::Evidence,
    },
    Probe {
        id: "SHUV-EVID-CONT-001",
        title: "Container and cgroup context",
        category: "container",
        description: "Records host container markers and bounded process cgroup memberships without entering namespaces.",
        required_tools: &["awk", "sort", "tr"],
        privilege: Privilege::RootRecommended,
        script: with_process_sample!(
            r#"[ ! -e /.dockerenv ] || printf 'host_marker=/.dockerenv\n'
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
"#,
            r#"
for shuvscan_pid in $shuvscan_pids; do
  if [ "$shuvscan_pid" = SHUVSCAN_MORE ]; then
    printf '%s low_high_process_sample=24\n' "$SHUVSCAN_TRUNCATED"
    break
  fi
  shuvscan_cgroup=/proc/$shuvscan_pid/cgroup
  if [ ! -r "$shuvscan_cgroup" ]; then
    [ ! -d "/proc/$shuvscan_pid" ] || shuvscan_skipped=$((shuvscan_skipped + 1))
    continue
  fi
  shuvscan_membership=$(tr '\n\t' '; ' < "$shuvscan_cgroup" 2>/dev/null)
  shuvscan_membership=${shuvscan_membership%';'}
  printf 'pid=%s\tcgroup=%s\n' "$shuvscan_pid" "$shuvscan_membership"
done
[ "$shuvscan_skipped" -eq 0 ] || printf '%s skipped_unreadable_cgroups=%s\n' "$SHUVSCAN_PARTIAL" "$shuvscan_skipped"
:"#
        ),
        kind: ProbeKind::Evidence,
    },
];

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
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
        run_script_with_stubs(probe.script, directory)
    }

    fn run_script_with_stubs(script: &str, directory: &Path) -> std::process::Output {
        let path = format!(
            "{}:{}",
            directory.display(),
            env::var("PATH").unwrap_or_default()
        );
        Command::new("sh")
            .args(["-c", script])
            .env("PATH", path)
            .env("LC_ALL", "C")
            .env("SHUVSCAN_UNAVAILABLE", "UNAVAILABLE:")
            .env("SHUVSCAN_PARTIAL", "PARTIAL:")
            .env("SHUVSCAN_TRUNCATED", "TRUNCATED:")
            .output()
            .unwrap()
    }

    fn run_systemd_unit_probe(directory: &Path, roots: &[&Path]) -> std::process::Output {
        const ROOTS: &str =
            "/etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system";
        let roots = roots
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let script = probe("SHUV-FS-001").script.replacen(ROOTS, &roots, 1);
        assert_ne!(script, probe("SHUV-FS-001").script);
        run_script_with_stubs(&script, directory)
    }

    fn run_temp_setid_probe(
        directory: &Path,
        root: &Path,
        mount_options: &str,
        privileged_uid: u32,
        privileged_gid: u32,
    ) -> std::process::Output {
        let effective_root = fs::canonicalize(root).unwrap();
        let mountinfo = format!(
            "1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / {} {mount_options} - tmpfs tmpfs {mount_options}\n",
            effective_root.display()
        );
        run_temp_setid_probe_with_mountinfo(
            directory,
            root,
            &mountinfo,
            privileged_uid,
            privileged_gid,
        )
    }

    fn run_temp_setid_probe_with_mountinfo(
        directory: &Path,
        root: &Path,
        mountinfo_contents: &str,
        privileged_uid: u32,
        privileged_gid: u32,
    ) -> std::process::Output {
        const ROOTS: &str = "/tmp /var/tmp /dev/shm";
        const MOUNTINFO: &str = "/proc/self/mountinfo";

        let mountinfo = directory.join("mountinfo");
        fs::write(&mountinfo, mountinfo_contents).unwrap();
        let script = probe("SHUV-FS-002")
            .script
            .replacen(ROOTS, root.to_str().unwrap(), 1)
            .replace(MOUNTINFO, mountinfo.to_str().unwrap())
            .replace("-user 0", &format!("-user {privileged_uid}"))
            .replace("-group 0", &format!("-group {privileged_gid}"));
        assert_ne!(script, probe("SHUV-FS-002").script);
        run_script_with_stubs(&script, directory)
    }

    fn write_file_with_mode(path: &Path, mode: u32) {
        fs::write(path, "fixture\n").unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions).unwrap();
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
    fn root_login_probe_flags_every_mode_except_disabled() {
        for (mode, expected_finding) in [
            ("no", false),
            ("yes", true),
            ("prohibit-password", true),
            ("forced-commands-only", true),
        ] {
            let directory = stub_dir();
            write_stub(
                &directory,
                "sshd",
                &format!("printf 'permitrootlogin %s\\n' '{mode}'"),
            );
            let output = run_with_stubs(probe("SHUV-AUTH-002"), &directory);
            fs::remove_dir_all(directory).unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();

            assert!(output.status.success());
            assert_eq!(
                !stdout.trim().is_empty(),
                expected_finding,
                "{mode}: {stdout}"
            );
        }
    }

    #[test]
    fn ssh_probes_match_canonical_case_sshd_keywords() {
        // OpenSSH 10.x `sshd -T` prints keywords in canonical case
        // (`PermitRootLogin prohibit-password`); a case-sensitive matcher
        // would silently report a clean result for an exposed daemon.
        let directory = stub_dir();
        write_stub(
            &directory,
            "sshd",
            "printf 'PermitRootLogin prohibit-password\\nPasswordAuthentication yes\\n'",
        );
        for id in ["SHUV-AUTH-002", "SHUV-AUTH-003"] {
            let output = run_with_stubs(probe(id), &directory);
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(output.status.success());
            assert!(
                !stdout.trim().is_empty(),
                "{id} missed canonical-case sshd -T output: {stdout:?}"
            );
        }
        fs::remove_dir_all(directory).unwrap();
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
                    .finding(
                        "arbitrary output",
                        &crate::model::truncate_evidence("arbitrary output".into(), 1024)
                    )
                    .is_none()
            );
            assert!(
                probe
                    .observation(
                        &crate::model::truncate_evidence("inventory".into(), 1024),
                        None,
                        Vec::new()
                    )
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
    fn unreadable_kernel_controls_are_explicitly_unavailable() {
        let directory = stub_dir();
        write_stub(&directory, "cat", "exit 1");

        for id in ["SHUV-KERN-001", "SHUV-KERN-002"] {
            let output = run_with_stubs(probe(id), &directory);
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(output.status.success());
            assert!(stdout.contains("UNAVAILABLE:"), "{id}: {stdout}");
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_filesystem_walks_are_explicitly_partial() {
        let directory = stub_dir();
        write_stub(&directory, "find", "exit 1");

        for id in ["SHUV-PERSIST-002", "SHUV-FS-001", "SHUV-EXEC-001"] {
            let output = run_with_stubs(probe(id), &directory);
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(output.status.success());
            assert!(stdout.contains("PARTIAL:"), "{id}: {stdout}");
        }

        let root = directory.join("temporary-root");
        fs::create_dir(&root).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let output = run_temp_setid_probe(&directory, &root, "rw", metadata.uid(), metadata.gid());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(output.status.success());
        assert!(stdout.contains("PARTIAL:"), "SHUV-FS-002: {stdout}");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn temp_setid_probe_tolerates_unreadable_nested_mount_points() {
        let directory = stub_dir();
        let root = directory.join("temporary-root");
        fs::create_dir(&root).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let effective_root = fs::canonicalize(&root).unwrap();
        let effective_root = effective_root.to_str().unwrap();
        let base = format!(
            "1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / {effective_root} rw - tmpfs tmpfs rw\n"
        );

        let run = |error_line: &str, mountinfo: &str| {
            write_stub(
                &directory,
                "find",
                &format!("printf '%s\\n' \"{error_line}\" >&2\nexit 1"),
            );
            let output = run_temp_setid_probe_with_mountinfo(
                &directory,
                &root,
                mountinfo,
                metadata.uid(),
                metadata.gid(),
            );
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap()
        };

        // A `Permission denied` on a foreign mount point strictly below the
        // root is what `-xdev` would have skipped anyway: not partial.
        let denied_mount = format!("find: '{effective_root}/.mount_app': Permission denied");
        let foreign =
            format!("{base}3 2 0:73 / {effective_root}/.mount_app ro,nosuid - fuse.app app ro\n");
        let stdout = run(&denied_mount, &foreign);
        assert!(stdout.trim().is_empty(), "{stdout}");

        // Same, with an octal-escaped mount point and an unquoted (BusyBox) message.
        let denied_spaced = format!("find: {effective_root}/mount dir: Permission denied");
        let spaced = format!(
            "{base}3 2 0:74 / {effective_root}/mount\\040dir ro,nosuid - fuse.app app ro\n"
        );
        let stdout = run(&denied_spaced, &spaced);
        assert!(stdout.trim().is_empty(), "{stdout}");

        // The same path when it is not a mount point is a real coverage gap.
        let stdout = run(&denied_mount, &base);
        assert!(stdout.contains("PARTIAL:"), "{stdout}");

        // A non-permission failure on a mount point is still a real failure.
        let stale = format!("find: '{effective_root}/.mount_app': Stale file handle");
        let stdout = run(&stale, &foreign);
        assert!(stdout.contains("PARTIAL:"), "{stdout}");

        // The walked root itself failing is never explained by mountinfo.
        let denied_root = format!("find: '{effective_root}': Permission denied");
        let stdout = run(&denied_root, &foreign);
        assert!(stdout.contains("PARTIAL:"), "{stdout}");

        // A mount point that is not below the root does not explain anything.
        let denied_sibling = format!("find: '{effective_root}-other': Permission denied");
        let sibling =
            format!("{base}3 1 0:75 / {effective_root}-other ro,nosuid - fuse.app app ro\n");
        let stdout = run(&denied_sibling, &sibling);
        assert!(stdout.contains("PARTIAL:"), "{stdout}");

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn temp_setid_probe_rejects_manufactured_mode_bits() {
        let directory = stub_dir();
        let root = directory.join("temporary-root");
        fs::create_dir(&root).unwrap();
        for (name, mode) in [
            ("ordinary", 0o700),
            ("self-setuid", 0o4700),
            ("owned-group-setgid", 0o2750),
            ("non-executable-setuid", 0o4600),
            ("non-executable-setgid", 0o2640),
        ] {
            write_file_with_mode(&root.join(name), mode);
        }
        let metadata = fs::metadata(&root).unwrap();
        let privileged_uid = u32::from(metadata.uid() == 0);
        let privileged_gid = u32::from(metadata.gid() == 0);

        let output = run_temp_setid_probe(&directory, &root, "rw", privileged_uid, privileged_gid);
        let stdout = String::from_utf8(output.stdout).unwrap();
        fs::remove_dir_all(directory).unwrap();

        assert!(output.status.success());
        assert!(stdout.trim().is_empty(), "{stdout}");
    }

    #[test]
    fn temp_setid_probe_reports_effective_root_identity_changes() {
        let directory = stub_dir();
        let root = directory.join("temporary-root");
        fs::create_dir(&root).unwrap();
        write_file_with_mode(&root.join("root-setuid"), 0o4700);
        write_file_with_mode(&root.join("root-group-setgid"), 0o2700);
        let metadata = fs::metadata(&root).unwrap();

        let output = run_temp_setid_probe(&directory, &root, "rw", metadata.uid(), metadata.gid());
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(output.status.success());
        assert!(stdout.contains("root-setuid"), "{stdout}");
        assert!(stdout.contains("root-group-setgid"), "{stdout}");

        let different_uid = u32::from(metadata.uid() == 0);
        let output = run_temp_setid_probe(&directory, &root, "rw", different_uid, metadata.gid());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(output.status.success());
        assert!(!stdout.contains("root-setuid"), "{stdout}");
        assert!(stdout.contains("root-group-setgid"), "{stdout}");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn temp_setid_probe_ignores_ineffective_mounts() {
        let directory = stub_dir();
        let root = directory.join("temporary-root");
        fs::create_dir(&root).unwrap();
        write_file_with_mode(&root.join("root-setuid"), 0o4700);
        let metadata = fs::metadata(&root).unwrap();

        for mount_options in ["rw,nosuid", "rw,noexec"] {
            let output = run_temp_setid_probe(
                &directory,
                &root,
                mount_options,
                metadata.uid(),
                metadata.gid(),
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(output.status.success());
            assert!(stdout.trim().is_empty(), "{mount_options}: {stdout}");
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn temp_setid_probe_checks_each_candidates_effective_mount() {
        let directory = stub_dir();
        let root = directory.join("temporary-root");
        let nested = root.join("nested-bind");
        fs::create_dir_all(&nested).unwrap();
        let root_candidate = root.join("root-setuid");
        let nested_candidate = nested.join("nested-root-setuid");
        write_file_with_mode(&root_candidate, 0o4700);
        write_file_with_mode(&nested_candidate, 0o4700);
        let metadata = fs::metadata(&root).unwrap();

        let mountinfo = format!(
            "1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / {} rw - tmpfs tmpfs rw\n3 2 0:2 / {} rw,nosuid - tmpfs tmpfs rw,nosuid\n",
            root.display(),
            nested.display()
        );
        let output = run_temp_setid_probe_with_mountinfo(
            &directory,
            &root,
            &mountinfo,
            metadata.uid(),
            metadata.gid(),
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(output.status.success());
        assert!(
            stdout
                .lines()
                .any(|line| line == root_candidate.to_str().unwrap())
        );
        assert!(
            !stdout
                .lines()
                .any(|line| line == nested_candidate.to_str().unwrap())
        );

        let mountinfo = format!(
            "1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / {} rw,nosuid - tmpfs tmpfs rw,nosuid\n3 2 0:2 / {} rw - tmpfs tmpfs rw\n",
            root.display(),
            nested.display()
        );
        let output = run_temp_setid_probe_with_mountinfo(
            &directory,
            &root,
            &mountinfo,
            metadata.uid(),
            metadata.gid(),
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(output.status.success());
        assert!(
            !stdout
                .lines()
                .any(|line| line == root_candidate.to_str().unwrap())
        );
        assert!(
            stdout
                .lines()
                .any(|line| line == nested_candidate.to_str().unwrap())
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn temp_setid_probe_decodes_mountinfo_paths() {
        let directory = stub_dir();
        let root = directory.join("temporary-root");
        let nested = root.join("nested bind");
        fs::create_dir_all(&nested).unwrap();
        let candidate = nested.join("root-setuid");
        write_file_with_mode(&candidate, 0o4700);
        let metadata = fs::metadata(&root).unwrap();
        let escaped_nested = nested.display().to_string().replace(' ', "\\040");
        let mountinfo = format!(
            "1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / {} rw - tmpfs tmpfs rw\n3 2 0:2 / {escaped_nested} rw,nosuid - tmpfs tmpfs rw,nosuid\n",
            root.display()
        );

        let output = run_temp_setid_probe_with_mountinfo(
            &directory,
            &root,
            &mountinfo,
            metadata.uid(),
            metadata.gid(),
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        fs::remove_dir_all(directory).unwrap();

        assert!(output.status.success());
        assert!(
            !stdout
                .lines()
                .any(|line| line == candidate.to_str().unwrap())
        );
    }

    #[test]
    fn temp_setid_probe_follows_a_symlinked_root() {
        use std::os::unix::fs::symlink;

        let directory = stub_dir();
        let root = directory.join("effective-root");
        let root_link = directory.join("temporary-root-link");
        fs::create_dir(&root).unwrap();
        symlink(&root, &root_link).unwrap();
        let candidate = root.join("root-setuid");
        write_file_with_mode(&candidate, 0o4700);
        let metadata = fs::metadata(&root).unwrap();

        let output =
            run_temp_setid_probe(&directory, &root_link, "rw", metadata.uid(), metadata.gid());
        let stdout = String::from_utf8(output.stdout).unwrap();
        fs::remove_dir_all(directory).unwrap();

        assert!(output.status.success());
        assert!(
            stdout
                .lines()
                .any(|line| line == candidate.to_str().unwrap())
        );
    }

    #[test]
    fn temp_setid_probe_reports_unknown_mount_options_as_partial() {
        const ROOTS: &str = "/tmp /var/tmp /dev/shm";
        const MOUNTINFO: &str = "/proc/self/mountinfo";

        let directory = stub_dir();
        let root = directory.join("temporary-root");
        fs::create_dir(&root).unwrap();
        let missing_mountinfo = directory.join("missing-mountinfo");
        let script = probe("SHUV-FS-002")
            .script
            .replacen(ROOTS, root.to_str().unwrap(), 1)
            .replace(MOUNTINFO, missing_mountinfo.to_str().unwrap());

        let output = run_script_with_stubs(&script, &directory);
        let stdout = String::from_utf8(output.stdout).unwrap();
        fs::remove_dir_all(directory).unwrap();

        assert!(output.status.success());
        assert!(stdout.contains("PARTIAL:"), "{stdout}");
        assert!(stdout.contains("mount options"), "{stdout}");
    }

    #[test]
    fn systemd_unit_probe_checks_symlinked_roots_and_unit_files() {
        use std::os::unix::fs::symlink;

        let directory = stub_dir();
        let effective_root = directory.join("effective-root");
        let lexical_root = directory.join("lexical-root");
        let outside = directory.join("outside");
        let linked_directory = directory.join("linked-directory");
        for path in [&effective_root, &lexical_root, &outside, &linked_directory] {
            fs::create_dir(path).unwrap();
        }

        let root_target = effective_root.join("root-link.service");
        let unit_target = outside.join("unit-link.service");
        let safe_target = outside.join("safe-link.service");
        let unrelated_target = linked_directory.join("not-a-unit.service");
        for path in [&root_target, &unit_target, &safe_target, &unrelated_target] {
            fs::write(path, "[Service]\n").unwrap();
        }
        for path in [&root_target, &unit_target, &unrelated_target] {
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o666);
            fs::set_permissions(path, permissions).unwrap();
        }

        let root_link = directory.join("root-link");
        symlink(&effective_root, &root_link).unwrap();
        symlink(&unit_target, lexical_root.join("unit-link.service")).unwrap();
        symlink(&safe_target, lexical_root.join("safe-link.service")).unwrap();
        symlink(&linked_directory, lexical_root.join("not-a-unit-directory")).unwrap();
        symlink("missing.service", lexical_root.join("dangling.service")).unwrap();
        symlink("/dev/null", lexical_root.join("masked.service")).unwrap();

        let output = run_systemd_unit_probe(&directory, &[&root_link, &lexical_root]);
        let stdout = String::from_utf8(output.stdout).unwrap();
        fs::remove_dir_all(directory).unwrap();

        assert!(output.status.success());
        assert!(stdout.contains(root_link.join("root-link.service").to_str().unwrap()));
        assert!(stdout.contains(lexical_root.join("unit-link.service").to_str().unwrap()));
        assert!(!stdout.contains("safe-link.service"));
        assert!(!stdout.contains("not-a-unit.service"));
        assert!(!stdout.contains("dangling.service"));
        assert!(!stdout.contains("masked.service"));
        assert!(!stdout.contains("PARTIAL:"));
    }

    #[test]
    fn systemd_unit_probe_batches_target_checks() {
        let directory = stub_dir();
        let root = directory.join("root");
        fs::create_dir(&root).unwrap();
        for index in 0..256 {
            fs::write(root.join(format!("fixture-{index}.service")), "[Service]\n").unwrap();
        }
        let count_file = directory.join("find-count");
        write_stub(
            &directory,
            "find",
            &format!(
                "count=0; [ ! -f '{0}' ] || count=$(cat '{0}'); count=$((count + 1)); printf '%s' \"$count\" > '{0}'; exec /usr/bin/find \"$@\"",
                count_file.display()
            ),
        );

        let output = run_systemd_unit_probe(&directory, &[&root]);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let calls: usize = fs::read_to_string(&count_file).unwrap().parse().unwrap();
        fs::remove_dir_all(directory).unwrap();

        assert!(output.status.success(), "{stdout}");
        assert!(calls <= 3, "expected batched find calls, observed {calls}");
    }

    #[test]
    fn systemd_unit_probe_reports_symlink_loops_as_partial() {
        use std::os::unix::fs::symlink;

        let directory = stub_dir();
        let root = directory.join("root");
        fs::create_dir(&root).unwrap();
        symlink("loop.service", root.join("loop.service")).unwrap();

        let output = run_systemd_unit_probe(&directory, &[&root]);
        let stdout = String::from_utf8(output.stdout).unwrap();
        fs::remove_dir_all(directory).unwrap();

        assert!(output.status.success());
        assert!(stdout.contains("PARTIAL:"), "{stdout}");
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
    fn process_sample_excludes_kernel_threads_and_zombies() {
        const PF_KTHREAD: u64 = 0x0020_0000;

        fn stat_fields(pid: &str) -> Option<(String, u64)> {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let rest = stat.rsplit_once(") ")?.1;
            let mut fields = rest.split_whitespace();
            let state = fields.next()?.to_string();
            let flags = fields.nth(5)?.parse().ok()?;
            Some((state, flags))
        }

        let directory = stub_dir();
        let output = run_with_stubs(probe("SHUV-EVID-PROC-001"), &directory);
        fs::remove_dir_all(directory).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(output.status.success());

        let sampled = stdout
            .lines()
            .filter_map(|line| line.strip_prefix("pid="))
            .map(|rest| rest.split('\t').next().unwrap().to_string())
            .collect::<Vec<_>>();
        assert!(
            !sampled.is_empty() || stdout.contains("UNAVAILABLE:") || stdout.contains("PARTIAL:")
        );
        for pid in &sampled {
            // A process may legitimately exit between sampling and this check.
            if let Some((state, flags)) = stat_fields(pid) {
                assert_ne!(state, "Z", "zombie pid {pid} sampled: {stdout}");
                assert_eq!(
                    flags & PF_KTHREAD,
                    0,
                    "kernel thread pid {pid} sampled: {stdout}"
                );
            }
        }
        if let Some((_, flags)) = stat_fields("2") {
            if flags & PF_KTHREAD != 0 {
                assert!(!sampled.iter().any(|pid| pid == "2"), "{stdout}");
            }
        }
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
