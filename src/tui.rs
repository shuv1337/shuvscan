use std::{
    collections::HashSet,
    io::{self, IsTerminal, Read, Write},
    os::fd::AsRawFd,
};

use crate::{model::ScanReport, output::terminal_safe};

/// Keyboard-driven viewer for completed scan reports.
///
/// The state machine and renderer are pure so they can be unit-tested without a
/// tty. Raw-mode I/O lives in [`run`].
pub struct Viewer<'a> {
    reports: &'a [ScanReport],
    target: usize,
    selected: usize,
    scroll: usize,
    expanded: Vec<HashSet<usize>>,
    help: bool,
    last_body_height: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    Enter,
    Tab,
    BackTab,
    Esc,
    CtrlC,
    Char(char),
}

impl<'a> Viewer<'a> {
    pub fn new(reports: &'a [ScanReport]) -> Self {
        Self {
            reports,
            target: 0,
            selected: 0,
            scroll: 0,
            expanded: reports.iter().map(|_| HashSet::new()).collect(),
            help: false,
            last_body_height: 10,
        }
    }

    pub fn handle(&mut self, key: Key) -> bool {
        if self.help {
            return match key {
                Key::Esc | Key::Char('?') => {
                    self.help = false;
                    true
                }
                Key::Char('q') | Key::CtrlC => false,
                _ => true,
            };
        }
        match key {
            Key::Char('q') | Key::CtrlC | Key::Esc => false,
            Key::Char('?') => {
                self.help = true;
                true
            }
            Key::Down | Key::Char('j') => {
                self.move_selection(1);
                true
            }
            Key::Up | Key::Char('k') => {
                self.move_selection(-1);
                true
            }
            Key::PageDown => {
                self.move_selection(self.page_step() as isize);
                true
            }
            Key::PageUp => {
                self.move_selection(-(self.page_step() as isize));
                true
            }
            Key::Home | Key::Char('g') => {
                self.selected = 0;
                self.scroll = 0;
                true
            }
            Key::End | Key::Char('G') => {
                self.selected = self.row_count().saturating_sub(1);
                true
            }
            Key::Enter | Key::Char(' ') | Key::Char('l') | Key::Char('h') => {
                self.toggle_expanded();
                true
            }
            Key::Tab | Key::Right | Key::Char(']') => {
                self.shift_target(1);
                true
            }
            Key::BackTab | Key::Left | Key::Char('[') => {
                self.shift_target(-1);
                true
            }
            Key::Char(_) => true,
        }
    }

    /// Render `height` lines of `width` columns. The selected row is kept in
    /// view. Lines are truncated to `width` by Unicode scalar count.
    pub fn frame(&mut self, width: usize, height: usize) -> Vec<String> {
        let width = width.max(1);
        let height = height.max(1);
        let header = self.header_lines();
        let footer = vec![self.footer_line()];
        let chrome = header.len() + footer.len();
        let body_height = height.saturating_sub(chrome);
        self.last_body_height = body_height.max(1);
        let body = if self.help {
            help_lines()
        } else {
            self.body_lines()
        };
        self.follow_selection(&body, body_height);
        let mut lines = Vec::with_capacity(height);
        for line in &header {
            lines.push(fit(line, width));
        }
        let start = self.scroll.min(
            body.len()
                .saturating_sub(body_height.max(1))
                .min(body.len()),
        );
        let end = (start + body_height).min(body.len());
        for line in &body[start..end] {
            lines.push(fit(line, width));
        }
        while lines.len() + footer.len() < height {
            lines.push(String::new());
        }
        for line in &footer {
            lines.push(fit(line, width));
        }
        lines.truncate(height);
        lines
    }

    pub fn selected_line(&self, lines: &[String]) -> Option<usize> {
        if self.help {
            return None;
        }
        let header = self.header_lines().len();
        let body = self.body_lines();
        let anchor = self.selected_anchor(&body)?;
        let index = header + anchor.saturating_sub(self.scroll);
        (index < lines.len().saturating_sub(1)).then_some(index)
    }

    fn header_lines(&self) -> Vec<String> {
        let Some(report) = self.reports.get(self.target) else {
            return vec!["shuvscan  (no reports)".into()];
        };
        let mut lines = vec![format!(
            "shuvscan {}  target {}/{}  {}",
            terminal_safe(report.scanner_version),
            self.target + 1,
            self.reports.len(),
            terminal_safe(&report.target)
        )];
        if let Some(pack) = &report.probe_pack {
            lines.push(format!(
                "pack {}@{}  signer={}",
                terminal_safe(&pack.id),
                terminal_safe(&pack.version),
                terminal_safe(&pack.signer)
            ));
        }
        if let Some(host) = &report.host {
            lines.push(format!(
                "host {}  kernel {}  {}",
                terminal_safe(&host.hostname),
                terminal_safe(&host.kernel),
                terminal_safe(&host.os)
            ));
        }
        let verdict = if !report.errors.is_empty() {
            "INCOMPLETE  Collection errors prevent a complete verdict."
        } else if report.findings.is_empty() {
            "PASS  No findings detected by the active probe pack."
        } else {
            "FINDINGS"
        };
        lines.push(verdict.into());
        lines.push(format!(
            "{} finding(s), {} observation(s), {} collection error(s)",
            report.findings.len(),
            report.observations.len(),
            report.errors.len()
        ));
        lines
    }

    fn footer_line(&self) -> String {
        if self.help {
            "?/Esc close help   q quit".into()
        } else {
            "j/k move  enter expand  tab target  ? help  q quit".into()
        }
    }

    fn body_lines(&self) -> Vec<String> {
        let Some(report) = self.reports.get(self.target) else {
            return Vec::new();
        };
        let mut lines = Vec::new();
        let expanded = &self.expanded[self.target];
        let mut row = 0;
        for finding in &report.findings {
            let marker = if expanded.contains(&row) { '-' } else { '+' };
            lines.push(format!(
                "{marker} {:<8} {}  {}",
                finding.severity.to_string().to_uppercase(),
                finding.id,
                finding.title
            ));
            if expanded.contains(&row) {
                if finding.evidence_truncated {
                    lines.push(format!(
                        "    evidence truncated: {} byte(s) omitted ({}-byte limit)",
                        finding.evidence_omitted_bytes, finding.evidence_limit_bytes
                    ));
                }
                for line in finding.evidence.output.lines() {
                    lines.push(format!("    {}", terminal_safe(line)));
                }
                lines.push(format!("    fix: {}", finding.remediation));
            }
            row += 1;
        }
        for observation in &report.observations {
            let marker = if expanded.contains(&row) { '-' } else { '+' };
            lines.push(format!(
                "{marker} EVIDENCE {}  {}",
                observation.id, observation.title
            ));
            if expanded.contains(&row) {
                if let Some(partial) = &observation.partial {
                    lines.push(format!("    partial: {}", terminal_safe(partial)));
                }
                if observation.truncated {
                    lines.push("    truncated: true".into());
                }
                for limit in &observation.collection_limits {
                    lines.push(format!("    collection limit: {}", terminal_safe(limit)));
                }
                if observation.evidence_budget_exceeded {
                    lines.push("    evidence budget exceeded: true".into());
                }
                for line in observation.evidence.output.lines() {
                    lines.push(format!("    {}", terminal_safe(line)));
                }
            }
            row += 1;
        }
        for error in &report.errors {
            let marker = if expanded.contains(&row) { '-' } else { '+' };
            lines.push(format!(
                "{marker} ERROR    {}  {}",
                terminal_safe(error.probe),
                terminal_safe(&error.message)
            ));
            row += 1;
        }
        if lines.is_empty() {
            lines.push("(no findings, observations, or collection errors)".into());
        }
        lines
    }

    fn selected_anchor(&self, body: &[String]) -> Option<usize> {
        if self.row_count() == 0 {
            return None;
        }
        let mut row = 0;
        for (index, line) in body.iter().enumerate() {
            if line.starts_with('+') || line.starts_with('-') {
                if row == self.selected {
                    return Some(index);
                }
                row += 1;
            }
        }
        None
    }

    fn follow_selection(&mut self, body: &[String], body_height: usize) {
        if body_height == 0 || body.is_empty() {
            self.scroll = 0;
            return;
        }
        let max_scroll = body.len().saturating_sub(body_height);
        self.scroll = self.scroll.min(max_scroll);
        let Some(anchor) = self.selected_anchor(body) else {
            return;
        };
        if anchor < self.scroll {
            self.scroll = anchor;
        } else if anchor >= self.scroll + body_height {
            self.scroll = anchor + 1 - body_height;
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let count = self.row_count();
        if count == 0 {
            self.selected = 0;
            return;
        }
        let next = self.selected as isize + delta;
        self.selected = next.clamp(0, count as isize - 1) as usize;
    }

    fn shift_target(&mut self, delta: isize) {
        if self.reports.is_empty() {
            return;
        }
        let count = self.reports.len() as isize;
        self.target = (self.target as isize + delta).rem_euclid(count) as usize;
        self.selected = 0;
        self.scroll = 0;
    }

    fn toggle_expanded(&mut self) {
        if self.row_count() == 0 {
            return;
        }
        let selected = self.selected;
        let set = &mut self.expanded[self.target];
        if !set.remove(&selected) {
            set.insert(selected);
        }
    }

    fn row_count(&self) -> usize {
        let Some(report) = self.reports.get(self.target) else {
            return 0;
        };
        report.findings.len() + report.observations.len() + report.errors.len()
    }

    fn page_step(&self) -> usize {
        self.last_body_height.max(1)
    }
}

pub fn ensure_interactive() -> io::Result<()> {
    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "--format tui requires an interactive terminal",
        ))
    }
}

pub fn run(reports: &[ScanReport]) -> io::Result<()> {
    ensure_interactive()?;
    let mut stdout = io::stdout();
    let _raw = RawMode::enter()?;
    let mut viewer = Viewer::new(reports);
    write!(stdout, "\x1b[?1049h\x1b[?25l")?;
    stdout.flush()?;
    let result = event_loop(&mut viewer, &mut stdout);
    let _ = write!(stdout, "\x1b[?25h\x1b[?1049l");
    let _ = stdout.flush();
    result
}

fn event_loop(viewer: &mut Viewer<'_>, stdout: &mut io::Stdout) -> io::Result<()> {
    let mut stdin = io::stdin();
    loop {
        let (width, height) = window_size();
        let lines = viewer.frame(width, height);
        let selected = viewer.selected_line(&lines);
        draw(stdout, &lines, selected)?;
        match read_key(&mut stdin)? {
            None => continue,
            Some(key) => {
                if !viewer.handle(key) {
                    return Ok(());
                }
            }
        }
    }
}

fn draw(stdout: &mut io::Stdout, lines: &[String], selected: Option<usize>) -> io::Result<()> {
    write!(stdout, "\x1b[H")?;
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            write!(stdout, "\r\n")?;
        }
        if selected == Some(index) {
            write!(stdout, "\x1b[7m{line}\x1b[27m\x1b[K")?;
        } else {
            write!(stdout, "{line}\x1b[K")?;
        }
    }
    stdout.flush()
}

fn help_lines() -> Vec<String> {
    vec![
        "Keyboard".into(),
        "  j/k, Down/Up     next/previous row".into(),
        "  Tab/Shift-Tab    next/previous target".into(),
        "  [/], Left/Right  previous/next target".into(),
        "  Enter/Space/h/l  expand or collapse the selected row".into(),
        "  g/G, Home/End    first/last row".into(),
        "  PgUp/PgDn        page through rows".into(),
        "  ?                toggle this help".into(),
        "  q, Esc, Ctrl-C   quit".into(),
        String::new(),
        "Use --format json or --format html for the full retained evidence.".into(),
    ]
}

fn fit(line: &str, width: usize) -> String {
    line.chars().take(width).collect()
}

fn window_size() -> (usize, usize) {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `TIOCGWINSZ` writes a `winsize` for a tty fd; a failed ioctl
    // leaves `size` unused and we fall back to a default geometry.
    let ok =
        unsafe { libc::ioctl(io::stdout().as_raw_fd(), libc::TIOCGWINSZ as _, &mut size) } == 0;
    let width = if ok && size.ws_col > 0 {
        usize::from(size.ws_col)
    } else {
        80
    };
    let height = if ok && size.ws_row > 0 {
        usize::from(size.ws_row)
    } else {
        24
    };
    (width, height)
}

struct RawMode {
    fd: i32,
    original: libc::termios,
}

impl RawMode {
    fn enter() -> io::Result<Self> {
        let fd = io::stdin().as_raw_fd();
        // SAFETY: `termios` is a C struct with no invalid bit patterns; `tcgetattr`
        // immediately overwrites it for the stdin fd before any field is read.
        let mut original = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is stdin; `termios` is written only through the libc API.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = original;
        // SAFETY: `raw` is a fully initialized `termios` copied from `tcgetattr`.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: `fd` is still stdin and `raw` is the cfmakeraw-adjusted termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, original })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: `fd` is the stdin we configured; `original` is the termios
        // captured before raw mode. Best-effort restore on all drop paths.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

fn read_key(stdin: &mut io::Stdin) -> io::Result<Option<Key>> {
    if !poll_stdin(250)? {
        return Ok(None);
    }
    let mut byte = [0_u8; 1];
    if stdin.read(&mut byte)? == 0 {
        return Ok(Some(Key::CtrlC));
    }
    Ok(Some(decode_key(stdin, byte[0])?))
}

fn decode_key(stdin: &mut io::Stdin, first: u8) -> io::Result<Key> {
    match first {
        0x03 => Ok(Key::CtrlC),
        b'\r' | b'\n' => Ok(Key::Enter),
        b'\t' => Ok(Key::Tab),
        0x1b => decode_escape(stdin),
        b' ' => Ok(Key::Char(' ')),
        byte if byte.is_ascii() => Ok(Key::Char(byte as char)),
        _ => Ok(Key::Char('\u{fffd}')),
    }
}

fn decode_escape(stdin: &mut io::Stdin) -> io::Result<Key> {
    if !poll_stdin(50)? {
        return Ok(Key::Esc);
    }
    let mut byte = [0_u8; 1];
    if stdin.read(&mut byte)? == 0 {
        return Ok(Key::Esc);
    }
    match byte[0] {
        b'[' => decode_csi(stdin),
        b'O' => {
            if !poll_stdin(50)? {
                return Ok(Key::Esc);
            }
            let mut next = [0_u8; 1];
            if stdin.read(&mut next)? == 0 {
                return Ok(Key::Esc);
            }
            Ok(match next[0] {
                b'H' => Key::Home,
                b'F' => Key::End,
                _ => Key::Esc,
            })
        }
        _ => Ok(Key::Esc),
    }
}

fn decode_csi(stdin: &mut io::Stdin) -> io::Result<Key> {
    if !poll_stdin(50)? {
        return Ok(Key::Esc);
    }
    let mut byte = [0_u8; 1];
    if stdin.read(&mut byte)? == 0 {
        return Ok(Key::Esc);
    }
    Ok(match byte[0] {
        b'A' => Key::Up,
        b'B' => Key::Down,
        b'C' => Key::Right,
        b'D' => Key::Left,
        b'H' => Key::Home,
        b'F' => Key::End,
        b'Z' => Key::BackTab,
        b'1' | b'4' | b'5' | b'6' | b'7' | b'8' => {
            let kind = byte[0];
            if poll_stdin(50)? {
                let mut next = [0_u8; 1];
                if stdin.read(&mut next)? == 0 {
                    return Ok(Key::Esc);
                }
                if next[0] == b'~' {
                    return Ok(match kind {
                        b'1' | b'7' => Key::Home,
                        b'4' | b'8' => Key::End,
                        b'5' => Key::PageUp,
                        b'6' => Key::PageDown,
                        _ => Key::Esc,
                    });
                }
            }
            Key::Esc
        }
        _ => Key::Esc,
    })
}

fn poll_stdin(timeout_ms: i32) -> io::Result<bool> {
    let mut fds = [libc::pollfd {
        fd: io::stdin().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];
    // SAFETY: `fds` is a live `pollfd` array of length 1 referring to stdin.
    let result = unsafe { libc::poll(fds.as_mut_ptr(), 1, timeout_ms) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(result > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Evidence, Finding, HostCapabilities, HostInfo, Observation, ScanError, ScanReport, Severity,
    };

    fn report(target: &str, findings: usize) -> ScanReport {
        ScanReport {
            schema_version: 1,
            scanner_version: "0.1.0-test",
            scan_id: "scan-fixture".into(),
            started_at: 1_723_000_000_000,
            completed_at: 1_723_000_000_042,
            probe_pack: None,
            target: target.into(),
            host: Some(HostInfo {
                hostname: "fixture-host".into(),
                kernel: "Linux 6.8.0".into(),
                os: "Fixture Linux".into(),
                capabilities: HostCapabilities {
                    root: Some(false),
                    sudo_present: true,
                    tools: vec!["find".into()],
                },
            }),
            duration_ms: 42,
            probes_run: 2,
            findings: (0..findings)
                .map(|index| Finding {
                    id: "SHUV-AUTH-001",
                    title: "Non-root account has UID 0",
                    severity: Severity::Critical,
                    category: "identity",
                    description: "An account other than root has UID 0.",
                    remediation: "Assign a unique non-zero UID.",
                    evidence_truncated: false,
                    evidence_omitted_bytes: 0,
                    evidence_limit_bytes: 8 * 1024,
                    evidence: Evidence {
                        command: "awk fixture",
                        output: format!("account-{index}:/root:/bin/sh"),
                    },
                })
                .collect(),
            observations: vec![Observation {
                id: "SHUV-EVID-PROC-001",
                title: "Sampled PID and parent PID pairs",
                category: "process",
                partial: Some("root access unavailable".into()),
                truncated: false,
                collection_limits: Vec::new(),
                evidence_budget_exceeded: false,
                evidence: Evidence {
                    command: "proc fixture",
                    output: "pid=42\tppid=1".into(),
                },
            }],
            errors: vec![ScanError {
                probe: "SHUV-AUTH-002",
                message: "requires root".into(),
            }],
        }
    }

    fn reports() -> Vec<ScanReport> {
        vec![report("host-a", 2), report("host-b", 1)]
    }

    #[test]
    fn quit_keys_stop_the_viewer() {
        let reports = reports();
        let mut viewer = Viewer::new(&reports);
        assert!(!viewer.handle(Key::Char('q')));
        let mut viewer = Viewer::new(&reports);
        assert!(!viewer.handle(Key::CtrlC));
        let mut viewer = Viewer::new(&reports);
        assert!(!viewer.handle(Key::Esc));
    }

    #[test]
    fn selection_clamps_and_wraps_across_targets() {
        let reports = reports();
        let mut viewer = Viewer::new(&reports);
        viewer.handle(Key::Char('j'));
        viewer.handle(Key::Char('j'));
        viewer.handle(Key::Char('j'));
        viewer.handle(Key::Char('j'));
        viewer.handle(Key::Char('j'));
        assert_eq!(viewer.selected, viewer.row_count() - 1);
        viewer.handle(Key::Char('k'));
        assert_eq!(viewer.selected, viewer.row_count() - 2);
        viewer.handle(Key::Tab);
        assert_eq!(viewer.target, 1);
        assert_eq!(viewer.selected, 0);
        viewer.handle(Key::Tab);
        assert_eq!(viewer.target, 0);
        viewer.handle(Key::BackTab);
        assert_eq!(viewer.target, 1);
    }

    #[test]
    fn enter_toggles_evidence_for_the_selected_row() {
        let reports = reports();
        let mut viewer = Viewer::new(&reports);
        let collapsed = viewer.frame(80, 24);
        assert!(collapsed.iter().all(|line| !line.contains("account-0")));
        viewer.handle(Key::Enter);
        let expanded = viewer.frame(80, 24);
        assert!(expanded.iter().any(|line| line.contains("account-0")));
        assert!(expanded.iter().any(|line| line.contains("fix:")));
        viewer.handle(Key::Char(' '));
        let collapsed_again = viewer.frame(80, 24);
        assert!(
            collapsed_again
                .iter()
                .all(|line| !line.contains("account-0"))
        );
    }

    #[test]
    fn frame_matches_requested_geometry_and_keeps_selection_visible() {
        let reports = reports();
        let mut viewer = Viewer::new(&reports);
        let lines = viewer.frame(40, 12);
        assert_eq!(lines.len(), 12);
        assert!(lines.iter().all(|line| line.chars().count() <= 40));
        viewer.handle(Key::End);
        let lines = viewer.frame(40, 8);
        assert_eq!(lines.len(), 8);
        let selected = viewer.selected_line(&lines).unwrap();
        assert!(lines[selected].contains("ERROR"));
    }

    #[test]
    fn help_overlay_toggles_and_esc_closes_it_without_quitting() {
        let reports = reports();
        let mut viewer = Viewer::new(&reports);
        assert!(viewer.handle(Key::Char('?')));
        let lines = viewer.frame(80, 20);
        assert!(lines.iter().any(|line| line.contains("Keyboard")));
        assert!(viewer.selected_line(&lines).is_none());
        assert!(viewer.handle(Key::Esc));
        assert!(!viewer.help);
        assert!(viewer.handle(Key::Char('j')));
    }

    #[test]
    fn incomplete_scans_are_never_labelled_pass() {
        let reports = reports();
        let mut viewer = Viewer::new(&reports);
        let lines = viewer.frame(80, 12);
        assert!(lines.iter().any(|line| line.contains("INCOMPLETE")));
        assert!(lines.iter().all(|line| !line.contains("PASS")));
    }

    #[test]
    fn home_and_end_jump_the_selection() {
        let reports = reports();
        let mut viewer = Viewer::new(&reports);
        viewer.handle(Key::Char('G'));
        assert_eq!(viewer.selected, viewer.row_count() - 1);
        viewer.handle(Key::Char('g'));
        assert_eq!(viewer.selected, 0);
    }

    #[test]
    fn evidence_control_characters_are_escaped() {
        let mut reports = reports();
        reports[0].findings[0].evidence.output = "x\u{1b}[31mred".into();
        let mut viewer = Viewer::new(&reports);
        viewer.handle(Key::Enter);
        let lines = viewer.frame(80, 24);
        let joined = lines.join("\n");
        assert!(!joined.contains('\u{1b}'));
        assert!(joined.contains(r"\u{1b}[31mred"));
    }
    #[test]
    fn bracket_keys_cycle_targets_and_hl_toggle_evidence() {
        let reports = reports();
        let mut viewer = Viewer::new(&reports);
        viewer.handle(Key::Char(']'));
        assert_eq!(viewer.target, 1);
        viewer.handle(Key::Char(']'));
        assert_eq!(viewer.target, 0);
        viewer.handle(Key::Char('['));
        assert_eq!(viewer.target, 1);

        let mut viewer = Viewer::new(&reports);
        viewer.handle(Key::Char('l'));
        let expanded = viewer.frame(80, 24);
        assert!(expanded.iter().any(|line| line.contains("account-0")));
        viewer.handle(Key::Char('h'));
        let collapsed = viewer.frame(80, 24);
        assert!(collapsed.iter().all(|line| !line.contains("account-0")));
    }
}
