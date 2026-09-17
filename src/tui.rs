use std::{
    collections::HashSet,
    io::{self, IsTerminal, Read, Write},
    os::fd::AsRawFd,
    sync::Mutex,
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
    last_width: usize,
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
            last_width: 80,
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
            Key::Enter | Key::Char(' ') => {
                self.toggle_expanded();
                true
            }
            Key::Tab | Key::Right | Key::Char(']') | Key::Char('l') => {
                self.shift_target(1);
                true
            }
            Key::BackTab | Key::Left | Key::Char('[') | Key::Char('h') => {
                self.shift_target(-1);
                true
            }
            Key::Char(_) => true,
        }
    }

    /// Render `height` lines of `width` columns. The selected row is kept in
    /// view. Body lines wrap; header and footer that overflow are marked with `…`.
    pub fn frame(&mut self, width: usize, height: usize) -> Vec<String> {
        let width = width.max(1);
        let height = height.max(1);
        self.last_width = width;
        let header = self.header_lines();
        let footer = vec![self.footer_line()];
        let chrome = header.len() + footer.len();
        let body_height = height.saturating_sub(chrome);
        self.last_body_height = body_height.max(1);
        let body = self.wrapped_body(width);
        self.follow_selection(&body, body_height);
        let mut lines = Vec::with_capacity(height);
        for line in &header {
            lines.push(ellipsize(line, width));
        }
        let start = self.scroll.min(
            body.len()
                .saturating_sub(body_height.max(1))
                .min(body.len()),
        );
        let end = (start + body_height).min(body.len());
        for line in &body[start..end] {
            lines.push(line.clone());
        }
        while lines.len() + footer.len() < height {
            lines.push(String::new());
        }
        for line in &footer {
            lines.push(ellipsize(line, width));
        }
        lines.truncate(height);
        lines
    }

    pub fn selected_line(&self, lines: &[String]) -> Option<usize> {
        if self.help {
            return None;
        }
        let header = self.header_lines().len();
        let body = self.wrapped_body(self.last_width.max(1));
        let anchor = self.selected_anchor(&body)?;
        let index = header + anchor.saturating_sub(self.scroll);
        (index < lines.len().saturating_sub(1)).then_some(index)
    }

    fn wrapped_body(&self, width: usize) -> Vec<String> {
        let source = if self.help {
            help_lines()
        } else {
            self.body_lines()
        };
        wrap_lines(&source, width)
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
            "j/k move  enter expand  h/l target  ? help  q quit".into()
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
                if !finding.evidence.command.is_empty() {
                    lines.push(format!(
                        "    command: {}",
                        terminal_safe(finding.evidence.command)
                    ));
                }
                if finding.evidence_truncated {
                    lines.push(format!(
                        "    evidence truncated: {} byte(s) omitted ({}-byte limit)",
                        finding.evidence_omitted_bytes, finding.evidence_limit_bytes
                    ));
                }
                for line in finding.evidence.output.lines() {
                    lines.push(format!("    {}", terminal_safe(line)));
                }
                lines.push(format!("    fix: {}", terminal_safe(finding.remediation)));
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
                if !observation.evidence.command.is_empty() {
                    lines.push(format!(
                        "    command: {}",
                        terminal_safe(observation.evidence.command)
                    ));
                }
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
            if expanded.contains(&row) {
                lines.push(format!("{marker} ERROR    {}", terminal_safe(error.probe)));
                for line in error.message.lines() {
                    lines.push(format!("    {}", terminal_safe(line)));
                }
            } else {
                lines.push(format!(
                    "{marker} ERROR    {}  {}",
                    terminal_safe(error.probe),
                    terminal_safe(&error.message)
                ));
            }
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

    fn selected_span(&self, body: &[String]) -> Option<(usize, usize)> {
        let start = self.selected_anchor(body)?;
        let end = body[start + 1..]
            .iter()
            .position(|line| line.starts_with('+') || line.starts_with('-'))
            .map_or(body.len(), |offset| start + 1 + offset);
        Some((start, end))
    }

    fn follow_selection(&mut self, body: &[String], body_height: usize) {
        if body_height == 0 || body.is_empty() {
            self.scroll = 0;
            return;
        }
        let max_scroll = body.len().saturating_sub(body_height);
        self.scroll = self.scroll.min(max_scroll);
        let Some((start, end)) = self.selected_span(body) else {
            return;
        };
        if start < self.scroll {
            self.scroll = start;
        }
        if end > self.scroll + body_height {
            self.scroll = end.saturating_sub(body_height);
            if start < self.scroll {
                self.scroll = start;
            }
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
    let _guard = TerminalGuard::enter()?;
    let mut stdout = io::stdout();
    let mut viewer = Viewer::new(reports);
    event_loop(&mut viewer, &mut stdout)
}

fn event_loop(viewer: &mut Viewer<'_>, stdout: &mut io::Stdout) -> io::Result<()> {
    let mut stdin = io::stdin();
    let mut last_size = (0, 0);
    let mut dirty = true;
    loop {
        let size = window_size();
        if dirty || size != last_size {
            last_size = size;
            let (width, height) = size;
            let lines = viewer.frame(width, height);
            let selected = viewer.selected_line(&lines);
            draw(stdout, &lines, selected)?;
            dirty = false;
        }
        match read_key(&mut stdin)? {
            None => continue,
            Some(key) => {
                if !viewer.handle(key) {
                    return Ok(());
                }
                dirty = true;
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
        "  h/l, Left/Right  previous/next target".into(),
        "  Tab/Shift-Tab    next/previous target".into(),
        "  [/]              previous/next target".into(),
        "  Enter/Space      expand or collapse the selected row".into(),
        "  g/G, Home/End    first/last row".into(),
        "  PgUp/PgDn        page through rows".into(),
        "  ?                toggle this help".into(),
        "  q, Esc, Ctrl-C   quit".into(),
        String::new(),
        "Use --format json or --format html for the full retained evidence.".into(),
    ]
}

fn wrap_lines(lines: &[String], width: usize) -> Vec<String> {
    lines
        .iter()
        .flat_map(|line| wrap_line(line, width))
        .collect()
}

fn wrap_line(line: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    if line.is_empty() {
        return vec![String::new()];
    }
    if line.chars().count() <= width {
        return vec![line.to_string()];
    }
    let indent = if width > 4 { 4 } else { 0 };
    let mut lines = Vec::new();
    let mut first = true;
    let mut chars = line.chars();
    loop {
        let columns = if first {
            width
        } else {
            width.saturating_sub(indent).max(1)
        };
        let chunk: String = chars.by_ref().take(columns).collect();
        if chunk.is_empty() {
            break;
        }
        if first {
            lines.push(chunk);
            first = false;
        } else {
            let mut rendered = String::with_capacity(indent + chunk.len());
            for _ in 0..indent {
                rendered.push(' ');
            }
            rendered.push_str(&chunk);
            lines.push(rendered);
        }
    }
    lines
}

fn ellipsize(line: &str, width: usize) -> String {
    let width = width.max(1);
    if line.chars().count() <= width {
        return line.to_string();
    }
    if width == 1 {
        return "…".to_string();
    }
    let mut truncated: String = line.chars().take(width - 1).collect();
    truncated.push('…');
    truncated
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

struct SavedTty {
    term_fd: i32,
    out_fd: i32,
    original: libc::termios,
}

static SAVED_TTY: Mutex<Option<SavedTty>> = Mutex::new(None);

struct TerminalGuard {
    term_fd: i32,
    out_fd: i32,
    original: libc::termios,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        let term_fd = io::stdin().as_raw_fd();
        let out_fd = io::stdout().as_raw_fd();
        // SAFETY: `termios` is a C struct with no invalid bit patterns; `tcgetattr`
        // immediately overwrites it for the stdin fd before any field is read.
        let mut original = unsafe { std::mem::zeroed() };
        // SAFETY: `term_fd` is stdin; `termios` is written only through the libc API.
        if unsafe { libc::tcgetattr(term_fd, &mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = original;
        // SAFETY: `raw` is a fully initialized `termios` copied from `tcgetattr`.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: `term_fd` is still stdin and `raw` is the cfmakeraw-adjusted termios.
        if unsafe { libc::tcsetattr(term_fd, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let guard = Self {
            term_fd,
            out_fd,
            original,
        };
        let seq = b"\x1b[?1049h\x1b[?25l";
        // SAFETY: `out_fd` is stdout, already required to be a tty.
        if unsafe { libc::write(out_fd, seq.as_ptr().cast(), seq.len()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        *SAVED_TTY
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(SavedTty {
            term_fd,
            out_fd,
            original,
        });
        crate::transport::set_interrupt_cleanup(Some(restore_after_interrupt));
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        crate::transport::set_interrupt_cleanup(None);
        restore_tty(self.term_fd, self.out_fd, &self.original);
        *SAVED_TTY
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

fn restore_after_interrupt() {
    let saved = SAVED_TTY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(saved) = saved {
        restore_tty(saved.term_fd, saved.out_fd, &saved.original);
    }
}

fn restore_tty(term_fd: i32, out_fd: i32, original: &libc::termios) {
    let seq = b"\x1b[?25h\x1b[?1049l";
    // SAFETY: best-effort restore of the tty we put in raw/alternate-screen
    // mode. `libc::write` is used so a locked `Stdout` cannot deadlock the
    // interrupt thread. Errors are ignored because this runs on Drop and
    // fatal-signal paths.
    unsafe {
        libc::write(out_fd, seq.as_ptr().cast(), seq.len());
        libc::tcsetattr(term_fd, libc::TCSANOW, original);
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
    fn hl_and_arrows_cycle_targets() {
        let reports = reports();
        let mut viewer = Viewer::new(&reports);
        viewer.handle(Key::Char('l'));
        assert_eq!(viewer.target, 1);
        viewer.handle(Key::Char('h'));
        assert_eq!(viewer.target, 0);
        viewer.handle(Key::Right);
        assert_eq!(viewer.target, 1);
        viewer.handle(Key::Left);
        assert_eq!(viewer.target, 0);
        viewer.handle(Key::Char(']'));
        assert_eq!(viewer.target, 1);
        viewer.handle(Key::Char('['));
        assert_eq!(viewer.target, 0);
    }

    #[test]
    fn long_lines_wrap_instead_of_silent_truncation() {
        let mut reports = reports();
        reports[0].findings[0].title =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        let mut viewer = Viewer::new(&reports);
        let lines = viewer.frame(28, 16);
        assert_eq!(lines.len(), 16);
        assert!(lines.iter().all(|line| line.chars().count() <= 28));
        let compact: String = lines
            .concat()
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();
        assert!(compact.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        assert!(compact.contains("0123456789abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn chrome_marks_horizontal_truncation() {
        let mut reports = reports();
        reports[0].target = "T".repeat(80);
        let mut viewer = Viewer::new(&reports);
        let lines = viewer.frame(24, 12);
        assert!(lines[0].chars().count() <= 24);
        assert!(lines[0].ends_with('…'));
    }

    #[test]
    fn error_rows_expand_to_the_full_message() {
        let mut reports = reports();
        reports[0].errors[0].message =
            "could not completely inspect /tmp; could not completely inspect /run/user".into();
        let mut viewer = Viewer::new(&reports);
        viewer.handle(Key::End);
        viewer.handle(Key::Enter);
        let lines = viewer.frame(36, 16);
        let compact: String = lines
            .concat()
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();
        assert!(compact.contains("couldnotcompletelyinspect/tmp"));
        assert!(compact.contains("couldnotcompletelyinspect/run"));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("ERROR") && line.contains("SHUV-AUTH-002"))
        );
        assert!(lines.iter().all(|line| line.chars().count() <= 36));
    }

    #[test]
    fn expanding_the_last_row_keeps_its_body_visible() {
        let mut reports = reports();
        reports[0].errors[0].message = "full collection error text for the last row".into();
        let mut viewer = Viewer::new(&reports);
        viewer.handle(Key::End);
        viewer.handle(Key::Enter);
        let lines = viewer.frame(48, 8);
        let joined = lines.join("\n");
        assert!(joined.contains("ERROR"));
        assert!(joined.contains("full collection error text"));
    }

    #[test]
    fn wrap_line_never_exceeds_width() {
        let wrapped = wrap_line("abcdefghijklmnopqrstuvwxyz0123456789", 10);
        assert!(wrapped.iter().all(|line| line.chars().count() <= 10));
        assert!(wrapped.len() > 1);
        assert_eq!(wrapped[0], "abcdefghij");
        assert!(wrapped[1].starts_with("    "));
    }
}
