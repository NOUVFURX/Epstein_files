use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Text;
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Terminal;

mod file_lock;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessInfo {
    pid: u32,
    uid: u32,
    name: String,
}

fn scan_locks(path: &Path) -> Result<Vec<(u32, String)>, String> {
    let mut command = Command::new("lsof");
    command.args(["-Fpc"]);
    if path.is_dir() {
        command.arg("+D");
    }
    command.arg(path);

    let output = command
        .output()
        .map_err(|error| format!("Could not run lsof: {error} (is lsof installed?)"))?;
    let mut processes = BTreeMap::new();
    let mut current_pid = None;

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(value) = line.strip_prefix('p') {
            current_pid = value.parse::<u32>().ok();
            if let Some(pid) = current_pid {
                processes.entry(pid).or_insert_with(String::new);
            }
        } else if let (Some(pid), Some(name)) = (current_pid, line.strip_prefix('c')) {
            processes.insert(pid, name.to_string());
        }
    }

    if !(output.status.success() || (output.status.code() == Some(1) && processes.is_empty())) {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("lsof exited with status {}", output.status)
        } else {
            format!("lsof failed: {stderr}")
        });
    }

    Ok(processes
        .into_iter()
        .filter(|(pid, _)| *pid != std::process::id())
        .collect())
}

fn process_info(pid: u32, lsof_name: &str) -> Result<ProcessInfo, String> {
    let output = Command::new("ps")
        .args(["-o", "uid=,comm=", "-p", &pid.to_string()])
        .output()
        .map_err(|error| format!("Could not inspect PID {pid} with ps: {error}"))?;

    if !output.status.success() {
        return Err(format!("PID {pid} exited or could not be inspected"));
    }

    let details = String::from_utf8_lossy(&output.stdout);
    let mut fields = details.split_whitespace();
    let uid = fields
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| format!("Could not read the UID for PID {pid}"))?;
    let name = fields.collect::<Vec<_>>().join(" ");
    let name = if name.is_empty() {
        lsof_name.to_string()
    } else {
        name
    };

    Ok(ProcessInfo { pid, uid, name })
}

fn list_processes(path: &Path) -> Result<Vec<ProcessInfo>, String> {
    scan_locks(path)?
        .into_iter()
        .map(|(pid, name)| process_info(pid, &name))
        .collect()
}

fn path_access_error(path: &Path) -> Option<io::Error> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::read_dir(path)
            .and_then(|mut entries| match entries.next() {
                Some(Ok(_)) | None => Ok(()),
                Some(Err(error)) => Err(error),
            })
            .err(),
        Ok(_) => fs::File::open(path).err(),
        Err(error) => Some(error),
    }
}

fn print_table(processes: &[ProcessInfo]) {
    println!("{:<10} {:<10} PROCESS", "PID", "UID");
    println!("{}", "-".repeat(54));
    for process in processes {
        println!("{:<10} {:<10} {}", process.pid, process.uid, process.name);
    }
}

fn prompt_line(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn offer_permissions(path: &Path) -> Result<(), String> {
    println!("No process locks were found, but the path cannot be accessed: permission denied.");
    let answer = prompt_line(
        "Add read/write access for the file owner (and directory traversal if needed)? [y/N]: ",
    )
    .map_err(|error| format!("Could not read input: {error}"))?;
    if !answer.eq_ignore_ascii_case("y") {
        return Ok(());
    }

    grant_owner_permissions(path)
}

fn grant_owner_permissions(path: &Path) -> Result<(), String> {
    let status = Command::new("chmod")
        .arg("u+rwX")
        .arg(path)
        .status()
        .map_err(|error| format!("Could not run chmod: {error}"))?;
    if status.success() {
        println!("Owner permissions updated for this path only. Run locksmith again to rescan.");
        Ok(())
    } else {
        Err(format!("chmod failed with status {status}"))
    }
}

fn selected_pids(input: &str, processes: &[ProcessInfo]) -> Result<Vec<u32>, String> {
    let mut selected = Vec::new();
    for part in input.split(',') {
        let pid = part
            .trim()
            .parse::<u32>()
            .map_err(|_| format!("Invalid PID: '{}'", part.trim()))?;
        if !processes.iter().any(|process| process.pid == pid) {
            return Err(format!("PID {pid} is not in the current lock list"));
        }
        if !selected.contains(&pid) {
            selected.push(pid);
        }
    }
    if selected.is_empty() {
        return Err("No PIDs selected".to_string());
    }
    Ok(selected)
}

fn terminate(process: &ProcessInfo) -> Result<(), String> {
    let current = process_info(process.pid, &process.name)?;
    if current.uid != process.uid || current.name != process.name {
        return Err(format!(
            "PID {} no longer matches the listed process; refusing to signal it",
            process.pid
        ));
    }

    let status = Command::new("kill")
        .args(["-TERM", &process.pid.to_string()])
        .status()
        .map_err(|error| format!("Could not send SIGTERM to PID {}: {error}", process.pid))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "Could not send SIGTERM to PID {} (status {status})",
            process.pid
        ))
    }
}

#[derive(Default)]
enum Dialog {
    #[default]
    None,
    ConfirmTermination(Vec<u32>),
    ConfirmPermissions,
}

struct App {
    path: PathBuf,
    processes: Vec<ProcessInfo>,
    selected: HashSet<u32>,
    cursor: usize,
    dialog: Dialog,
    status: String,
}

impl App {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            processes: Vec::new(),
            selected: HashSet::new(),
            cursor: 0,
            dialog: Dialog::None,
            status: String::new(),
        }
    }

    fn refresh(&mut self) -> Result<(), String> {
        let found = list_processes(&self.path);
        let access_error = path_access_error(&self.path);

        match found {
            Ok(processes) => {
                self.processes = processes;
                self.selected
                    .retain(|pid| self.processes.iter().any(|process| process.pid == *pid));
                if self.processes.is_empty() {
                    if let Some(error) = access_error {
                        if error.kind() == io::ErrorKind::PermissionDenied {
                            self.processes.clear();
                            self.selected.clear();
                            self.dialog = Dialog::ConfirmPermissions;
                            self.status =
                                "No open files found; this path is inaccessible.".to_string();
                            return Ok(());
                        }
                        return Err(format!(
                            "Could not access '{}': {error}",
                            self.path.display()
                        ));
                    }
                    self.status =
                        "No processes holding open file descriptors were found.".to_string();
                } else {
                    self.status = format!("{} process(es) found.", self.processes.len());
                }
            }
            Err(error) => {
                if access_error
                    .as_ref()
                    .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
                {
                    self.dialog = Dialog::ConfirmPermissions;
                    self.status = "The path is inaccessible.".to_string();
                    self.processes.clear();
                    self.selected.clear();
                    return Ok(());
                }
                return Err(error);
            }
        }

        self.selected
            .retain(|pid| self.processes.iter().any(|process| process.pid == *pid));
        if self.processes.is_empty() {
            self.cursor = 0;
        } else {
            self.cursor = self.cursor.min(self.processes.len() - 1);
        }
        Ok(())
    }

    fn handle_key(&mut self, key: KeyCode) -> Result<bool, String> {
        match &self.dialog {
            Dialog::ConfirmTermination(pids) => match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let pids = pids.clone();
                    let mut messages = Vec::new();
                    for pid in pids {
                        if let Some(process) =
                            self.processes.iter().find(|process| process.pid == pid)
                        {
                            match terminate(process) {
                                Ok(()) => messages.push(format!("SIGTERM sent to PID {pid}")),
                                Err(error) => messages.push(error),
                            }
                        }
                    }
                    self.dialog = Dialog::None;
                    self.refresh()?;
                    if !messages.is_empty() {
                        self.status = messages.join("; ");
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.dialog = Dialog::None;
                    self.status = "Termination cancelled.".to_string();
                }
                _ => {}
            },
            Dialog::ConfirmPermissions => match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    grant_owner_permissions(&self.path)?;
                    self.dialog = Dialog::None;
                    self.refresh()?;
                    self.status = "Owner permissions updated for this path only.".to_string();
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.dialog = Dialog::None;
                    self.status = "Permission change cancelled.".to_string();
                }
                _ => {}
            },
            Dialog::None => match key {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(false),
                KeyCode::Up | KeyCode::Char('k') => {
                    self.cursor = self.cursor.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if !self.processes.is_empty() {
                        self.cursor = (self.cursor + 1).min(self.processes.len() - 1);
                    }
                }
                KeyCode::Char(' ') => {
                    if let Some(process) = self.processes.get(self.cursor) {
                        if !self.selected.insert(process.pid) {
                            self.selected.remove(&process.pid);
                        }
                    }
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    if self.selected.len() == self.processes.len() {
                        self.selected.clear();
                    } else {
                        self.selected = self.processes.iter().map(|process| process.pid).collect();
                    }
                }
                KeyCode::Enter => {
                    if self.selected.is_empty() {
                        self.status = "Select one or more processes first.".to_string();
                    } else {
                        self.dialog =
                            Dialog::ConfirmTermination(self.selected.iter().copied().collect());
                    }
                }
                KeyCode::Char('r') | KeyCode::Char('R') => self.refresh()?,
                _ => {}
            },
        }
        Ok(true)
    }
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

fn draw_ui(frame: &mut ratatui::Frame<'_>, app: &App, table_state: &mut TableState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .split(frame.area());

    frame.render_widget(
        Paragraph::new(app.path.display().to_string())
            .block(Block::default().borders(Borders::ALL).title(" locksmith ")),
        areas[0],
    );

    let rows = app.processes.iter().map(|process| {
        let marker = if app.selected.contains(&process.pid) {
            "[x]"
        } else {
            "[ ]"
        };
        Row::new(vec![
            Cell::from(marker),
            Cell::from(process.pid.to_string()),
            Cell::from(process.uid.to_string()),
            Cell::from(process.name.clone()),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(["SEL", "PID", "UID", "PROCESS"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Open file holders "),
    )
    .row_highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
    .highlight_symbol(">> ");
    table_state.select((!app.processes.is_empty()).then_some(app.cursor));
    frame.render_stateful_widget(table, areas[1], table_state);

    frame.render_widget(
        Paragraph::new(Text::raw(app.status.clone()))
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(" Status ")),
        areas[2],
    );
    frame.render_widget(
        Paragraph::new("↑/↓ move  Space select  a all/none  Enter terminate  r rescan  q quit"),
        areas[3],
    );

    let dialog_text = match &app.dialog {
        Dialog::None => None,
        Dialog::ConfirmTermination(pids) => Some(format!(
            "Send SIGTERM to {} selected process(es)?\n[y] Confirm    [n/Esc] Cancel",
            pids.len()
        )),
        Dialog::ConfirmPermissions => Some(
            "Add owner read/write access (and directory traversal where needed)?\nOnly this path will change.\n[y] Confirm    [n/Esc] Cancel"
                .to_string(),
        ),
    };
    if let Some(text) = dialog_text {
        let popup = centered_rect(frame.area(), 64, 7);
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: true })
                .block(Block::default().borders(Borders::ALL).title(" Confirm ")),
            popup,
        );
    }
}

struct TerminalGuard {
    active: bool,
}

impl TerminalGuard {
    fn enter() -> Result<Self, String> {
        enable_raw_mode()
            .map_err(|error| format!("Could not enable raw terminal mode: {error}"))?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(format!("Could not enter alternate screen: {error}"));
        }
        Ok(Self { active: true })
    }

    fn restore(&mut self) -> Result<(), String> {
        execute!(io::stdout(), LeaveAlternateScreen)
            .map_err(|error| format!("Could not restore terminal screen: {error}"))?;
        disable_raw_mode()
            .map_err(|error| format!("Could not disable raw terminal mode: {error}"))?;
        self.active = false;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            let _ = disable_raw_mode();
        }
    }
}

fn run_tui(path: PathBuf) -> Result<(), String> {
    let mut guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))
        .map_err(|error| format!("Could not initialize terminal UI: {error}"))?;
    let mut app = App::new(path);
    let result = (|| {
        app.refresh()?;
        loop {
            terminal
                .draw(|frame| draw_ui(frame, &app, &mut TableState::default()))
                .map_err(|error| format!("Could not draw terminal UI: {error}"))?;
            if event::poll(Duration::from_millis(250))
                .map_err(|error| format!("Could not read terminal input: {error}"))?
            {
                if let Event::Key(key) = event::read()
                    .map_err(|error| format!("Could not read terminal input: {error}"))?
                {
                    if key.kind == KeyEventKind::Press && !app.handle_key(key.code)? {
                        break;
                    }
                }
            }
        }
        Ok(())
    })();
    drop(terminal);
    guard.restore()?;
    result
}

fn run(path: PathBuf) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("Path '{}' does not exist.", path.display()));
    }
    let path = fs::canonicalize(&path)
        .map_err(|error| format!("Could not resolve '{}': {error}", path.display()))?;

    loop {
        println!("Checking for open files under: {}\n", path.display());
        let found = list_processes(&path);
        let access_error = path_access_error(&path);

        let processes = match found {
            Ok(processes) => processes,
            Err(error) => {
                if access_error
                    .as_ref()
                    .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
                {
                    return offer_permissions(&path);
                }
                return Err(error);
            }
        };

        if processes.is_empty() {
            if let Some(error) = access_error {
                if error.kind() == io::ErrorKind::PermissionDenied {
                    return offer_permissions(&path);
                }
                return Err(format!("Could not access '{}': {error}", path.display()));
            }
            println!("No processes holding open file descriptors were found.");
            return Ok(());
        }

        print_table(&processes);
        println!("\nEnter comma-separated PIDs to send SIGTERM, 'all' for every listed PID, or 'q' to quit.");
        let choice =
            prompt_line("Action: ").map_err(|error| format!("Could not read input: {error}"))?;
        if choice.eq_ignore_ascii_case("q") || choice.is_empty() {
            return Ok(());
        }

        let selected = if choice.eq_ignore_ascii_case("all") {
            processes.iter().map(|process| process.pid).collect()
        } else {
            match selected_pids(&choice, &processes) {
                Ok(selected) => selected,
                Err(error) => {
                    eprintln!("{error}");
                    continue;
                }
            }
        };

        let confirmation = prompt_line(&format!(
            "Send SIGTERM to {} process(es)? [y/N]: ",
            selected.len()
        ))
        .map_err(|error| format!("Could not read input: {error}"))?;
        if !confirmation.eq_ignore_ascii_case("y") {
            continue;
        }

        for pid in selected {
            if let Some(process) = processes.iter().find(|process| process.pid == pid) {
                if let Err(error) = terminate(process) {
                    eprintln!("{error}");
                }
            }
        }
        println!();
    }
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let Some(first) = args.next() else {
        print_usage(&program);
        return ExitCode::from(2);
    };
    if first == "--help" || first == "-h" {
        print_usage(&program);
        return ExitCode::SUCCESS;
    }

    if first == "lock" || first == "unlock" {
        let Some(path) = args.next() else {
            print_usage(&program);
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            print_usage(&program);
            return ExitCode::from(2);
        }
        let operation = if first == "lock" {
            file_lock::Operation::Lock
        } else {
            file_lock::Operation::Unlock
        };
        return match file_lock::run(operation, Path::new(&path)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Error: {error}");
                ExitCode::FAILURE
            }
        };
    }

    let (force_plain, force_tui, path) = if first == "--plain" || first == "--tui" {
        let Some(path) = args.next() else {
            print_usage(&program);
            return ExitCode::from(2);
        };
        (first == "--plain", first == "--tui", path)
    } else {
        (false, false, first)
    };
    if args.next().is_some() {
        print_usage(&program);
        return ExitCode::from(2);
    }

    let use_tui =
        force_tui || (!force_plain && io::stdin().is_terminal() && io::stdout().is_terminal());
    let result = if use_tui {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            Err("The terminal interface requires an interactive terminal; use --plain to disable it.".to_string())
        } else {
            run_tui(PathBuf::from(path))
        }
    } else {
        run(PathBuf::from(path))
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage(program: &std::ffi::OsStr) {
    eprintln!(
        "Usage:\n  {} [--plain|--tui] <file-or-directory>\n  {} <lock|unlock> <file-or-directory>",
        Path::new(program).display(),
        Path::new(program).display(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_pids_must_be_in_the_current_scan() {
        let processes = vec![ProcessInfo {
            pid: 123,
            uid: 501,
            name: "editor".to_string(),
        }];

        assert_eq!(selected_pids("123", &processes).unwrap(), vec![123]);
        assert!(selected_pids("123,456", &processes).is_err());
        assert!(selected_pids("-1", &processes).is_err());
    }
}
