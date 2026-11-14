use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

use crate::file_lock::{self, Operation};
use crate::{grant_owner_permissions, list_processes, path_access_error, terminate, ProcessInfo};

pub fn launch(initial_path: Option<PathBuf>) -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Locksmith")
            .with_inner_size([900.0, 620.0])
            .with_min_inner_size([700.0, 450.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Locksmith",
        options,
        Box::new(move |_creation_context| Ok(Box::new(LocksmithGui::new(initial_path)))),
    )
    .map_err(|error| format!("Could not open Locksmith: {error}"))
}

struct LocksmithGui {
    path: String,
    processes: Vec<ProcessInfo>,
    selected: BTreeSet<u32>,
    status: String,
    permission_denied: bool,
    confirm_termination: bool,
    confirm_permissions: bool,
    file_operation: Option<Operation>,
    password: Zeroizing<String>,
    password_confirmation: Zeroizing<String>,
    password_error: String,
    scan_on_start: bool,
}

impl LocksmithGui {
    fn new(initial_path: Option<PathBuf>) -> Self {
        let scan_on_start = initial_path.is_some();
        Self {
            path: initial_path
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            processes: Vec::new(),
            selected: BTreeSet::new(),
            status: "Enter a file or folder, then select Scan.".to_string(),
            permission_denied: false,
            confirm_termination: false,
            confirm_permissions: false,
            file_operation: None,
            password: Zeroizing::new(String::new()),
            password_confirmation: Zeroizing::new(String::new()),
            password_error: String::new(),
            scan_on_start,
        }
    }

    fn scan(&mut self) {
        self.permission_denied = false;
        self.processes.clear();
        self.selected.clear();
        let input = Path::new(self.path.trim());
        if input.as_os_str().is_empty() {
            self.status = "Enter a file or folder path.".to_string();
            return;
        }

        match fs::metadata(input) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.status = format!("Path does not exist: {}", input.display());
                self.processes.clear();
                self.selected.clear();
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                self.status = format!("Permission denied for: {}", input.display());
                self.permission_denied = true;
                self.processes.clear();
                self.selected.clear();
                return;
            }
            Err(error) => {
                self.status = format!("Could not inspect path: {error}");
                return;
            }
        }

        let path = match fs::canonicalize(input) {
            Ok(path) => path,
            Err(error) => {
                self.status = format!("Could not resolve path: {error}");
                return;
            }
        };
        self.path = path.display().to_string();
        self.permission_denied = false;
        let found = list_processes(&path);
        let access_error = path_access_error(&path);

        match found {
            Ok(processes) => {
                self.processes = processes;
                self.selected
                    .retain(|pid| self.processes.iter().any(|process| process.pid == *pid));
                if self.processes.is_empty() {
                    if let Some(error) = access_error {
                        if error.kind() == std::io::ErrorKind::PermissionDenied {
                            self.permission_denied = true;
                            self.status =
                                "No open files found; this path is inaccessible.".to_string();
                            return;
                        }
                        self.status = format!("Could not access path: {error}");
                        return;
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
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
                {
                    self.permission_denied = true;
                    self.status = "The path is inaccessible.".to_string();
                    self.processes.clear();
                    self.selected.clear();
                } else {
                    self.status = error;
                }
            }
        }
    }

    fn path_changed(&mut self, path: PathBuf) {
        self.cancel_file_operation();
        self.path = path.display().to_string();
        self.processes.clear();
        self.selected.clear();
        self.permission_denied = false;
        self.status = "Path changed; select Scan.".to_string();
    }

    fn terminate_selected(&mut self) {
        let selected = self.selected.iter().copied().collect::<Vec<_>>();
        let mut outcomes = Vec::new();
        for pid in selected {
            if let Some(process) = self.processes.iter().find(|process| process.pid == pid) {
                match terminate(process) {
                    Ok(()) => outcomes.push(format!("SIGTERM sent to PID {pid}")),
                    Err(error) => outcomes.push(error),
                }
            }
        }

        self.confirm_termination = false;
        self.scan();
        if !outcomes.is_empty() {
            self.status = format!("{}; {}", outcomes.join("; "), self.status);
        }
    }

    fn begin_file_operation(&mut self, operation: Operation) {
        self.file_operation = Some(operation);
        self.password.zeroize();
        self.password_confirmation.zeroize();
        self.password_error.clear();
    }

    fn cancel_file_operation(&mut self) {
        self.password.zeroize();
        self.password_confirmation.zeroize();
        self.password_error.clear();
        self.file_operation = None;
    }

    fn apply_file_operation(&mut self, operation: Operation) {
        let password = Zeroizing::new(std::mem::take(&mut *self.password));
        let confirmation = Zeroizing::new(std::mem::take(&mut *self.password_confirmation));
        if matches!(operation, Operation::Lock) && password.as_bytes() != confirmation.as_bytes() {
            self.password_error = "Passwords did not match.".to_string();
            return;
        }

        let result = file_lock::run_with_password(
            operation,
            Path::new(self.path.trim()),
            password.as_bytes(),
        );
        self.cancel_file_operation();
        self.processes.clear();
        self.selected.clear();
        self.permission_denied = false;

        match result {
            Ok(summary) => {
                let mut status = format!(
                    "{} file(s) updated; {} file(s) skipped.",
                    summary.updated.len(),
                    summary.skipped
                );
                if !summary.failures.is_empty() {
                    status.push_str(&format!(
                        " {} failed: {}",
                        summary.failures.len(),
                        summary.failures.join("; ")
                    ));
                }
                if matches!(operation, Operation::Unlock) && summary.failures.is_empty() {
                    if let Err(error) = open_in_default_app(Path::new(self.path.trim())) {
                        status.push_str(&format!(" Unlocked, but could not open it: {error}"));
                    }
                }
                self.status = status;
            }
            Err(error) => self.status = error,
        }
    }

    fn update_view(&mut self, root_ui: &mut egui::Ui) {
        if self.scan_on_start {
            self.scan_on_start = false;
            self.scan();
        }
        let context = root_ui.ctx().clone();

        egui::CentralPanel::default().show(root_ui, |ui| {
            ui.heading("Locksmith");
            ui.label("Find processes holding open files and manage them safely.");
            ui.add_space(12.0);

            ui.horizontal(|ui| {
                ui.label("File or folder:");
                let path_changed = ui
                    .add(
                        egui::TextEdit::singleline(&mut self.path)
                            .desired_width(ui.available_width() - 230.0),
                    )
                    .changed();
                if path_changed {
                    self.cancel_file_operation();
                    self.processes.clear();
                    self.selected.clear();
                    self.permission_denied = false;
                    self.status = "Path changed; select Scan.".to_string();
                }
                if ui.button("Choose file...").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.path_changed(path);
                    }
                }
                if ui.button("Choose folder...").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        self.path_changed(path);
                    }
                }
            });

            ui.horizontal(|ui| {
                if ui.button("Scan").clicked() {
                    self.scan();
                }
                if ui.button("Select all").clicked() {
                    self.selected = self.processes.iter().map(|process| process.pid).collect();
                }
                if ui.button("Clear selection").clicked() {
                    self.selected.clear();
                }
                if ui
                    .add_enabled(
                        !self.selected.is_empty(),
                        egui::Button::new("Terminate selected"),
                    )
                    .clicked()
                {
                    self.confirm_termination = true;
                }
                if ui
                    .add_enabled(
                        !self.path.trim().is_empty(),
                        egui::Button::new("Lock files..."),
                    )
                    .clicked()
                {
                    self.begin_file_operation(Operation::Lock);
                }
                if ui
                    .add_enabled(
                        !self.path.trim().is_empty(),
                        egui::Button::new("Unlock & open..."),
                    )
                    .clicked()
                {
                    self.begin_file_operation(Operation::Unlock);
                }
            });

            ui.add_space(8.0);
            ui.label(&self.status);
            if self.permission_denied {
                ui.horizontal(|ui| {
                    ui.label("No process locks were found, but the path is inaccessible.");
                    if ui.button("Change owner permissions...").clicked() {
                        self.confirm_permissions = true;
                    }
                });
            }
            ui.separator();

            if self.processes.is_empty() {
                ui.label("No process entries to display.");
            } else {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Grid::new("process_table")
                            .striped(true)
                            .min_col_width(70.0)
                            .show(ui, |ui| {
                                ui.strong("Select");
                                ui.strong("PID");
                                ui.strong("UID");
                                ui.strong("Process");
                                ui.end_row();

                                for process in &self.processes {
                                    let mut selected = self.selected.contains(&process.pid);
                                    if ui.checkbox(&mut selected, "").changed() {
                                        if selected {
                                            self.selected.insert(process.pid);
                                        } else {
                                            self.selected.remove(&process.pid);
                                        }
                                    }
                                    ui.label(process.pid.to_string());
                                    ui.label(process.uid.to_string());
                                    ui.label(&process.name);
                                    ui.end_row();
                                }
                            });
                    });
            }
        });

        if self.confirm_termination {
            egui::Window::new("Confirm termination")
                .collapsible(false)
                .resizable(false)
                .show(&context, |ui| {
                    ui.label(format!(
                        "Send SIGTERM to {} selected process(es)?",
                        self.selected.len()
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Confirm").clicked() {
                            self.terminate_selected();
                        }
                        if ui.button("Cancel").clicked() {
                            self.confirm_termination = false;
                        }
                    });
                });
        }

        if self.confirm_permissions {
            egui::Window::new("Confirm permission change")
                .collapsible(false)
                .resizable(false)
                .show(&context, |ui| {
                    ui.label("Add owner read/write and directory traversal permissions?");
                    ui.label("This change applies only to the selected path.");
                    ui.horizontal(|ui| {
                        if ui.button("Confirm").clicked() {
                            match grant_owner_permissions(Path::new(self.path.trim())) {
                                Ok(()) => {
                                    self.confirm_permissions = false;
                                    self.permission_denied = false;
                                    self.status = "Owner permissions updated.".to_string();
                                    self.scan();
                                }
                                Err(error) => self.status = error,
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.confirm_permissions = false;
                        }
                    });
                });
        }

        if let Some(operation) = self.file_operation {
            let title = match operation {
                Operation::Lock => "Lock files",
                Operation::Unlock => "Unlock files",
            };
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .show(&context, |ui| {
                    ui.label(match operation {
                        Operation::Lock => {
                            "Enter a password (at least 12 characters). It cannot be recovered."
                        }
                        Operation::Unlock => {
                            "Enter the correct password to unlock and open the file or folder."
                        }
                    });
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.password)
                            .password(true)
                            .hint_text("Password"),
                    );
                    if matches!(operation, Operation::Lock) {
                        ui.add(
                            egui::TextEdit::singleline(&mut *self.password_confirmation)
                                .password(true)
                                .hint_text("Confirm password"),
                        );
                    }
                    if !self.password_error.is_empty() {
                        ui.colored_label(egui::Color32::RED, &self.password_error);
                    }
                    ui.horizontal(|ui| {
                        let label = match operation {
                            Operation::Lock => "Lock",
                            Operation::Unlock => "Unlock & open",
                        };
                        if ui.button(label).clicked() {
                            self.apply_file_operation(operation);
                        }
                        if ui.button("Cancel").clicked() {
                            self.cancel_file_operation();
                        }
                    });
                });
        }
    }
}

impl eframe::App for LocksmithGui {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.update_view(ui);
    }
}

fn open_in_default_app(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let status = Command::new("open").arg(path).status();
    #[cfg(target_os = "linux")]
    let status = Command::new("xdg-open").arg(path).status();

    let status = status.map_err(|error| format!("Could not launch the default app: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("Default app exited with status {status}"))
    }
}
