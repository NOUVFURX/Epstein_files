use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(target_os = "macos")]
use std::sync::mpsc::{self, Receiver, TryRecvError};
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::Duration;

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
    locked_files: Vec<PathBuf>,
    locked_files_error: Option<String>,
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
    #[cfg(target_os = "macos")]
    save_password_for_touch_id: bool,
    #[cfg(target_os = "macos")]
    touch_id_password_rx: Option<(u64, String, Receiver<Result<Zeroizing<Vec<u8>>, String>>)>,
    #[cfg(target_os = "macos")]
    touch_id_request_id: u64,
    #[cfg(target_os = "macos")]
    touch_id_setup_open: bool,
    #[cfg(target_os = "macos")]
    touch_id_setup_password: Zeroizing<String>,
    #[cfg(target_os = "macos")]
    touch_id_setup_confirmation: Zeroizing<String>,
    #[cfg(target_os = "macos")]
    touch_id_setup_error: String,
    #[cfg(target_os = "macos")]
    open_with_app: Option<PathBuf>,
}

impl LocksmithGui {
    fn new(initial_path: Option<PathBuf>) -> Self {
        let scan_on_start = initial_path.is_some();
        Self {
            path: initial_path
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            processes: Vec::new(),
            locked_files: Vec::new(),
            locked_files_error: None,
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
            #[cfg(target_os = "macos")]
            save_password_for_touch_id: false,
            #[cfg(target_os = "macos")]
            touch_id_password_rx: None,
            #[cfg(target_os = "macos")]
            touch_id_request_id: 0,
            #[cfg(target_os = "macos")]
            touch_id_setup_open: false,
            #[cfg(target_os = "macos")]
            touch_id_setup_password: Zeroizing::new(String::new()),
            #[cfg(target_os = "macos")]
            touch_id_setup_confirmation: Zeroizing::new(String::new()),
            #[cfg(target_os = "macos")]
            touch_id_setup_error: String::new(),
            #[cfg(target_os = "macos")]
            open_with_app: None,
        }
    }

    fn scan(&mut self) {
        self.permission_denied = false;
        self.processes.clear();
        self.locked_files.clear();
        self.locked_files_error = None;
        self.selected.clear();
        let input = Path::new(self.path.trim());
        if input.as_os_str().is_empty() {
            self.status = "Enter a file or folder path.".to_string();
            self.locked_files_error = Some("Enter a path to list locked files.".to_string());
            return;
        }

        match fs::metadata(input) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.status = format!("Path does not exist: {}", input.display());
                self.locked_files_error = Some(self.status.clone());
                self.processes.clear();
                self.selected.clear();
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                self.status = format!("Permission denied for: {}", input.display());
                self.locked_files_error = Some(self.status.clone());
                self.permission_denied = true;
                self.processes.clear();
                self.selected.clear();
                return;
            }
            Err(error) => {
                self.status = format!("Could not inspect path: {error}");
                self.locked_files_error = Some(self.status.clone());
                return;
            }
        }

        let path = match fs::canonicalize(input) {
            Ok(path) => path,
            Err(error) => {
                self.status = format!("Could not resolve path: {error}");
                self.locked_files_error = Some(self.status.clone());
                return;
            }
        };
        self.path = path.display().to_string();
        self.refresh_locked_files(&path);
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
        self.locked_files.clear();
        self.locked_files_error = None;
        self.selected.clear();
        self.permission_denied = false;
        self.status = "Path changed; select Scan.".to_string();
    }

    fn refresh_locked_files(&mut self, path: &Path) {
        match file_lock::find_locked_files(path) {
            Ok(files) => {
                self.locked_files = files;
                self.locked_files_error = None;
            }
            Err(error) => {
                self.locked_files.clear();
                self.locked_files_error = Some(error);
            }
        }
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
        #[cfg(target_os = "macos")]
        {
            self.touch_id_request_id = self.touch_id_request_id.wrapping_add(1);
        }
        self.file_operation = Some(operation);
        self.password.zeroize();
        self.password_confirmation.zeroize();
        self.password_error.clear();
        #[cfg(target_os = "macos")]
        {
            self.save_password_for_touch_id = false;
        }
    }

    fn cancel_file_operation(&mut self) {
        #[cfg(target_os = "macos")]
        {
            self.touch_id_request_id = self.touch_id_request_id.wrapping_add(1);
        }
        self.password.zeroize();
        self.password_confirmation.zeroize();
        self.password_error.clear();
        self.file_operation = None;
        #[cfg(target_os = "macos")]
        {
            self.save_password_for_touch_id = false;
        }
    }

    fn apply_file_operation(&mut self, operation: Operation) {
        let password = Zeroizing::new(std::mem::take(&mut *self.password).into_bytes());
        let confirmation =
            Zeroizing::new(std::mem::take(&mut *self.password_confirmation).into_bytes());
        if matches!(operation, Operation::Lock) && password.as_slice() != confirmation.as_slice() {
            self.password_error = "Passwords did not match.".to_string();
            return;
        }

        let save_password_for_touch_id = {
            #[cfg(target_os = "macos")]
            {
                self.save_password_for_touch_id
            }
            #[cfg(not(target_os = "macos"))]
            {
                false
            }
        };
        self.apply_file_operation_with_password(
            operation,
            password.as_slice(),
            save_password_for_touch_id,
            false,
        );
    }

    fn apply_file_operation_with_password(
        &mut self,
        operation: Operation,
        password: &[u8],
        _save_password_for_touch_id: bool,
        offer_password_fallback: bool,
    ) {
        let target_path = PathBuf::from(self.path.trim());
        let result = file_lock::run_with_password(operation, &target_path, password);
        self.refresh_locked_files(&target_path);
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
                if offer_password_fallback && !summary.failures.is_empty() {
                    self.status = status;
                    self.password_error =
                        "The saved Touch ID passphrase did not unlock all files. Enter the master passphrase to retry.".to_string();
                    return;
                }
                self.cancel_file_operation();
                #[cfg(target_os = "macos")]
                if matches!(operation, Operation::Lock) && _save_password_for_touch_id {
                    if !summary.updated.is_empty() && summary.failures.is_empty() {
                        match crate::biometric::store_password(password) {
                            Ok(()) => status.push_str(" Passphrase saved for Touch ID unlock."),
                            Err(error) => {
                                status.push_str(&format!(" Touch ID setup failed: {error}"));
                            }
                        }
                    } else {
                        status.push_str(
                            " Touch ID was not enabled because the files did not all lock successfully.",
                        );
                    }
                }
                if matches!(operation, Operation::Unlock) && summary.updated.is_empty() {
                    status.push_str(" No Locksmith-locked files were unlocked.");
                }
                if matches!(operation, Operation::Unlock)
                    && !summary.updated.is_empty()
                    && summary.failures.is_empty()
                {
                    let application = {
                        #[cfg(target_os = "macos")]
                        {
                            self.open_with_app.as_deref()
                        }
                        #[cfg(not(target_os = "macos"))]
                        {
                            None
                        }
                    };
                    if let Err(error) = open_in_app(Path::new(self.path.trim()), application) {
                        status.push_str(&format!(" Unlocked, but could not open it: {error}"));
                    }
                }
                self.status = status;
            }
            Err(error) if offer_password_fallback => {
                self.password_error =
                    format!("{error}. Enter the master passphrase to unlock instead.");
            }
            Err(error) => {
                self.cancel_file_operation();
                self.status = error;
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn unlock_with_touch_id(&mut self, context: &egui::Context) {
        if self.touch_id_password_rx.is_some() {
            return;
        }

        let (sender, receiver) = mpsc::channel();
        self.touch_id_request_id = self.touch_id_request_id.wrapping_add(1);
        let request_id = self.touch_id_request_id;
        let path = self.path.clone();
        self.touch_id_password_rx = Some((request_id, path.clone(), receiver));
        self.password_error.clear();
        self.status = "Waiting for Touch ID...".to_string();
        context.request_repaint_after(Duration::from_millis(100));

        if let Err(error) = thread::Builder::new()
            .name("locksmith-touch-id".to_string())
            .spawn(move || {
                let result = crate::biometric::authenticate_and_load_password();
                let _ = sender.send(result);
            })
        {
            self.touch_id_password_rx = None;
            self.password_error = format!("Could not start Touch ID authentication: {error}");
        }
    }

    #[cfg(target_os = "macos")]
    fn begin_touch_id_setup(&mut self) {
        self.touch_id_setup_password.zeroize();
        self.touch_id_setup_confirmation.zeroize();
        self.touch_id_setup_error.clear();
        self.touch_id_setup_open = true;
    }

    #[cfg(target_os = "macos")]
    fn apply_touch_id_setup(&mut self) {
        let password = Zeroizing::new(std::mem::take(&mut *self.touch_id_setup_password));
        let confirmation = Zeroizing::new(std::mem::take(&mut *self.touch_id_setup_confirmation));

        if password.chars().count() < 12 {
            self.touch_id_setup_error =
                "Use the same passphrase as your locked files (at least 12 characters)."
                    .to_string();
            return;
        }
        if password.as_bytes() != confirmation.as_bytes() {
            self.touch_id_setup_error = "Passphrases did not match.".to_string();
            return;
        }

        match crate::biometric::store_password(password.as_bytes()) {
            Ok(()) => {
                self.touch_id_setup_open = false;
                self.touch_id_setup_error.clear();
                self.status =
                    "Passphrase saved; Touch ID will be checked when unlocking.".to_string();
            }
            Err(error) => self.touch_id_setup_error = error,
        }
    }

    #[cfg(target_os = "macos")]
    fn poll_touch_id_unlock(&mut self) {
        let result = self
            .touch_id_password_rx
            .as_ref()
            .and_then(|(request_id, path, receiver)| match receiver.try_recv() {
                Ok(result) => Some((*request_id, path.clone(), result)),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some((
                    *request_id,
                    path.clone(),
                    Err("Touch ID authentication ended without a result.".to_string()),
                )),
            });

        if let Some((request_id, path, result)) = result {
            self.touch_id_password_rx = None;
            if request_id != self.touch_id_request_id
                || !matches!(self.file_operation, Some(Operation::Unlock))
                || self.path != path
            {
                return;
            }
            match result {
                Ok(password) => {
                    self.apply_file_operation_with_password(
                        Operation::Unlock,
                        &password,
                        false,
                        true,
                    );
                }
                Err(error) => {
                    self.password_error =
                        format!("{error}. Enter the master passphrase to unlock instead.");
                }
            }
        }
    }

    fn update_view(&mut self, root_ui: &mut egui::Ui) {
        if self.scan_on_start {
            self.scan_on_start = false;
            self.scan();
        }
        #[cfg(target_os = "macos")]
        self.poll_touch_id_unlock();
        let context = root_ui.ctx().clone();
        #[cfg(target_os = "macos")]
        if self.touch_id_password_rx.is_some() {
            context.request_repaint_after(Duration::from_millis(100));
        }

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
                    self.locked_files.clear();
                    self.locked_files_error = None;
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
                #[cfg(target_os = "macos")]
                if ui.button("Set up Face Lock...").clicked() {
                    self.begin_touch_id_setup();
                }
            });

            let locked_files = self.locked_files.clone();
            let locked_files_error = self.locked_files_error.clone();
            let mut unlock_path = None;
            egui::CollapsingHeader::new(format!(
                "Locked files under selected path ({})",
                locked_files.len()
            ))
            .default_open(true)
            .show(ui, |ui| {
                ui.label("The list uses Locksmith's unreadable and immutable file flags.");
                if let Some(error) = &locked_files_error {
                    ui.colored_label(egui::Color32::RED, error);
                } else if locked_files.is_empty() {
                    if self.path.trim().is_empty() {
                        ui.label("Enter a file or folder path to list locked files.");
                    } else {
                        ui.label("No locked files found. Select Scan to refresh this list.");
                    }
                } else {
                    egui::ScrollArea::vertical()
                        .max_height(180.0)
                        .show(ui, |ui| {
                            for file in &locked_files {
                                ui.horizontal(|ui| {
                                    ui.label(file.display().to_string());
                                    if ui.button("Unlock...").clicked() {
                                        unlock_path = Some(file.clone());
                                    }
                                });
                            }
                        });
                }
            });
            if let Some(path) = unlock_path {
                self.path_changed(path);
                self.begin_file_operation(Operation::Unlock);
            }

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
                    #[cfg(target_os = "macos")]
                    if matches!(operation, Operation::Lock) {
                        ui.checkbox(
                            &mut self.save_password_for_touch_id,
                            "Save this passphrase for Touch ID unlock",
                        );
                        ui.label(
                            "Locksmith will ask for Touch ID before reading this passphrase from your login Keychain.",
                        );
                    }
                    #[cfg(target_os = "macos")]
                    if matches!(operation, Operation::Unlock) {
                        ui.label("Use Touch ID to unlock without typing the master passphrase.");
                        ui.label(
                            "Unlocking restores the file contents in place before opening them.",
                        );
                        ui.horizontal(|ui| {
                            if ui.button("Choose app to open with...").clicked() {
                                self.open_with_app = rfd::FileDialog::new()
                                    .set_title("Choose an application")
                                    .pick_file();
                            }
                            let app_name = self
                                .open_with_app
                                .as_deref()
                                .and_then(Path::file_name)
                                .map(|name| name.to_string_lossy().into_owned())
                                .unwrap_or_else(|| "Default app".to_string());
                            ui.label(format!("Open with: {app_name}"));
                        });
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(
                                    self.touch_id_password_rx.is_none(),
                                    egui::Button::new("Unlock with Touch ID"),
                                )
                                .clicked()
                            {
                                self.unlock_with_touch_id(&context);
                            }
                            if ui
                                .add_enabled(
                                    self.touch_id_password_rx.is_none(),
                                    egui::Button::new("Remove saved Touch ID passphrase"),
                                )
                                .clicked()
                            {
                                match crate::biometric::remove_password() {
                                    Ok(()) => {
                                        self.password_error.clear();
                                        self.status =
                                            "Saved Touch ID passphrase removed.".to_string();
                                    }
                                    Err(error) => self.password_error = error,
                                }
                            }
                        });
                    }
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

        #[cfg(target_os = "macos")]
        if self.touch_id_setup_open {
            egui::Window::new("Set up Face Lock")
                .collapsible(false)
                .resizable(false)
                .show(&context, |ui| {
                    ui.label("On macOS, Face Lock uses Touch ID; Macs do not provide Face ID.");
                    ui.label(
                        "Enter the same passphrase used for your locked files. Touch ID will replace typing it when you unlock.",
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.touch_id_setup_password)
                            .password(true)
                            .hint_text("Master passphrase"),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.touch_id_setup_confirmation)
                            .password(true)
                            .hint_text("Confirm master passphrase"),
                    );
                    if !self.touch_id_setup_error.is_empty() {
                        ui.colored_label(egui::Color32::RED, &self.touch_id_setup_error);
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Set up Face Lock").clicked() {
                            self.apply_touch_id_setup();
                        }
                        if ui.button("Cancel").clicked() {
                            self.touch_id_setup_password.zeroize();
                            self.touch_id_setup_confirmation.zeroize();
                            self.touch_id_setup_error.clear();
                            self.touch_id_setup_open = false;
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

fn open_in_app(path: &Path, _application: Option<&Path>) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let status = {
        let mut command = Command::new("open");
        if let Some(application) = _application {
            command.arg("-a").arg(application);
        }
        command.arg(path).status()
    };
    #[cfg(target_os = "linux")]
    let status = Command::new("xdg-open").arg(path).status();

    let status = status.map_err(|error| format!("Could not launch the default app: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("Default app exited with status {status}"))
    }
}
