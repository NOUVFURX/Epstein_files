use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

#[cfg(target_os = "macos")]
mod biometric;
mod file_lock;
mod gui;

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

fn grant_owner_permissions(path: &Path) -> Result<(), String> {
    let status = Command::new("chmod")
        .arg("u+rwX")
        .arg(path)
        .status()
        .map_err(|error| format!("Could not run chmod: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("chmod failed with status {status}"))
    }
}

fn process_table(processes: &[ProcessInfo]) {
    println!("{:<10} {:<10} PROCESS", "PID", "UID");
    println!("{}", "-".repeat(54));
    for process in processes {
        println!("{:<10} {:<10} {}", process.pid, process.uid, process.name);
    }
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

fn run_plain(path: PathBuf) -> Result<(), String> {
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

        process_table(&processes);
        println!(
            "\nEnter comma-separated PIDs to send SIGTERM, 'all' for every listed PID, or 'q' to quit."
        );
        let choice = prompt_line("Action: ")?;
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
        ))?;
        if !confirmation.eq_ignore_ascii_case("y") {
            continue;
        }

        for pid in selected {
            if let Some(process) = processes.iter().find(|process| process.pid == pid) {
                match terminate(process) {
                    Ok(()) => println!("Sent SIGTERM to PID {} ({}).", process.pid, process.name),
                    Err(error) => eprintln!("{error}"),
                }
            }
        }
        println!();
    }
}

fn prompt_line(prompt: &str) -> Result<String, String> {
    use std::io::Write;
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|error| format!("Could not display prompt: {error}"))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| format!("Could not read input: {error}"))?;
    Ok(input.trim().to_string())
}

fn offer_permissions(path: &Path) -> Result<(), String> {
    println!("No process locks were found, but the path is inaccessible.");
    let answer = prompt_line(
        "Add read/write access for the file owner (and directory traversal if needed)? [y/N]: ",
    )?;
    if answer.eq_ignore_ascii_case("y") {
        grant_owner_permissions(path)?;
        println!("Owner permissions updated for this path only. Run FURX-LOCK again to rescan.");
    }
    Ok(())
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

fn print_usage(program: &std::ffi::OsStr) {
    println!(
        "Usage:\n  {} [gui [file-or-directory]]\n  {} --plain <file-or-directory>\n  {} <lock|unlock> <file-or-directory>",
        Path::new(program).display(),
        Path::new(program).display(),
        Path::new(program).display(),
    );
}

fn report(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let Some(first) = args.next() else {
        return report(gui::launch(None));
    };

    if first == "--help" || first == "-h" {
        print_usage(&program);
        return ExitCode::SUCCESS;
    }

    if first == "gui" {
        let path = args.next().map(PathBuf::from);
        if args.next().is_some() {
            print_usage(&program);
            return ExitCode::from(2);
        }
        return report(gui::launch(path));
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
        return report(file_lock::run(operation, Path::new(&path)));
    }

    if first == "--plain" {
        let Some(path) = args.next() else {
            print_usage(&program);
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            print_usage(&program);
            return ExitCode::from(2);
        }
        return report(run_plain(PathBuf::from(path)));
    }

    if args.next().is_some() {
        print_usage(&program);
        return ExitCode::from(2);
    }
    report(gui::launch(Some(PathBuf::from(first))))
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
