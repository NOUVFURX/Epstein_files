use std::fs::{self, File, Permissions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{inout::InOutBuf, AeadInOut, KeyInit};
use aes_gcm::{aead::array::Array, Aes256Gcm};
use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"LOCKSMTH";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_PREFIX_LEN: usize = 4;
const VERIFIER_LEN: usize = 32;
const HEADER_TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 1 + SALT_LEN + NONCE_PREFIX_LEN + 4 + 8 + 4 + 4 + VERIFIER_LEN;
const MODE_OFFSET: usize = 29;
const LENGTH_OFFSET: usize = 33;
const ARGON_MEMORY_OFFSET: usize = 41;
const ARGON_ITERATIONS_OFFSET: usize = 45;
const VERIFIER_OFFSET: usize = 49;
const CHUNK_SIZE: usize = 1024 * 1024;
const TAG_LEN: usize = 16;
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_ITERATIONS: u32 = 3;

#[derive(Clone, Copy)]
pub enum Operation {
    Lock,
    Unlock,
}

pub struct OperationSummary {
    pub updated: Vec<PathBuf>,
    pub skipped: usize,
    pub failures: Vec<String>,
}

pub fn run(operation: Operation, input_path: &Path) -> Result<(), String> {
    let (_, files) = collect_target_files(input_path)?;
    if files.is_empty() {
        println!("No regular files found.");
        return Ok(());
    }

    let password = Zeroizing::new(
        rpassword::prompt_password(match operation {
            Operation::Lock => "Encryption password: ",
            Operation::Unlock => "Decryption password: ",
        })
        .map_err(|error| format!("Could not read password: {error}"))?,
    );
    if password.chars().count() < 12 {
        return Err("Use a password with at least 12 characters.".to_string());
    }
    if matches!(operation, Operation::Lock) {
        let confirmation = Zeroizing::new(
            rpassword::prompt_password("Confirm password: ")
                .map_err(|error| format!("Could not read password confirmation: {error}"))?,
        );
        if password
            .as_bytes()
            .ct_eq(confirmation.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err("Passwords did not match.".to_string());
        }
    }

    let summary = process_files(operation, files, password.as_bytes());
    for path in &summary.updated {
        println!("Updated {}", path.display());
    }
    println!(
        "{} file(s) updated; {} file(s) skipped.",
        summary.updated.len(),
        summary.skipped
    );
    if summary.failures.is_empty() {
        Ok(())
    } else {
        for failure in &summary.failures {
            eprintln!("Error: {failure}");
        }
        Err(format!(
            "{} file(s) failed. Recursive operations can partially complete; review the reported files.",
            summary.failures.len()
        ))
    }
}

pub fn run_with_password(
    operation: Operation,
    input_path: &Path,
    password: &[u8],
) -> Result<OperationSummary, String> {
    if matches!(operation, Operation::Lock)
        && std::str::from_utf8(password)
            .map(|password| password.chars().count() < 12)
            .unwrap_or(true)
    {
        return Err("Use a password with at least 12 characters.".to_string());
    }
    let (_, files) = collect_target_files(input_path)?;
    Ok(process_files(operation, files, password))
}

fn collect_target_files(input_path: &Path) -> Result<(PathBuf, Vec<PathBuf>), String> {
    let metadata = fs::symlink_metadata(input_path)
        .map_err(|error| format!("Could not inspect '{}': {error}", input_path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err("Refusing to lock or unlock a symbolic link.".to_string());
    }
    let path = fs::canonicalize(input_path)
        .map_err(|error| format!("Could not resolve '{}': {error}", input_path.display()))?;
    let files = collect_regular_files(&path)
        .map_err(|error| format!("Could not scan '{}': {error}", path.display()))?;
    Ok((path, files))
}

fn process_files(operation: Operation, files: Vec<PathBuf>, password: &[u8]) -> OperationSummary {
    let mut summary = OperationSummary {
        updated: Vec::new(),
        skipped: 0,
        failures: Vec::new(),
    };
    for path in files {
        let result = match operation {
            Operation::Lock => lock_file(&path, password),
            Operation::Unlock => unlock_file(&path, password),
        };
        match result {
            Ok(true) => summary.updated.push(path),
            Ok(false) => summary.skipped += 1,
            Err(error) => summary
                .failures
                .push(format!("{}: {error}", path.display())),
        }
    }
    summary
}

fn collect_regular_files(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut pending = vec![path.to_path_buf()];
    let mut files = Vec::new();

    while let Some(current) = pending.pop() {
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_file() {
            files.push(current);
        } else if metadata.is_dir() {
            for entry in fs::read_dir(current)? {
                pending.push(entry?.path());
            }
        }
    }

    files.sort();
    Ok(files)
}

fn read_header(file: &mut File) -> Result<Option<[u8; HEADER_LEN]>, String> {
    let mut prefix = [0u8; 9];
    match file.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            file.seek(SeekFrom::Start(0))
                .map_err(|error| format!("Could not rewind file: {error}"))?;
            return Ok(None);
        }
        Err(error) => return Err(format!("Could not read file header: {error}")),
    }
    if &prefix[..8] != MAGIC {
        file.seek(SeekFrom::Start(0))
            .map_err(|error| format!("Could not rewind file: {error}"))?;
        return Ok(None);
    }
    if prefix[8] != VERSION {
        return Err(format!("Unsupported locksmith file version: {}", prefix[8]));
    }

    let mut header = [0u8; HEADER_LEN];
    header[..prefix.len()].copy_from_slice(&prefix);
    file.read_exact(&mut header[prefix.len()..])
        .map_err(|error| format!("Encrypted file header is incomplete: {error}"))?;
    Ok(Some(header))
}

fn derive_material(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 64]>, String> {
    let params = Params::new(ARGON_MEMORY_KIB, ARGON_ITERATIONS, 1, Some(64))
        .map_err(|error| format!("Invalid Argon2 parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut material = Zeroizing::new([0u8; 64]);
    argon2
        .hash_password_into(password, salt, material.as_mut())
        .map_err(|error| format!("Could not derive key from password: {error}"))?;
    Ok(material)
}

fn make_cipher(material: &[u8]) -> Result<Aes256Gcm, String> {
    Aes256Gcm::new_from_slice(&material[..32])
        .map_err(|error| format!("Could not initialize encryption: {error}"))
}

fn cipher_nonce(bytes: [u8; 12]) -> Array<u8, aes_gcm::aead::consts::U12> {
    Array::from(bytes)
}

fn chunk_nonce(prefix: &[u8], index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn chunk_aad(header: &[u8; HEADER_LEN], index: u64, length: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + 12);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&(length as u32).to_be_bytes());
    aad
}

fn create_temp(path: &Path, mode: u32) -> Result<NamedTempFile, String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temp = NamedTempFile::new_in(parent)
        .map_err(|error| format!("Could not create temporary file: {error}"))?;
    temp.as_file()
        .set_permissions(Permissions::from_mode(mode))
        .map_err(|error| format!("Could not set temporary file permissions: {error}"))?;
    Ok(temp)
}

fn persist_temp(
    temp: NamedTempFile,
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), String> {
    let result = unsafe { libc::fchown(std::os::fd::AsRawFd::as_raw_fd(temp.as_file()), uid, gid) };
    if result != 0 {
        return Err(format!(
            "Could not preserve file ownership: {}",
            io::Error::last_os_error()
        ));
    }
    temp.as_file()
        .set_permissions(Permissions::from_mode(mode))
        .map_err(|error| format!("Could not set file permissions: {error}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|error| format!("Could not flush temporary file: {error}"))?;
    temp.persist(path)
        .map_err(|error| format!("Could not replace the original file: {}", error.error))?;
    Ok(())
}

fn unchanged_source(path: &Path, original: &fs::Metadata) -> Result<(), String> {
    let current = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not recheck source file: {error}"))?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || current.dev() != original.dev()
        || current.ino() != original.ino()
        || current.len() != original.len()
        || current.mtime() != original.mtime()
        || current.mtime_nsec() != original.mtime_nsec()
        || current.ctime() != original.ctime()
        || current.ctime_nsec() != original.ctime_nsec()
    {
        return Err(
            "File changed while it was being processed; original was left unchanged.".to_string(),
        );
    }
    Ok(())
}

fn set_immutable(path: &Path, immutable: bool) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("chflags");
    #[cfg(target_os = "linux")]
    let mut command = std::process::Command::new("chattr");
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return Err("Immutable file flags are not supported on this platform.".to_string());

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let status = command
            .arg("--")
            .arg(if immutable {
                if cfg!(target_os = "macos") {
                    "uchg"
                } else {
                    "+i"
                }
            } else if cfg!(target_os = "macos") {
                "nouchg"
            } else {
                "-i"
            })
            .arg(path)
            .status()
            .map_err(|error| format!("Could not change immutable flag: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("Could not change immutable flag (status {status})"))
        }
    }
}

fn is_immutable(path: &Path, metadata: &fs::Metadata) -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        let _ = path;
        Ok(std::os::darwin::fs::MetadataExt::st_flags(metadata) & libc::UF_IMMUTABLE != 0)
    }
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("lsattr")
            .args(["-d", "--"])
            .arg(path)
            .output()
            .map_err(|error| format!("Could not inspect immutable flag: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "Could not inspect immutable flag (status {})",
                output.status
            ));
        }
        let flags = String::from_utf8_lossy(&output.stdout);
        Ok(flags
            .split_whitespace()
            .next()
            .is_some_and(|flags| flags.contains('i')))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (path, metadata);
        Ok(false)
    }
}

fn header_tag(
    cipher: &Aes256Gcm,
    nonce_prefix: &[u8],
    header: &[u8; HEADER_LEN],
) -> Result<[u8; HEADER_TAG_LEN], String> {
    let nonce = cipher_nonce(chunk_nonce(nonce_prefix, u64::MAX));
    let mut empty = [];
    let tag = cipher
        .encrypt_inout_detached(&nonce, header, InOutBuf::from(&mut empty[..]))
        .map_err(|_| "Could not authenticate encrypted file header.".to_string())?;
    let mut output = [0u8; HEADER_TAG_LEN];
    output.copy_from_slice(tag.as_slice());
    Ok(output)
}

fn verify_header_tag(
    cipher: &Aes256Gcm,
    nonce_prefix: &[u8],
    header: &[u8; HEADER_LEN],
    tag_bytes: [u8; HEADER_TAG_LEN],
) -> Result<(), String> {
    let nonce = cipher_nonce(chunk_nonce(nonce_prefix, u64::MAX));
    let tag = Array::from(tag_bytes);
    let mut empty = [];
    cipher
        .decrypt_inout_detached(&nonce, header, InOutBuf::from(&mut empty[..]), &tag)
        .map_err(|_| "Encrypted file header authentication failed.".to_string())
}

fn lock_file(path: &Path, password: &[u8]) -> Result<bool, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("Could not inspect file: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }
    if metadata.permissions().mode() & 0o777 == 0 && is_immutable(path, &metadata)? {
        return Ok(false);
    }
    if metadata.nlink() > 1 {
        return Err("Refusing to replace a file with multiple hard links because other links would remain unencrypted.".to_string());
    }

    let mut input = File::open(path).map_err(|error| format!("Could not open file: {error}"))?;
    if read_header(&mut input)?.is_some() {
        return Ok(false);
    }
    let open_metadata = input
        .metadata()
        .map_err(|error| format!("Could not inspect open file: {error}"))?;
    if open_metadata.dev() != metadata.dev() || open_metadata.ino() != metadata.ino() {
        return Err("File changed before encryption began.".to_string());
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    getrandom::fill(&mut salt).map_err(|error| format!("Could not generate salt: {error}"))?;
    getrandom::fill(&mut nonce_prefix)
        .map_err(|error| format!("Could not generate nonce: {error}"))?;
    let material = derive_material(password, &salt)?;
    let cipher = make_cipher(material.as_ref())?;
    let original_mode = metadata.permissions().mode() & 0o777;

    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION;
    header[9..25].copy_from_slice(&salt);
    header[25..29].copy_from_slice(&nonce_prefix);
    header[MODE_OFFSET..LENGTH_OFFSET].copy_from_slice(&original_mode.to_be_bytes());
    header[LENGTH_OFFSET..ARGON_MEMORY_OFFSET].copy_from_slice(&metadata.len().to_be_bytes());
    header[ARGON_MEMORY_OFFSET..ARGON_ITERATIONS_OFFSET]
        .copy_from_slice(&ARGON_MEMORY_KIB.to_be_bytes());
    header[ARGON_ITERATIONS_OFFSET..VERIFIER_OFFSET]
        .copy_from_slice(&ARGON_ITERATIONS.to_be_bytes());
    header[VERIFIER_OFFSET..HEADER_LEN].copy_from_slice(&material[32..]);
    let header_tag = header_tag(&cipher, &nonce_prefix, &header)?;

    let mut temp = create_temp(path, 0o600)?;
    temp.write_all(&header)
        .map_err(|error| format!("Could not write encrypted header: {error}"))?;
    temp.write_all(&header_tag)
        .map_err(|error| format!("Could not write encrypted header tag: {error}"))?;
    let mut remaining = metadata.len();
    let mut index = 0u64;
    while remaining > 0 {
        let length = remaining.min(CHUNK_SIZE as u64) as usize;
        let mut chunk = Zeroizing::new(vec![0u8; length]);
        input
            .read_exact(&mut chunk[..])
            .map_err(|error| format!("Could not read source file: {error}"))?;
        let nonce_bytes = chunk_nonce(&nonce_prefix, index);
        let aad = chunk_aad(&header, index, length);
        let nonce = cipher_nonce(nonce_bytes);
        let tag = cipher
            .encrypt_inout_detached(&nonce, &aad, InOutBuf::from(&mut chunk[..]))
            .map_err(|_| "Could not encrypt file chunk.".to_string())?;
        temp.write_all(&chunk)
            .and_then(|_| temp.write_all(tag.as_slice()))
            .map_err(|error| format!("Could not write encrypted file: {error}"))?;
        remaining -= length as u64;
        index += 1;
    }
    unchanged_source(path, &metadata)?;
    persist_temp(temp, path, metadata.uid(), metadata.gid(), 0o000)?;
    set_immutable(path, true).map_err(|error| {
        format!("File was encrypted and made unreadable, but deletion protection failed: {error}")
    })?;
    Ok(true)
}

fn unlock_file(path: &Path, password: &[u8]) -> Result<bool, String> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|error| format!("Could not inspect file: {error}"))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err("Refusing to unlock a symbolic link or non-regular file.".to_string());
    }
    let locked_mode = path_metadata.permissions().mode() & 0o777;
    let was_immutable = is_immutable(path, &path_metadata)?;
    if !was_immutable && locked_mode & 0o400 != 0 {
        return unlock_file_contents(path, password);
    }
    if was_immutable {
        set_immutable(path, false)?;
    }
    if let Err(error) = fs::set_permissions(path, Permissions::from_mode(locked_mode | 0o600)) {
        let mut message = format!("Could not temporarily access locked file: {error}");
        if was_immutable {
            if let Err(restore_error) = set_immutable(path, true) {
                message.push_str(&format!(
                    "; could not restore immutable flag: {restore_error}"
                ));
            }
        }
        return Err(message);
    }

    let result = unlock_file_contents(path, password);
    match result {
        Ok(true) => Ok(true),
        Ok(false) => {
            restore_locked_state(path, locked_mode, was_immutable)?;
            Ok(false)
        }
        Err(error) => match restore_locked_state(path, locked_mode, was_immutable) {
            Ok(()) => Err(error),
            Err(restore_error) => Err(format!("{error}; {restore_error}")),
        },
    }
}

fn restore_locked_state(path: &Path, mode: u32, immutable: bool) -> Result<(), String> {
    fs::set_permissions(path, Permissions::from_mode(mode))
        .map_err(|error| format!("Could not restore file permissions: {error}"))?;
    if immutable {
        set_immutable(path, true)?;
    }
    Ok(())
}

fn unlock_file_contents(path: &Path, password: &[u8]) -> Result<bool, String> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|error| format!("Could not inspect file: {error}"))?;
    let mut input = File::open(path).map_err(|error| format!("Could not open file: {error}"))?;
    let metadata = input
        .metadata()
        .map_err(|error| format!("Could not inspect open file: {error}"))?;
    if metadata.dev() != path_metadata.dev() || metadata.ino() != path_metadata.ino() {
        return Err("File changed before decryption began.".to_string());
    }
    let Some(header) = read_header(&mut input)? else {
        return Ok(false);
    };

    let salt = &header[9..25];
    let nonce_prefix = &header[25..29];
    let original_mode = u32::from_be_bytes(
        header[MODE_OFFSET..LENGTH_OFFSET]
            .try_into()
            .map_err(|_| "Invalid encrypted file mode.".to_string())?,
    );
    if original_mode & !0o777 != 0 {
        return Err("Encrypted file contains invalid permission metadata.".to_string());
    }
    let plaintext_length = u64::from_be_bytes(
        header[LENGTH_OFFSET..ARGON_MEMORY_OFFSET]
            .try_into()
            .map_err(|_| "Invalid encrypted file length.".to_string())?,
    );
    let memory_kib = u32::from_be_bytes(
        header[ARGON_MEMORY_OFFSET..ARGON_ITERATIONS_OFFSET]
            .try_into()
            .map_err(|_| "Invalid Argon2 memory metadata.".to_string())?,
    );
    let iterations = u32::from_be_bytes(
        header[ARGON_ITERATIONS_OFFSET..VERIFIER_OFFSET]
            .try_into()
            .map_err(|_| "Invalid Argon2 iteration metadata.".to_string())?,
    );
    if memory_kib != ARGON_MEMORY_KIB || iterations != ARGON_ITERATIONS {
        return Err("Unsupported Argon2 parameters in encrypted file.".to_string());
    }
    let expected_verifier = &header[VERIFIER_OFFSET..HEADER_LEN];
    let file_length = metadata.len();
    let chunks = plaintext_length
        .checked_add(CHUNK_SIZE as u64 - 1)
        .ok_or_else(|| "Encrypted file length is invalid.".to_string())?
        / CHUNK_SIZE as u64;
    let expected_length = chunks
        .checked_mul(TAG_LEN as u64)
        .and_then(|tag_bytes| plaintext_length.checked_add(tag_bytes))
        .and_then(|data_bytes| data_bytes.checked_add((HEADER_LEN + HEADER_TAG_LEN) as u64))
        .ok_or_else(|| "Encrypted file length is invalid.".to_string())?;
    if expected_length != file_length {
        return Err("Encrypted file length does not match its header.".to_string());
    }
    let mut stored_header_tag = [0u8; HEADER_TAG_LEN];
    input
        .read_exact(&mut stored_header_tag)
        .map_err(|error| format!("Encrypted file header tag is incomplete: {error}"))?;
    let material = derive_material(password, salt)?;
    if expected_verifier.ct_eq(&material[32..]).unwrap_u8() != 1 {
        return Err("Password did not match.".to_string());
    }
    let cipher = make_cipher(material.as_ref())?;
    verify_header_tag(&cipher, nonce_prefix, &header, stored_header_tag)?;

    let mut temp = create_temp(path, 0o600)?;
    let mut remaining = plaintext_length;
    let mut index = 0u64;
    while remaining > 0 {
        let length = remaining.min(CHUNK_SIZE as u64) as usize;
        let mut chunk = Zeroizing::new(vec![0u8; length]);
        let mut tag = [0u8; TAG_LEN];
        input
            .read_exact(&mut chunk)
            .and_then(|_| input.read_exact(&mut tag))
            .map_err(|error| format!("Encrypted file is truncated or damaged: {error}"))?;
        let nonce_bytes = chunk_nonce(nonce_prefix, index);
        let aad = chunk_aad(&header, index, length);
        let nonce = cipher_nonce(nonce_bytes);
        let tag = Array::from(tag);
        cipher
            .decrypt_inout_detached(&nonce, &aad, InOutBuf::from(&mut chunk[..]), &tag)
            .map_err(|_| format!("Authentication failed for encrypted chunk {index}."))?;
        temp.write_all(&chunk)
            .map_err(|error| format!("Could not write decrypted file: {error}"))?;
        remaining -= length as u64;
        index += 1;
    }
    unchanged_source(path, &metadata)?;
    persist_temp(temp, path, metadata.uid(), metadata.gid(), original_mode)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite_locked_file(path: &Path, bytes: &[u8]) {
        set_immutable(path, false).unwrap();
        fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, Permissions::from_mode(0o000)).unwrap();
        set_immutable(path, true).unwrap();
    }

    #[test]
    fn encrypts_and_restores_a_file_and_rejects_wrong_password() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notes.txt");
        let original = vec![b'x'; CHUNK_SIZE + 17];
        fs::write(&path, &original).unwrap();
        let original_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let password = b"correct horse battery staple";

        assert!(lock_file(&path, password).unwrap());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0);
        assert!(is_immutable(&path, &fs::metadata(&path).unwrap()).unwrap());
        assert!(fs::read(&path).is_err());
        assert!(fs::remove_file(&path).is_err());

        set_immutable(&path, false).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        let mut encrypted = fs::read(&path).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o000)).unwrap();
        set_immutable(&path, true).unwrap();
        assert!(unlock_file(&path, b"wrong password").is_err());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0);
        assert!(is_immutable(&path, &fs::metadata(&path).unwrap()).unwrap());

        set_immutable(&path, false).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        encrypted[MODE_OFFSET] ^= 1;
        rewrite_locked_file(&path, &encrypted);
        assert!(unlock_file(&path, password).is_err());
        encrypted[MODE_OFFSET] ^= 1;
        rewrite_locked_file(&path, &encrypted);
        assert!(unlock_file(&path, password).unwrap());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            original_mode
        );
    }

    #[test]
    fn encrypts_and_restores_empty_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty.txt");
        fs::write(&path, []).unwrap();
        let password = b"correct horse battery staple";

        assert!(lock_file(&path, password).unwrap());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0);
        assert!(unlock_file(&path, password).unwrap());
        assert!(fs::read(&path).unwrap().is_empty());
    }

    #[test]
    fn recursive_collection_skips_symbolic_links() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file.txt");
        fs::write(&file, b"contents").unwrap();
        let link = directory.path().join("link.txt");
        std::os::unix::fs::symlink(&file, &link).unwrap();

        let files = collect_regular_files(directory.path()).unwrap();
        assert_eq!(files, vec![file]);
    }
}
