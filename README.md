# FURX-LOCK

`FURX-LOCK` is a Rust desktop app and command-line utility for finding processes
with open file descriptors on a file or directory. Directory scans are
recursive and use `lsof`; `lsof` and `ps` must be available on `PATH`.

Build and run:

```sh
cargo build --release
./target/release/furx-lock
```

Starting without arguments opens the native desktop window, where you can enter
a path or choose a file/folder and scan it. The helper script does the same and
builds the release executable:

```sh
./run.sh
```

You can optionally pass a path to prefill and scan it in the GUI:

```sh
./run.sh /path/to/file-or-folder
```

### Install the Linux desktop launcher

Linux builds include X11 and Wayland support and use the XDG portal for file
selection. A prebuilt Linux x86_64 archive is published on each version tag:

[Download FURX-LOCK for Linux](https://github.com/NOUVFURX/Epstein_files/releases/latest/download/furx-lock-linux-x86_64.tar.gz)

Extract the archive, then install the executable and application-menu entry
for the current user:

```sh
tar -xzf furx-lock-linux-x86_64.tar.gz
install -Dm755 furx-lock/furx-lock "$HOME/.local/bin/furx-lock"
install -Dm644 furx-lock/furx-lock.desktop \
  "$HOME/.local/share/applications/furx-lock.desktop"
```

To build from source instead:

```sh
cargo build --release
```

The **FURX-LOCK** launcher will then appear in the desktop application menu.

In the GUI, select processes in the results table and confirm before sending
them `SIGTERM`. Use `--plain <file-or-directory>` for the prompt-based terminal
interface. The GUI also provides **Lock files** and **Unlock & open** actions.
On macOS, you can optionally save the passphrase in the Keychain behind Touch
ID and use it to unlock files; the master passphrase remains available as a
fallback.
The app also supports `lock` and `unlock` commands below.

Selected processes receive `SIGTERM` (not a force kill), after confirmation.
If there are no matching processes and the path is inaccessible, the tool can
add owner read/write permissions and directory traversal permission where
applicable. Permission changes apply only to the specified path, never
recursively.

## Password-locking files

Lock or unlock one regular file or recursively process regular files in a
directory:

```sh
./run.sh lock <file-or-directory>
./run.sh unlock <file-or-directory>
```

The password is entered through a hidden prompt, never as a command-line
argument. Locking replaces each file in place with chunked AES-256-GCM
ciphertext, derives keys with Argon2id, and restricts the encrypted file to
no read/write permissions (`000`) and applies an OS immutable flag to prevent
ordinary opens and deletion. On macOS this uses `uchg`; on Linux it uses
`chattr +i` and may require privileges or filesystem support. Unlocking
temporarily restores access, then restores the original file contents and
permission bits after successful authentication. Failed unlock attempts
restore the locked state.

These OS protections are safeguards, not tamper-proof security: an
administrator (and, depending on platform configuration, the file owner) can
deliberately clear immutable flags. A salted password verifier is stored in
each encrypted file as requested; it enables offline password guessing, so
choose a strong password. The plaintext password is not stored in the
encrypted file.

On macOS, the optional Touch ID feature stores the passphrase in the login
Keychain and requires a Touch ID prompt in FURX-LOCK before retrieving it. It
is available only in the GUI, only on that Mac. Use **Set up Face Lock** in
the main window, entering the same passphrase used for your files; you can
also save a passphrase when locking files. In the unlock dialog, choose
**Unlock with Touch ID** and optionally **Choose app to open with...**. The
chosen app opens the decrypted file without asking for the master passphrase.
Unlocking restores plaintext in place, so relock the file after use if needed.

The saved credential can be removed from the unlock dialog. The biometric
prompt is an application-level gate; it does not protect against malicious
software running as the same macOS user. If authentication is unavailable,
canceled, or fails, enter the master passphrase instead. This feature uses
Touch ID, not Face ID. Windows Hello support is not included.

The GUI's **Locked files under selected path** list shows regular files marked
unreadable and immutable by FURX-LOCK. Unlocking still verifies the encrypted
file format before restoring contents.

Back up important files before locking: losing the password makes the contents
unrecoverable. Recursive runs skip symbolic links and can partially complete
if a file fails; each changed and failed file is reported. Files with multiple
hard links are refused to avoid leaving plaintext through another link.