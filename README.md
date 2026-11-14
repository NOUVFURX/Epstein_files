# locksmith

`locksmith` is a Rust command-line utility for finding processes with open file
descriptors on a file or directory. Directory scans are recursive and use
`lsof`; `lsof` and `ps` must be available on `PATH`.

Build and run:

```sh
cargo build --release
./target/release/locksmith
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

In the GUI, select processes in the results table and confirm before sending
them `SIGTERM`. Use `--plain <file-or-directory>` for the prompt-based terminal
interface. The GUI also provides **Lock files** and **Unlock & open** actions;
unlocking requires the correct password and does not attempt password guessing.
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
choose a strong password. The plaintext password is not stored.

Back up important files before locking: losing the password makes the contents
unrecoverable. Recursive runs skip symbolic links and can partially complete
if a file fails; each changed and failed file is reported. Files with multiple
hard links are refused to avoid leaving plaintext through another link.