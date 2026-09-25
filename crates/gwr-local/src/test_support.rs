//! Test-only helpers shared by unit tests that execute programs they create.
//!
//! Unit tests run as threads of one process, and many of them spawn children.
//! A child created by `fork` holds a copy of every descriptor the parent had
//! open at that instant until it calls `exec`. If one test thread still holds
//! a freshly written script open for writing (for example during `sync_all`)
//! while a sibling thread forks, the script's inode keeps a writer, and
//! `execve` of that script fails with `ETXTBSY` ("Text file busy").
//!
//! The cure is to never hold a write descriptor for an executed file in the
//! test process: the bytes are written by a short-lived child process, whose
//! descriptors close before it exits and cannot leak into sibling forks.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

/// Creates or replaces `path` with `bytes` and mode 0700 without this process
/// ever opening `path` for writing.
pub(crate) fn write_executable(path: &Path, bytes: &[u8]) {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "umask 077 && cat > \"$1\" && chmod 700 \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn executable writer");
    child
        .stdin
        .take()
        .expect("writer stdin")
        .write_all(bytes)
        .expect("write executable bytes");
    assert!(
        child.wait().expect("wait executable writer").success(),
        "executable writer failed for {}",
        path.display()
    );
}
