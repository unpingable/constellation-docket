//! The production launcher path: `docket governed-loop standing-write-launcher`
//! writes the launcher in its own process, so a consumer that executes it is
//! not exposed to "Text file busy" even while its own threads fork.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn root(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "docket-launcher-cli-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir(&path).unwrap();
    path
}

fn write_launcher(resolver: &PathBuf, config: &PathBuf, output: &PathBuf) -> std::process::Output {
    let python = std::fs::canonicalize("/usr/bin/python3").unwrap();
    Command::new(env!("CARGO_BIN_EXE_docket"))
        .args(["governed-loop", "standing-write-launcher", "--resolver"])
        .arg(resolver)
        .arg("--config")
        .arg(config)
        .arg("--python-interpreter")
        .arg(python)
        .arg("--output")
        .arg(output)
        .output()
        .unwrap()
}

#[test]
fn cli_written_launcher_executes_while_consumer_threads_fork() {
    let root = root("fork-pressure");
    let resolver = root.join("resolver");
    let config = root.join("config.json");
    std::fs::write(&resolver, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(&config, b"{}\n").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let forkers: Vec<_> = (0..4)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = Command::new("/bin/true").status();
                }
            })
        })
        .collect();
    let mut failures = Vec::new();
    for n in 0..15 {
        let launcher = root.join(format!("launcher-{n}"));
        let written = write_launcher(&resolver, &config, &launcher);
        assert!(written.status.success(), "{written:?}");
        let mode = std::fs::metadata(&launcher).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        match Command::new(&launcher).status() {
            Ok(status) if status.success() => {}
            other => failures.push(format!("{n}: {other:?}")),
        }
    }
    stop.store(true, Ordering::Relaxed);
    for forker in forkers {
        forker.join().unwrap();
    }
    let again = write_launcher(&resolver, &config, &root.join("launcher-0"));
    assert!(
        !again.status.success(),
        "the launcher output is create-once"
    );
    let _ = std::fs::remove_dir_all(root);
    assert!(failures.is_empty(), "{failures:?}");
}
