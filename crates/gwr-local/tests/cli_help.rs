//! Root help is a no-state operator discovery surface.

use std::process::{Command, Output};

fn docket_help(flag: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_docket"))
        .arg(flag)
        .output()
        .expect("run docket help")
}

#[test]
fn root_help_flags_succeed_without_state_and_are_identical() {
    let long = docket_help("--help");
    let short = docket_help("-h");

    assert!(
        long.status.success(),
        "{}",
        String::from_utf8_lossy(&long.stderr)
    );
    assert!(
        short.status.success(),
        "{}",
        String::from_utf8_lossy(&short.stderr)
    );
    assert!(long.stderr.is_empty());
    assert!(short.stderr.is_empty());
    assert_eq!(long.stdout, short.stdout);
}

#[test]
fn root_help_exposes_bootstrap_workflow_and_runtime_dependencies() {
    let output = docket_help("--help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("help is utf-8");

    for required in [
        "Usage:",
        "--state <directory>",
        "repository register",
        "repository relocate",
        "continuity subject",
        "governed-loop inspect",
        "prepare start",
        "dispatch",
        "show (--attempt <id> | --dispatch <id>) [--json]",
        "--provider fake",
        "--provider codex",
        "GWR_BROKER_BIN",
        "GWR_WORKSPACE_ROOT",
        "GWR_CODEX_BIN",
        "source-install-and-bootstrap.md",
    ] {
        assert!(help.contains(required), "root help omitted {required:?}");
    }
}
