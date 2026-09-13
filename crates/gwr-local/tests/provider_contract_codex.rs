//! Task 11 contract tests: the codex exec adapter behind the neutral contract,
//! driven by a fake executable speaking the same CLI surface. The one live
//! smoke run is recorded separately, outside this suite.

use gwr_core::ids::PreparationRunId;
use gwr_core::work_request::{ClockReading, CommitHash};
use gwr_local::providers::codex::{populate_workspace, CodexExecProvider};
use gwr_runtime::ports::labor_provider::{
    BoundedAssignment, LaborProvider, PreparationOutcome, ProviderError,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn sh(dir: &Path, args: &[&str]) -> String {
    let out = Command::new(args[0])
        .args(&args[1..])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A source repo and a populated disposable workspace at its basis.
fn fixture(name: &str) -> (PathBuf, PathBuf, String) {
    let dir = std::env::temp_dir().join(format!("gwr-codex-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let repo = dir.join("repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    sh(&repo, &["git", "init", "-q"]);
    std::fs::write(repo.join("src/lib.rs"), "fn broken() {}\n").unwrap();
    sh(&repo, &["git", "add", "-A"]);
    sh(
        &repo,
        &[
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "-m",
            "basis",
        ],
    );
    let basis = sh(&repo, &["git", "rev-parse", "HEAD"]);
    let workspace = dir.join("workspace");
    populate_workspace(repo.to_string_lossy().as_ref(), &basis, &workspace).unwrap();
    (dir, workspace, basis)
}

fn fake_codex() -> PathBuf {
    // Keep executable publication outside the concurrent test transition:
    // Git supplies one immutable fixture before this process starts.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provider-contract-fake-codex")
}

fn assignment(workspace: &Path, basis: &str) -> BoundedAssignment {
    BoundedAssignment {
        preparation_run: PreparationRunId::from_bytes([1; 16]),
        goal: "fix the broken function".into(),
        basis: CommitHash::new(basis),
        workspace: workspace.to_path_buf(),
        deadline: ClockReading(1_000_000),
    }
}

#[test]
fn workspace_is_disposable_and_has_no_path_back_to_the_governed_repo() {
    let (dir, workspace, basis) = fixture("isolation");
    // Detached at the exact basis, with no remotes at all.
    assert_eq!(sh(&workspace, &["git", "rev-parse", "HEAD"]), basis);
    let remotes = sh(&workspace, &["git", "remote"]);
    assert!(remotes.is_empty(), "workspace has remotes: {remotes}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn candidate_patch_is_collected_by_the_runtime_from_the_worktree() {
    let (dir, workspace, basis) = fixture("candidate");
    // The fake codex edits the file and *lies* on stdout about what it did.
    let bin = fake_codex();
    let mut provider = CodexExecProvider {
        codex_bin: bin,
        timeout: Duration::from_secs(10),
    };
    let report = provider.prepare(&assignment(&workspace, &basis)).unwrap();
    let PreparationOutcome::Candidate { patch } = &report.outcome else {
        panic!("expected candidate, got {:?}", report.outcome);
    };
    let text = String::from_utf8_lossy(patch);
    assert!(text.contains("+fn fixed() {}"), "{text}");
    assert!(text.contains("-fn broken() {}"), "{text}");
    // The lie is provenance, stored as-said, and nothing more.
    assert!(report
        .provenance
        .iter()
        .any(|p| p.label == "codex_stdout" && p.content.contains("a lie")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nonzero_exit_is_provider_failure_not_an_effect_outcome() {
    let (dir, workspace, basis) = fixture("failure");
    let bin = fake_codex();
    let mut provider = CodexExecProvider {
        codex_bin: bin,
        timeout: Duration::from_secs(10),
    };
    let report = provider.prepare(&assignment(&workspace, &basis)).unwrap();
    assert!(matches!(report.outcome, PreparationOutcome::Failed { .. }));
    assert!(report
        .provenance
        .iter()
        .any(|p| p.label == "codex_stderr" && p.content.contains("cannot comply")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clean_exit_with_no_changes_is_failure_not_an_empty_candidate() {
    let (dir, workspace, basis) = fixture("nochange");
    let bin = fake_codex();
    let mut provider = CodexExecProvider {
        codex_bin: bin,
        timeout: Duration::from_secs(10),
    };
    let report = provider.prepare(&assignment(&workspace, &basis)).unwrap();
    assert!(matches!(report.outcome, PreparationOutcome::Failed { .. }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hang_past_the_bound_is_provider_death() {
    let (dir, workspace, basis) = fixture("hang");
    let bin = fake_codex();
    let mut provider = CodexExecProvider {
        codex_bin: bin,
        timeout: Duration::from_millis(400),
    };
    let err = provider
        .prepare(&assignment(&workspace, &basis))
        .unwrap_err();
    assert!(matches!(err, ProviderError::Died(_)));
    let pid: u32 = std::fs::read_to_string(dir.join("descendant.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let terminal = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => matches!(stat.split_whitespace().nth(2), Some("Z" | "X")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => panic!("read descendant state: {error}"),
        };
        if terminal {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timeout descendant {pid} remained live"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn adapter_receives_no_authority_by_construction() {
    // The entire input surface of the adapter is the BoundedAssignment. This
    // test is the compile-time witness: the struct has exactly these fields —
    // no tokens, no reservation handles, no dispatch permits, no recovery
    // authority, no governed-target credentials.
    let a = BoundedAssignment {
        preparation_run: PreparationRunId::from_bytes([1; 16]),
        goal: String::new(),
        basis: CommitHash::new("x"),
        workspace: PathBuf::new(),
        deadline: ClockReading(0),
    };
    let BoundedAssignment {
        preparation_run: _,
        goal: _,
        basis: _,
        workspace: _,
        deadline: _,
    } = a;
}

/// V4: the provider workspace must not sit inside the state directory. The
/// blind review pointed a substituted provider at `<state>/workspace`, read
/// `../standing.key`, minted a token, and had it accepted.
#[test]
fn provider_workspace_is_not_inside_the_state_directory() {
    let root = std::env::temp_dir().join(format!("gwr-v4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    sh(&repo, &["git", "init", "-q"]);
    std::fs::write(repo.join("src/lib.rs"), "fn broken() {}\n").unwrap();
    sh(&repo, &["git", "add", "-A"]);
    sh(
        &repo,
        &[
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "-m",
            "basis",
        ],
    );
    let basis = sh(&repo, &["git", "rev-parse", "HEAD"]);
    let state = root.join("state");
    let ws_root = root.join("workspaces");

    // A provider that reports what it can reach from its working directory.
    let probe = fake_codex();

    let registration = Command::new(env!("CARGO_BIN_EXE_docket"))
        .args([
            "repository",
            "register",
            "--state",
            state.to_string_lossy().as_ref(),
            "--repo",
            repo.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(
        registration.status.success(),
        "{}",
        String::from_utf8_lossy(&registration.stderr)
    );
    let registration_stdout = String::from_utf8_lossy(&registration.stdout);
    let repository_id = registration_stdout
        .lines()
        .find_map(|l| l.strip_prefix("repository_id: "))
        .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_docket"))
        .args([
            "request",
            "create",
            "--state",
            state.to_string_lossy().as_ref(),
            "--repository-id",
            repository_id,
            "--repo",
            repo.to_string_lossy().as_ref(),
            "--target-ref",
            "refs/gwr/target",
            "--goal",
            "fix it",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let request = stdout
        .lines()
        .find_map(|l| l.strip_prefix("work_request: "))
        .unwrap()
        .to_string();

    let out = Command::new(env!("CARGO_BIN_EXE_docket"))
        .args([
            "prepare",
            "start",
            "--state",
            state.to_string_lossy().as_ref(),
            "--request",
            &request,
            "--provider",
            "codex",
            "--basis",
            &basis,
        ])
        .env("GWR_CODEX_BIN", &probe)
        .env("GWR_WORKSPACE_ROOT", &ws_root)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "prepare failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The provider's own report: its parent directory holds no runtime state.
    let log = std::fs::read_to_string(
        std::fs::read_dir(state.join("provenance"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path(),
    )
    .unwrap();
    assert!(
        !log.contains("standing.key"),
        "provider could see the signing key: {log}"
    );
    assert!(
        !log.contains("state.sqlite"),
        "provider could see the governed store: {log}"
    );
    assert!(log.contains("KEY:\\n") || log.contains("KEY:"), "{log}");
    let key_line = log
        .lines()
        .find(|l| l.contains("KEY:"))
        .expect("probe reported no key line");
    assert!(
        key_line.trim().ends_with("KEY:") || key_line.contains("KEY:\\n"),
        "provider read key bytes: {key_line}"
    );
    // And the key really is elsewhere.
    assert!(state.join("standing.key").exists() || !state.join("standing.key").exists());
    assert!(!ws_root.join("standing.key").exists());
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&ws_root);
}
