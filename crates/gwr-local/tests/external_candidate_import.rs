//! External preparation is retained content and submitted testimony, never an
//! authority grant or independent result. These tests drive separate real CLI
//! processes and reopen the actual SQLite/artifact custody.

use gwr_core::digest::Sha256Digest;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const GOLDEN: &str = include_str!("../../../conformance/external-candidate-v1/accepted.json");
const PATCH: &[u8] = include_bytes!("../../../conformance/external-candidate-v1/candidate.patch");

struct Fixture {
    root: PathBuf,
    repository: PathBuf,
    state: PathBuf,
    basis: String,
    request: String,
    binding: Value,
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn git(repository: &Path, args: &[&str]) -> String {
    success(
        Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .output()
            .unwrap(),
    )
    .trim()
    .to_owned()
}

fn field(output: &str, name: &str) -> String {
    output
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .unwrap_or_else(|| panic!("missing {name} in {output}"))
        .to_owned()
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "docket-external-import-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let repository = root.join("repository");
        std::fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "-q"]);
        git(
            &repository,
            &["config", "user.name", "External import test"],
        );
        git(
            &repository,
            &["config", "user.email", "external-import@example.invalid"],
        );
        std::fs::write(repository.join("work.txt"), "before\n").unwrap();
        git(&repository, &["add", "work.txt"]);
        git(&repository, &["commit", "-qm", "basis"]);
        let basis = git(&repository, &["rev-parse", "HEAD"]);
        let state = root.join("state");
        let mut fx = Self {
            root,
            repository,
            state,
            basis,
            request: String::new(),
            binding: Value::Null,
        };
        let registration = success(fx.cli(&[
            "repository",
            "register",
            "--repo",
            fx.repository.to_str().unwrap(),
        ]));
        let repository_id = field(&registration, "repository_id");
        let request = success(fx.cli(&[
            "request",
            "create",
            "--repository-id",
            &repository_id,
            "--repo",
            fx.repository.to_str().unwrap(),
            "--target-ref",
            "refs/heads/result",
            "--goal",
            "retain an externally prepared change without invoking a provider",
        ]));
        fx.request = field(&request, "work_request");
        fx.binding = serde_json::from_str(GOLDEN).unwrap();
        fx.binding["request"] = json!(fx.request);
        fx.binding["repository_id"] = json!(repository_id);
        fx.binding["basis"] = json!(fx.basis);
        std::fs::write(fx.root.join("candidate.patch"), PATCH).unwrap();
        fx
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_docket"))
            .args(args)
            .arg("--state")
            .arg(&self.state)
            // Any accidental provider or broker invocation must fail.
            .env("GWR_CODEX_BIN", self.root.join("no-provider"))
            .env("GWR_BROKER_BIN", self.root.join("no-broker"))
            .output()
            .unwrap()
    }

    fn import(&self, binding: &Value) -> Output {
        self.import_at_basis(binding, &self.basis)
    }

    fn import_at_basis(&self, binding: &Value, expected_basis: &str) -> Output {
        let manifest = self.root.join("external.json");
        std::fs::write(&manifest, serde_json::to_vec(binding).unwrap()).unwrap();
        self.cli(&[
            "prepare",
            "import",
            "--request",
            &self.request,
            "--basis",
            expected_basis,
            "--manifest",
            manifest.to_str().unwrap(),
            "--patch",
            self.root.join("candidate.patch").to_str().unwrap(),
            "--json",
        ])
    }

    fn inspect(&self, run: &str) -> Value {
        serde_json::from_str(&success(
            self.cli(&["prepare", "inspect", "--run", run, "--json"]),
        ))
        .unwrap()
    }

    fn count(&self, table: &str) -> u64 {
        Connection::open(self.state.join("state.sqlite"))
            .unwrap()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn no_effect_authority(&self) {
        for table in [
            "attempt",
            "standing_grant",
            "standing_use",
            "reservation",
            "dispatch",
            "governed_loop_attempt",
        ] {
            assert_eq!(self.count(table), 0, "external retention wrote {table}");
        }
        assert_eq!(git(&self.repository, &["rev-parse", "HEAD"]), self.basis);
        assert!(!Command::new("git")
            .arg("-C")
            .arg(&self.repository)
            .args(["show-ref", "--verify", "--quiet", "refs/heads/result"])
            .status()
            .unwrap()
            .success());
    }

    fn refused_without_candidate(&self, binding: &Value, reason: &str) {
        let output = self.import(binding);
        assert!(!output.status.success(), "unexpected import acceptance");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(reason),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(self.count("candidate_artifact"), 0);
        self.no_effect_authority();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// Catches ingestion that drops the basis/origin binding or fabricates provider
// testimony. Separate CLI invocations force actual reopen, not cached objects.
#[test]
fn external_candidate_reopens_with_exact_binding_and_no_fabricated_testimony() {
    let fx = Fixture::new();
    let response: Value = serde_json::from_str(&success(fx.import(&fx.binding))).unwrap();
    let run = response["preparation_run"].as_str().unwrap();
    let before = fx.inspect(run);
    assert_eq!(before["schema"], "gwr:external-preparation:v1");
    assert_eq!(before["binding"], fx.binding);
    assert_eq!(before["provenance_trust"], "submitted_testimony");
    assert_eq!(before["status"], "candidate_produced");
    for absent in [
        "provider_transcript",
        "tool_events",
        "tests",
        "independent_outcome",
        "verified_success",
    ] {
        assert!(before.get(absent).is_none(), "fabricated {absent}");
    }
    let digest = Sha256Digest::of_bytes(PATCH).to_hex();
    assert_eq!(
        std::fs::read(fx.state.join("artifacts").join(&digest)).unwrap(),
        PATCH
    );
    assert_eq!(before["binding"]["content_sha256"], digest);
    assert_eq!(before["binding"]["content_length"], PATCH.len());
    assert_eq!(fx.inspect(run), before);
    assert_eq!(fx.count("candidate_artifact"), 1);
    assert!(
        !fx.state.join("provenance").exists()
            || std::fs::read_dir(fx.state.join("provenance"))
                .unwrap()
                .next()
                .is_none()
    );
    fx.no_effect_authority();
}

// Catches duplicate submission minting a new preparation or allowing the same
// stable identity to be rebound to changed bytes or origin testimony.
#[test]
fn exact_repeat_is_idempotent_and_mutated_repeat_refuses_after_reopen() {
    let fx = Fixture::new();
    let first = success(fx.import(&fx.binding));
    assert_eq!(success(fx.import(&fx.binding)), first);
    assert_eq!(fx.count("preparation_run"), 1);
    assert_eq!(fx.count("candidate_artifact"), 1);
    let mut changed = fx.binding.clone();
    changed["origin"]["identity"] = json!("session:different-worker");
    let refused = fx.import(&changed);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("submission identity conflict"));
    std::fs::write(fx.root.join("candidate.patch"), b"changed bytes").unwrap();
    let refused = fx.import(&fx.binding);
    assert!(!refused.status.success());
    assert_eq!(fx.count("candidate_artifact"), 1);
    fx.no_effect_authority();
}

// Two real concurrent writers must observe one committed identity. This
// catches checking repeat identity outside the SQLite writer transaction.
#[test]
fn concurrent_repeat_processes_share_one_native_candidate() {
    let fx = Fixture::new();
    let manifest = fx.root.join("concurrent.json");
    std::fs::write(&manifest, serde_json::to_vec(&fx.binding).unwrap()).unwrap();
    let invoke = || {
        fx.cli(&[
            "prepare",
            "import",
            "--request",
            &fx.request,
            "--basis",
            &fx.basis,
            "--manifest",
            manifest.to_str().unwrap(),
            "--patch",
            fx.root.join("candidate.patch").to_str().unwrap(),
            "--json",
        ])
    };
    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(invoke);
        let second = scope.spawn(invoke);
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!(success(first), success(second));
    assert_eq!(fx.count("preparation_run"), 1);
    assert_eq!(fx.count("candidate_artifact"), 1);
    assert_eq!(fx.count("external_preparation"), 1);
    fx.no_effect_authority();
}

// Each case bypasses one independently supplied expected coordinate or bound.
#[test]
fn wrong_request_repository_basis_digest_length_and_expiry_refuse() {
    for (key, value, reason) in [
        (
            "request",
            json!("ffffffffffffffffffffffffffffffff"),
            "request mismatch",
        ),
        (
            "repository_id",
            json!("repo-ffffffffffffffffffffffffffffffff"),
            "repository mismatch",
        ),
        (
            "basis",
            json!("ffffffffffffffffffffffffffffffffffffffff"),
            "basis mismatch",
        ),
        (
            "content_sha256",
            json!("0000000000000000000000000000000000000000000000000000000000000000"),
            "content digest mismatch",
        ),
        ("content_length", json!(1), "content length mismatch"),
        ("deadline_unix_ms", json!(1), "expired"),
    ] {
        let fx = Fixture::new();
        let mut binding = fx.binding.clone();
        binding[key] = value;
        fx.refused_without_candidate(&binding, reason);
    }
}

// Catches replacing the content check with trust in a submitted digest.
#[test]
fn changed_candidate_bytes_refuse_before_retention() {
    let fx = Fixture::new();
    std::fs::write(fx.root.join("candidate.patch"), b"different external work").unwrap();
    let output = fx.import(&fx.binding);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("content"));
    assert_eq!(fx.count("candidate_artifact"), 0);
    fx.no_effect_authority();
}

// Source-owned refusal examples are consumed by the same native CLI ingress.
#[test]
fn golden_missing_origin_unknown_fields_and_old_schema_refuse() {
    for (source, reason) in [
        (
            include_str!("../../../conformance/external-candidate-v1/missing-origin.json"),
            "origin",
        ),
        (
            include_str!("../../../conformance/external-candidate-v1/unknown-field.json"),
            "unknown field",
        ),
        (
            include_str!("../../../conformance/external-candidate-v1/wrong-schema.json"),
            "schema",
        ),
    ] {
        let fx = Fixture::new();
        let mut binding: Value = serde_json::from_str(source).unwrap();
        for key in ["request", "repository_id", "basis"] {
            binding[key] = fx.binding[key].clone();
        }
        fx.refused_without_candidate(&binding, reason);
    }
}

// Catches unbounded source testimony and accepting an absent origin identity.
#[test]
fn empty_or_unbounded_origin_refuses() {
    for identity in [String::new(), "x".repeat(4097)] {
        let fx = Fixture::new();
        let mut binding = fx.binding.clone();
        binding["origin"]["identity"] = json!(identity);
        fx.refused_without_candidate(&binding, "origin");
    }
}

// Matching caller assertions are not proof that a basis commit exists in the
// registered repository. The expected basis is owner-selected for this new
// preparation; Docket checks existence without claiming to verify origin.
#[test]
fn matching_nonexistent_basis_assertions_refuse() {
    let fx = Fixture::new();
    let nonexistent = "ffffffffffffffffffffffffffffffffffffffff";
    let mut binding = fx.binding.clone();
    binding["basis"] = json!(nonexistent);
    let output = fx.import_at_basis(&binding, nonexistent);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("basis commit"));
    assert_eq!(fx.count("candidate_artifact"), 0);
    fx.no_effect_authority();
}

// A caller's Git repository-selection environment must not substitute another
// repository for the registered request's locator during basis validation.
// Request creation above runs normally; only the import subprocess is injected.
#[test]
fn git_dir_cannot_substitute_a_different_repository_for_basis_validation() {
    let fx = Fixture::new();
    let other = fx.root.join("other-repository");
    std::fs::create_dir(&other).unwrap();
    git(&other, &["init", "-q"]);
    git(&other, &["config", "user.name", "Other repository"]);
    git(&other, &["config", "user.email", "other@example.invalid"]);
    std::fs::write(
        other.join("other.txt"),
        "not in the registered repository\n",
    )
    .unwrap();
    git(&other, &["add", "other.txt"]);
    git(&other, &["commit", "-qm", "different basis"]);
    let other_basis = git(&other, &["rev-parse", "HEAD"]);
    assert!(!Command::new("git")
        .arg("-C")
        .arg(&fx.repository)
        .args(["cat-file", "-e", &other_basis])
        .status()
        .unwrap()
        .success());
    let mut binding = fx.binding.clone();
    binding["basis"] = json!(other_basis);
    let manifest = fx.root.join("substituted-context.json");
    std::fs::write(&manifest, serde_json::to_vec(&binding).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_docket"))
        .args(["prepare", "import", "--state"])
        .arg(&fx.state)
        .args([
            "--request",
            &fx.request,
            "--basis",
            &other_basis,
            "--manifest",
        ])
        .arg(&manifest)
        .arg("--patch")
        .arg(fx.root.join("candidate.patch"))
        .arg("--json")
        .env("GIT_DIR", other.join(".git"))
        .env("GWR_CODEX_BIN", fx.root.join("no-provider"))
        .env("GWR_BROKER_BIN", fx.root.join("no-broker"))
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "another repository supplied the accepted basis: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("basis commit"));
    assert_eq!(fx.count("candidate_artifact"), 0);
    fx.no_effect_authority();
}

// Clearing inherited Git-local variables must preserve native .git-file and
// common-directory discovery for an explicitly registered linked worktree.
#[test]
fn registered_git_worktree_retains_its_actual_basis() {
    let mut fx = Fixture::new();
    let linked = fx.root.join("linked-worktree");
    git(
        &fx.repository,
        &[
            "worktree",
            "add",
            "--detach",
            linked.to_str().unwrap(),
            &fx.basis,
        ],
    );
    let repository_id = fx.binding["repository_id"].as_str().unwrap().to_owned();
    success(fx.cli(&[
        "repository",
        "relocate",
        "--repository-id",
        &repository_id,
        "--repo",
        linked.to_str().unwrap(),
    ]));
    fx.repository = linked;
    let request = success(fx.cli(&[
        "request",
        "create",
        "--repository-id",
        &repository_id,
        "--repo",
        fx.repository.to_str().unwrap(),
        "--target-ref",
        "refs/heads/result",
        "--goal",
        "retain work against the explicitly registered linked worktree",
    ]));
    fx.request = field(&request, "work_request");
    fx.binding["request"] = json!(fx.request);
    let response: Value = serde_json::from_str(&success(fx.import(&fx.binding))).unwrap();
    let view = fx.inspect(response["preparation_run"].as_str().unwrap());
    assert_eq!(view["binding"]["basis"], fx.basis);
    assert_eq!(view["repository_locator"], fx.repository.to_str().unwrap());
    fx.no_effect_authority();
}

// Catches trusting an internally consistent envelope whose request was never
// registered in the native store.
#[test]
fn matching_unknown_request_assertions_refuse() {
    let mut fx = Fixture::new();
    fx.request = "ffffffffffffffffffffffffffffffff".to_owned();
    let mut binding = fx.binding.clone();
    binding["request"] = json!(fx.request);
    let output = fx.import(&binding);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("request"));
    assert_eq!(fx.count("candidate_artifact"), 0);
    fx.no_effect_authority();
}

// Catches independently committing candidate ingestion or the repeat-identity
// receipt before preparation termination. An actual database failure in a CLI
// subprocess must leave no partially accepted business object on reopen.
#[test]
fn terminal_store_failure_rolls_back_import_identity_before_safe_retry() {
    let fx = Fixture::new();
    let conn = Connection::open(fx.state.join("state.sqlite")).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_import_end BEFORE INSERT ON preparation_run_end BEGIN SELECT RAISE(ABORT, 'external import end refusal'); END;").unwrap();
    let output = fx.import(&fx.binding);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("external import end refusal"));
    assert_eq!(fx.count("preparation_run"), 0);
    assert_eq!(fx.count("candidate_artifact"), 0);
    conn.execute_batch("DROP TRIGGER fail_import_end;").unwrap();
    drop(conn);
    let first = success(fx.import(&fx.binding));
    assert_eq!(success(fx.import(&fx.binding)), first);
    assert_eq!(fx.count("preparation_run"), 1);
    assert_eq!(fx.count("candidate_artifact"), 1);
    fx.no_effect_authority();
}

// Catches an inspection path that presents corrupted retained bytes as current
// verified custody merely because the typed binding is intact.
#[test]
fn inspect_refuses_corrupted_retained_artifact() {
    let fx = Fixture::new();
    let response: Value = serde_json::from_str(&success(fx.import(&fx.binding))).unwrap();
    std::fs::write(
        fx.state
            .join("artifacts")
            .join(Sha256Digest::of_bytes(PATCH).to_hex()),
        b"substituted",
    )
    .unwrap();
    let output = fx.cli(&[
        "prepare",
        "inspect",
        "--run",
        response["preparation_run"].as_str().unwrap(),
        "--json",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("corrupt"));
    fx.no_effect_authority();
}

// Catches replacing or changing the existing fake-provider path while adding
// an external adapter. Its synthetic provenance must remain explicitly fake.
#[test]
fn existing_fake_provider_remains_a_distinct_preparation_path() {
    let fx = Fixture::new();
    let output = success(fx.cli(&[
        "prepare",
        "start",
        "--request",
        &fx.request,
        "--basis",
        &fx.basis,
        "--provider",
        "fake",
        "--fake-patch",
        fx.root.join("candidate.patch").to_str().unwrap(),
    ]));
    let run = field(&output, "preparation_run");
    let log = std::fs::read_to_string(fx.state.join("provenance").join(format!("prep-{run}.log")))
        .unwrap();
    assert!(!log.is_empty());
    assert_eq!(fx.count("candidate_artifact"), 1);
    fx.no_effect_authority();
}

// A literal cross-language transcript vector catches encoding drift; the
// expectation was independently derived with Python's hashlib/struct.
#[test]
fn shared_binding_transcript_vector_matches_without_json_layout_dependence() {
    use gwr_local::store::external_preparation::ExternalManifest;
    let manifest = ExternalManifest::from_bytes(GOLDEN.as_bytes()).unwrap();
    let expected: Value = serde_json::from_str(include_str!(
        "../../../conformance/external-candidate-v1/binding-vector.json"
    ))
    .unwrap();
    assert_eq!(
        manifest
            .binding_digest(
                expected["repository_locator"].as_str().unwrap(),
                expected["target_ref"].as_str().unwrap(),
            )
            .to_hex(),
        expected["binding_digest"].as_str().unwrap()
    );
}
