//! Operator projection through the real read-only Docket CLI.

use gwr_local::store::SqliteStore;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("docket-status-{name}-{}", std::process::id()));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }

    fn database(&self) -> PathBuf {
        self.0.join("state.sqlite")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn status_summary(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_docket"))
        .args(["status-summary", "--json", "--state"])
        .arg(root)
        .output()
        .unwrap()
}

fn read_summary(root: &Path) -> Value {
    let result = status_summary(root);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    serde_json::from_slice(&result.stdout).unwrap()
}

// These are small SQLite projection fixtures. No authority or execution
// service is entered to produce the supplied row states.
fn add_attempt(db: &Connection, id: usize, status: &str, outcome: Option<&str>, at: i64) {
    let settlement = (status == "settled").then_some("fixture-settlement");
    let settled_at = settlement.map(|_| at + 10);
    let reconciliation = (status == "indeterminate").then_some("fixture-reconciliation");
    db.execute(
        "INSERT INTO governed_loop_attempt
        (issuance, signed_body_b64, issuer_principal, signer_key_id, signer_public_key,
         signature, campaign, occurrence, program, proposal, work_schema, work, subject,
         scope, observation, ag_standing_resolution, mandate, ag_spend, execution_standing,
         standing_currentness, attempt, executor_marker, executor_binding,
         executor_program_digest, executor_plan, accepted_at, status, settlement, receipt,
         outcome, settled_at, reconciliation, indeterminate_evidence)
         VALUES (?1, 'fixture', 'fixture', 'fixture', 'fixture', 'fixture', 'fixture',
                 'fixture', 'fixture', 'fixture', 'fixture', 'fixture', 'fixture', 'fixture',
                 'fixture', 'fixture', 'fixture', ?1, ?1, 'fixture', ?1, ?1, 'fixture',
                 'fixture', 'fixture', ?2, ?3, ?4, ?4, ?5, ?6, ?7, ?7)",
        params![
            format!("must-not-escape-id-{id}"),
            at,
            status,
            settlement,
            outcome,
            settled_at,
            reconciliation
        ],
    )
    .unwrap();
}

#[test]
fn summary_counts_retained_states_without_issuing_or_settling_anything() {
    let fixture = Fixture::new("retained-states");
    drop(SqliteStore::open(&fixture.database()).unwrap());
    let db = Connection::open(fixture.database()).unwrap();
    add_attempt(&db, 1, "accepted", None, 70);
    add_attempt(&db, 2, "accepted", None, 40);
    add_attempt(&db, 3, "settled", Some("success"), 10);
    add_attempt(&db, 4, "settled", Some("failure"), 20);
    add_attempt(&db, 5, "indeterminate", None, 30);
    add_attempt(&db, 6, "accepted", None, -1);
    db.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    add_attempt(&db, 7, "must-not-escape-unknown-state", None, 5);
    drop(db);
    let before = fs::read(fixture.database()).unwrap();

    assert_eq!(
        read_summary(&fixture.0),
        json!({
            "schema": "gwr:docket-status-summary:v1",
            "governed_attempts": {
                "scope": "retained_rowid_tail",
                "coverage": "complete",
                "row_limit": 4096,
                "rows_counted": 7,
                "accepted": 2,
                "settled_success": 1,
                "settled_failure": 1,
                "indeterminate": 1,
                "other": 2,
                "oldest_counted_accepted_at_unix_ms": 40
            }
        })
    );
    assert_eq!(fs::read(fixture.database()).unwrap(), before);
    for side_effect in ["standing.key", "artifacts", "journals", "provenance"] {
        assert!(!fixture.0.join(side_effect).exists());
    }
}

#[test]
fn summary_identifies_the_bounded_tail_and_excludes_older_accepted_rows() {
    let fixture = Fixture::new("long-history");
    drop(SqliteStore::open(&fixture.database()).unwrap());
    let mut db = Connection::open(fixture.database()).unwrap();
    let tx = db.transaction().unwrap();
    add_attempt(&tx, 0, "accepted", None, 5);
    for id in 1..=4096 {
        add_attempt(&tx, id, "settled", Some("success"), id as i64 + 5);
    }
    tx.commit().unwrap();
    drop(db);

    let summary = read_summary(&fixture.0);
    let counts = &summary["governed_attempts"];
    assert_eq!(counts["coverage"], "truncated");
    assert_eq!(counts["rows_counted"], 4096);
    assert_eq!(counts["settled_success"], 4096);
    assert_eq!(counts["accepted"], 0);
    assert!(counts["oldest_counted_accepted_at_unix_ms"].is_null());
}

#[test]
fn empty_store_and_unavailable_store_remain_distinct() {
    let fixture = Fixture::new("empty-missing-foreign");
    let missing = fixture.0.join("missing-state");
    let result = status_summary(&missing);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!missing.exists());

    // A pre-existing SQLite file with the wrong schema must not be migrated
    // or interpreted as an empty governed-attempt history.
    let db = Connection::open(fixture.database()).unwrap();
    db.execute("CREATE TABLE unrelated(value TEXT)", [])
        .unwrap();
    drop(db);
    let before = fs::read(fixture.database()).unwrap();
    let result = status_summary(&fixture.0);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(fs::read(fixture.database()).unwrap(), before);

    drop(SqliteStore::open(&fixture.database()).unwrap());
    let summary = read_summary(&fixture.0);
    let counts = &summary["governed_attempts"];
    assert_eq!(counts["coverage"], "complete");
    assert_eq!(counts["rows_counted"], 0);
    assert!(counts["oldest_counted_accepted_at_unix_ms"].is_null());
}
