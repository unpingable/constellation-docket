//! F2 regression: campaign standing consumption has exactly one durable
//! winner. The law lives in the database — one immediate transaction decides
//! — so it holds across threads, service instances, processes, and restarts.
//! These tests use file-backed databases and real process boundaries; the
//! property under test is exactly the one the in-memory suite cannot see.

use gwr_core::campaign::proposal::{CampaignStageProposal, RepoPin, StageBasis};
use gwr_core::campaign::standing::{CampaignStageStanding, ExecutionContext};
use gwr_core::campaign::{ReviewRequirement, StageClass, WorkerRole};
use gwr_core::digest::Sha256Digest;
use gwr_core::refusal::CampaignRefusal;
use gwr_core::work_request::{ClockReading, CommitHash, RepositoryLocator};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::campaign as svc;
use gwr_runtime::services::campaign::CampaignError;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Barrier;

const COMMIT_A: &str = "72cb3b323fa286cd212378eadae4a42fe4dc093e";
const TREE_A: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gwr-f2-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn operator_proposal(nonce: &str) -> CampaignStageProposal {
    CampaignStageProposal::propose(
        "upstream-0".into(),
        "camp-1".into(),
        "stage-a".into(),
        StageClass::OperatorStage,
        WorkerRole::Operator,
        gwr_core::campaign::StageEffectClass::WorkspaceMutation,
        StageBasis::RootAuthorization {
            identity: "root-auth-1".into(),
        },
        vec![RepoPin {
            repository: RepositoryLocator::new("/repo"),
            commit: CommitHash::new(COMMIT_A),
            tree: TREE_A.into(),
        }],
        vec!["src/lib.rs".into()],
        "evidence-contract-1".into(),
        "handoff-schema-1".into(),
        ClockReading(10_000_000),
        nonce.into(),
        String::new(),
        ReviewRequirement::Required,
        vec!["does-not-establish-correctness".into()],
        None,
        ClockReading(1_000),
    )
    .unwrap()
}

/// Propose and admit an operator stage against the store at `db`.
fn admitted_operator_at(db: &Path, nonce: &str) -> CampaignStageStanding {
    let mut store = SqliteStore::open(db).unwrap();
    let p = operator_proposal(nonce);
    svc::propose_stage(&mut store, &p).unwrap();
    svc::admit(&mut store, &p.digest, ClockReading(2_000)).unwrap()
}

fn context(standing: &CampaignStageStanding) -> ExecutionContext {
    ExecutionContext {
        campaign: standing.campaign().to_string(),
        stage: standing.stage().to_string(),
        role: WorkerRole::Operator,
        proposal_digest: standing.proposal_digest(),
    }
}

#[test]
fn concurrent_identical_consumers_have_exactly_one_winner() {
    let dir = scratch("race-identical");
    let db = dir.join("state.sqlite");
    // The law rides on WAL mode, the deployment's journal mode.
    {
        let mut store = SqliteStore::open(&db).unwrap();
        let mode: String = store.query_string_for_test("PRAGMA journal_mode").unwrap();
        assert_eq!(mode, "wal");
    }
    let rounds = 32;
    let threads = 8;
    for round in 0..rounds {
        let standing = admitted_operator_at(&db, &format!("nonce-r{round}"));
        let ctx = context(&standing);
        let barrier = std::sync::Arc::new(Barrier::new(threads));
        let mut handles = Vec::new();
        for _ in 0..threads {
            let db = db.clone();
            let ctx = ctx.clone();
            let barrier = barrier.clone();
            let standing_digest = standing.digest();
            handles.push(std::thread::spawn(move || {
                let mut store = SqliteStore::open(&db).unwrap();
                barrier.wait();
                // Identical inputs: same standing, same context, same clock
                // reading — the record two winners would write is byte-identical.
                svc::consume(&mut store, &standing_digest, &ctx, ClockReading(3_000))
            }));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let wins = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(wins, 1, "round {round}: exactly one consumer may succeed");
        for r in &results {
            if let Err(e) = r {
                assert_eq!(
                    *e,
                    CampaignError::Refusal(CampaignRefusal::OutcomeUnresolved),
                    "round {round}: a loser receives the exact replay classification"
                );
            }
        }
        // One durable row, and it is the winner's record.
        let mut store = SqliteStore::open(&db).unwrap();
        let persisted = store
            .get_campaign_consumption(&standing.digest())
            .unwrap()
            .unwrap();
        let winner = results.iter().find_map(|r| r.as_ref().ok()).unwrap();
        assert_eq!(&persisted, winner);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_differing_timestamps_have_exactly_one_winner() {
    let dir = scratch("race-differing");
    let db = dir.join("state.sqlite");
    let standing = admitted_operator_at(&db, "nonce-1");
    let ctx = context(&standing);
    let threads = 8u64;
    let barrier = std::sync::Arc::new(Barrier::new(threads as usize));
    let mut handles = Vec::new();
    for t in 0..threads {
        let db = db.clone();
        let ctx = ctx.clone();
        let barrier = barrier.clone();
        let standing_digest = standing.digest();
        handles.push(std::thread::spawn(move || {
            let mut store = SqliteStore::open(&db).unwrap();
            barrier.wait();
            svc::consume(&mut store, &standing_digest, &ctx, ClockReading(3_000 + t))
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    for r in &results {
        if let Err(e) = r {
            assert_eq!(
                *e,
                CampaignError::Refusal(CampaignRefusal::OutcomeUnresolved),
                "a loser receives the exact replay classification, never success"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fresh_service_instances_share_the_durable_burn() {
    let dir = scratch("instances");
    let db = dir.join("state.sqlite");
    let standing = admitted_operator_at(&db, "nonce-1");
    let ctx = context(&standing);
    // One service instance burns.
    {
        let mut a = SqliteStore::open(&db).unwrap();
        svc::consume(&mut a, &standing.digest(), &ctx, ClockReading(3_000)).unwrap();
    }
    // A second, independent service instance on the same database sees the
    // burn and refuses the replay.
    {
        let mut b = SqliteStore::open(&db).unwrap();
        assert_eq!(
            svc::consume(&mut b, &standing.digest(), &ctx, ClockReading(3_100)),
            Err(CampaignError::Refusal(CampaignRefusal::OutcomeUnresolved))
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reopening_a_file_backed_store_preserves_every_recovery_state() {
    let dir = scratch("reopen");
    let db = dir.join("state.sqlite");
    let standing = admitted_operator_at(&db, "nonce-1");
    let ctx = context(&standing);
    // A refused attempt (wrong role) burns nothing: the standing stays
    // available for the lawful consumer.
    {
        let mut store = SqliteStore::open(&db).unwrap();
        let mut bad = ctx.clone();
        bad.role = WorkerRole::Reviewer;
        assert_eq!(
            svc::consume(&mut store, &standing.digest(), &bad, ClockReading(3_000)),
            Err(CampaignError::Refusal(CampaignRefusal::RoleMismatch))
        );
        assert!(store
            .get_campaign_consumption(&standing.digest())
            .unwrap()
            .is_none());
    }
    // State 2: burn committed, effect not begun — survives reopen.
    {
        let mut store = SqliteStore::open(&db).unwrap();
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)).unwrap();
    }
    {
        let mut store = SqliteStore::open(&db).unwrap();
        assert_eq!(
            svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_100)),
            Err(CampaignError::Refusal(CampaignRefusal::OutcomeUnresolved))
        );
        svc::record_effect_completed(&mut store, &standing.digest()).unwrap();
    }
    // State 3: effect completed, receipt missing — survives reopen.
    {
        let mut store = SqliteStore::open(&db).unwrap();
        assert_eq!(
            svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_200)),
            Err(CampaignError::Refusal(CampaignRefusal::ReceiptMissing))
        );
        svc::record_receipt(
            &mut store,
            &standing.digest(),
            &Sha256Digest::of_bytes(b"receipt"),
        )
        .unwrap();
    }
    // State 4: effect completed and receipted — survives reopen.
    {
        let mut store = SqliteStore::open(&db).unwrap();
        assert_eq!(
            svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_300)),
            Err(CampaignError::Refusal(
                CampaignRefusal::EffectAlreadyReceipted
            ))
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Run the real docket CLI against a scratch state dir, returning (status,
/// stdout, stderr).
fn docket(state: &Path, args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let mut full: Vec<&str> = args.to_vec();
    full.push("--state");
    full.push(state.to_str().unwrap());
    let out = Command::new(env!("CARGO_BIN_EXE_docket"))
        .args(&full)
        .output()
        .unwrap();
    (
        out.status,
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn field(stdout: &str, key: &str) -> String {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .unwrap_or_else(|| panic!("missing {key} in:\n{stdout}"))
        .trim()
        .to_string()
}

#[test]
fn cross_process_burn_refuses_replay_and_survives_process_exit() {
    let dir = scratch("process");
    let (status, stdout, stderr) = docket(
        &dir,
        &[
            "campaign",
            "propose-stage",
            "--class",
            "operator_stage",
            "--campaign",
            "camp-p",
            "--stage",
            "stage-a",
            "--upstream-digest",
            "up-1",
            "--basis-root",
            "root-1",
            "--pin",
            &format!("/repo:{COMMIT_A}:{TREE_A}"),
            "--allow",
            "src/lib.rs",
            "--evidence-contract",
            "e-1",
            "--handoff-schema",
            "h-1",
            "--nonce",
            "n-1",
        ],
    );
    assert!(status.success(), "propose-stage failed: {stderr}");
    let proposal = field(&stdout, "proposal: ");
    let (status, stdout, stderr) = docket(&dir, &["campaign", "admit", "--proposal", &proposal]);
    assert!(status.success(), "admit failed: {stderr}");
    let standing = field(&stdout, "standing: ");
    let consume_args = [
        "campaign",
        "consume",
        "--standing",
        &standing,
        "--role",
        "operator",
        "--campaign",
        "camp-p",
        "--stage",
        "stage-a",
        "--proposal",
        &proposal,
    ];
    // Process 1 burns, then exits without recording any outcome — the
    // crash-after-burn case.
    let (status, _stdout, stderr) = docket(&dir, &consume_args);
    assert!(status.success(), "first consume failed: {stderr}");
    // Process 2 (a genuinely new process, reopened storage): the burn is
    // visible and replay refuses with the exact unresolved classification.
    let (status, _stdout, stderr) = docket(&dir, &consume_args);
    assert!(!status.success(), "replayed burn must refuse");
    assert!(
        stderr.contains("OutcomeUnresolved"),
        "exact replay classification, got: {stderr}"
    );
    // Process 3: the read surface reports the durable consumed state.
    let (status, stdout, stderr) = docket(&dir, &["campaign", "show", "--standing", &standing]);
    assert!(status.success(), "show failed: {stderr}");
    assert!(
        stdout.contains("consumption_state: consumed_outcome_unresolved"),
        "durable state visible across processes, got:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// --- P4: bounded writer contention (busy_timeout) ---------------------------

#[test]
fn busy_timeout_is_configured_and_bounded() {
    let dir = scratch("busy-pragma");
    let db = dir.join("state.sqlite");
    let mut store = SqliteStore::open(&db).unwrap();
    let timeout: String = store
        .query_string_for_test("SELECT printf('%d', (SELECT * FROM pragma_busy_timeout))")
        .unwrap();
    assert_eq!(timeout, "5000");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn writer_lock_held_briefly_loser_waits_then_gets_typed_classification() {
    let dir = scratch("busy-wait");
    let db = dir.join("state.sqlite");
    let standing = admitted_operator_at(&db, "nonce-1");
    let ctx = context(&standing);
    // The exact burn record the loser would write, computed purely.
    let record = standing.preflight(&ctx, ClockReading(3_000)).unwrap();
    // A raw connection holds the write lock, then commits the winning burn
    // while the loser waits inside its bounded busy window.
    let raw = rusqlite::Connection::open(&db).unwrap();
    raw.execute_batch("BEGIN IMMEDIATE").unwrap();
    let db_b = db.clone();
    let standing_digest = standing.digest();
    let loser = std::thread::spawn(move || {
        let mut store = SqliteStore::open(&db_b).unwrap();
        svc::consume(&mut store, &standing_digest, &ctx, ClockReading(3_000))
    });
    std::thread::sleep(std::time::Duration::from_millis(1_500));
    raw.execute(
        "INSERT INTO campaign_stage_consumption
         (standing, digest, campaign, stage, role, consumed_at, effect_completed, receipt)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        rusqlite::params![
            record.standing.to_hex(),
            record.digest.to_hex(),
            record.campaign,
            record.stage,
            "operator",
            record.consumed_at.0 as i64,
            0,
            rusqlite::types::Null,
        ],
    )
    .unwrap();
    raw.execute_batch("COMMIT").unwrap();
    // The loser waited out the short lock, observed the committed burn, and
    // received the exact replay classification — never a raw SQLITE_BUSY,
    // never a success.
    let result = loser.join().unwrap();
    assert_eq!(
        result,
        Err(CampaignError::Refusal(CampaignRefusal::OutcomeUnresolved))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn writer_lock_held_beyond_timeout_fails_bounded_never_succeeds() {
    let dir = scratch("busy-timeout");
    let db = dir.join("state.sqlite");
    let standing = admitted_operator_at(&db, "nonce-1");
    let ctx = context(&standing);
    let raw = rusqlite::Connection::open(&db).unwrap();
    raw.execute_batch("BEGIN IMMEDIATE").unwrap();
    let db_b = db.clone();
    let standing_digest = standing.digest();
    let loser = std::thread::spawn(move || {
        let mut store = SqliteStore::open(&db_b).unwrap();
        svc::consume(&mut store, &standing_digest, &ctx, ClockReading(3_000))
    });
    // Hold past the five-second budget.
    std::thread::sleep(std::time::Duration::from_millis(6_500));
    let result = loser.join().unwrap();
    match result {
        Err(CampaignError::Store(_)) => {}
        other => panic!("a lock held past the budget must fail bounded, got: {other:?}"),
    }
    raw.execute_batch("ROLLBACK").unwrap();
    // No burn committed anywhere: the standing is still available, and the
    // next ordinary consumer wins.
    {
        let mut store = SqliteStore::open(&db).unwrap();
        assert!(store
            .get_campaign_consumption(&standing.digest())
            .unwrap()
            .is_none());
        svc::consume(
            &mut store,
            &standing.digest(),
            &context(&standing),
            ClockReading(3_000),
        )
        .unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
