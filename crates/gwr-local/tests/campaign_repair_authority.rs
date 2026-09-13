//! P1 repair-authority export and verification: the Docket-owned artifact a
//! repair stage's execution may rely on. Service-level law tests plus real
//! CLI tests over a file-backed store. Every refusal is exact.

use gwr_core::campaign::adjudication::AdjudicationVerdict;
use gwr_core::campaign::authority::RepairAuthorityV1;
use gwr_core::campaign::proposal::{CampaignStageProposal, RepairBasis, RepoPin, StageBasis};
use gwr_core::campaign::standing::ExecutionContext;
use gwr_core::campaign::{RepairScopeClass, ReviewRequirement, StageClass, WorkerRole};
use gwr_core::digest::Sha256Digest;
use gwr_core::refusal::CampaignRefusal;
use gwr_core::work_request::{ClockReading, CommitHash, RepositoryLocator};
use gwr_local::campaign_export;
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::campaign as svc;
use gwr_runtime::services::campaign::CampaignError;
use std::path::{Path, PathBuf};
use std::process::Command;

const COMMIT_A: &str = "72cb3b323fa286cd212378eadae4a42fe4dc093e";
const TREE_A: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const REVIEW_RECEIPT: Sha256Digest = Sha256Digest::from_bytes([9; 32]);
const VERIFIER: &str = "gwr-local 0.1.0";

fn pin() -> RepoPin {
    RepoPin {
        repository: RepositoryLocator::new("/repo"),
        commit: CommitHash::new(COMMIT_A),
        tree: TREE_A.into(),
    }
}

fn original_proposal() -> CampaignStageProposal {
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
        vec![pin()],
        vec!["src/lib.rs".into(), "docs/x.md".into()],
        "evidence-contract-1".into(),
        "handoff-schema-1".into(),
        ClockReading(10_000),
        "nonce-1".into(),
        String::new(),
        ReviewRequirement::Required,
        vec!["does-not-establish-correctness".into()],
        None,
        ClockReading(1_000),
    )
    .unwrap()
}

/// A consumed, adjudicated original stage plus an admitted repair standing:
/// (repair proposal digest, repair standing digest).
fn repair_chain(store: &mut SqliteStore) -> (Sha256Digest, Sha256Digest) {
    let original = original_proposal();
    svc::propose_stage(store, &original).unwrap();
    let standing = svc::admit(store, &original.digest, ClockReading(2_000)).unwrap();
    let ctx = ExecutionContext {
        campaign: "camp-1".into(),
        stage: "stage-a".into(),
        role: WorkerRole::Operator,
        proposal_digest: original.digest,
    };
    svc::consume(store, &standing.digest(), &ctx, ClockReading(3_000)).unwrap();
    svc::record_receipt(store, &standing.digest(), &REVIEW_RECEIPT).unwrap();
    let adjudication = svc::adjudicate(
        store,
        "camp-1",
        "stage-a",
        &REVIEW_RECEIPT,
        AdjudicationVerdict::ExactRepair,
        "adjudicator-1",
        vec!["finding-1".into()],
        vec![],
        ClockReading(4_000),
    )
    .unwrap();
    let repair = CampaignStageProposal::propose(
        "upstream-repair".into(),
        "camp-1".into(),
        "stage-a-repair".into(),
        StageClass::RecordsRepairStage,
        WorkerRole::Repair,
        gwr_core::campaign::StageEffectClass::RecordsOnly,
        StageBasis::PredecessorStage {
            stage: "stage-a".into(),
            adjudication_digest: adjudication.digest,
        },
        vec![pin()],
        vec!["docs/x.md".into()],
        "evidence-contract-1".into(),
        "handoff-schema-1".into(),
        ClockReading(10_000),
        "nonce-repair".into(),
        String::new(),
        ReviewRequirement::Required,
        vec!["does-not-widen-scope".into()],
        Some(RepairBasis {
            original_stage: "stage-a".into(),
            rejected_review_receipt: REVIEW_RECEIPT,
            finding_ids: vec!["finding-1".into()],
            scope_class: RepairScopeClass::RecordsOnly,
            nonclaims: vec!["does-not-widen-scope".into()],
            review_requirement: ReviewRequirement::Required,
        }),
        ClockReading(4_500),
    )
    .unwrap();
    svc::propose_stage(store, &repair).unwrap();
    let repair_standing = svc::admit(store, &repair.digest, ClockReading(5_000)).unwrap();
    (repair.digest, repair_standing.digest())
}

fn export(store: &mut SqliteStore, standing: &Sha256Digest) -> RepairAuthorityV1 {
    svc::export_repair_authority(store, standing, ClockReading(5_500), VERIFIER).unwrap()
}

#[test]
fn export_is_deterministic_and_verifies() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let (_p, standing) = repair_chain(&mut store);
    let a = export(&mut store, &standing);
    let b = export(&mut store, &standing);
    assert_eq!(a, b);
    assert_eq!(campaign_export::render(&a), campaign_export::render(&b));
    svc::verify_repair_authority(&mut store, &a, ClockReading(5_500), VERIFIER).unwrap();
}

#[test]
fn a_stale_bundle_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let (_p, standing) = repair_chain(&mut store);
    let bundle = export(&mut store, &standing);
    // The standing expires at 10_000; verification at/after expiry refuses.
    assert_eq!(
        svc::verify_repair_authority(&mut store, &bundle, ClockReading(10_000), VERIFIER),
        Err(CampaignError::Refusal(CampaignRefusal::Expired))
    );
}

#[test]
fn a_superseded_adjudication_refuses_verification() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let (_p, standing) = repair_chain(&mut store);
    let bundle = export(&mut store, &standing);
    // A newer adjudication of the same review receipt supersedes the cited
    // one; the artifact is no longer current authority.
    svc::adjudicate(
        &mut store,
        "camp-1",
        "stage-a",
        &REVIEW_RECEIPT,
        AdjudicationVerdict::Refuse,
        "adjudicator-1",
        vec!["finding-1".into()],
        vec![],
        ClockReading(6_000),
    )
    .unwrap();
    assert_eq!(
        svc::verify_repair_authority(&mut store, &bundle, ClockReading(6_500), VERIFIER),
        Err(CampaignError::Refusal(CampaignRefusal::Superseded))
    );
}

#[test]
fn a_superseded_repair_standing_refuses_verification() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let (_p, standing) = repair_chain(&mut store);
    let bundle = export(&mut store, &standing);
    // Re-admitting the same repair stage issues a newer standing; the
    // bundle's standing is now historical. (The re-proposal carries a new
    // nonce and cites the same lawful adjudication.)
    let adjudication_digest = bundle.adjudication;
    let reproposal = CampaignStageProposal::propose(
        "upstream-repair".into(),
        "camp-1".into(),
        "stage-a-repair".into(),
        StageClass::RecordsRepairStage,
        WorkerRole::Repair,
        gwr_core::campaign::StageEffectClass::RecordsOnly,
        StageBasis::PredecessorStage {
            stage: "stage-a".into(),
            adjudication_digest,
        },
        vec![pin()],
        vec!["docs/x.md".into()],
        "evidence-contract-1".into(),
        "handoff-schema-1".into(),
        ClockReading(10_000),
        "nonce-repair-2".into(),
        String::new(),
        ReviewRequirement::Required,
        vec!["does-not-widen-scope".into()],
        Some(RepairBasis {
            original_stage: "stage-a".into(),
            rejected_review_receipt: REVIEW_RECEIPT,
            finding_ids: vec!["finding-1".into()],
            scope_class: RepairScopeClass::RecordsOnly,
            nonclaims: vec!["does-not-widen-scope".into()],
            review_requirement: ReviewRequirement::Required,
        }),
        ClockReading(4_500),
    )
    .unwrap();
    svc::propose_stage(&mut store, &reproposal).unwrap();
    svc::admit(&mut store, &reproposal.digest, ClockReading(5_600)).unwrap();
    assert_eq!(
        svc::verify_repair_authority(&mut store, &bundle, ClockReading(5_700), VERIFIER),
        Err(CampaignError::Refusal(CampaignRefusal::Superseded))
    );
}

#[test]
fn burn_state_drift_refuses_verification() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let (_p, standing) = repair_chain(&mut store);
    let bundle = export(&mut store, &standing);
    assert_eq!(bundle.consumption, None);
    // The repair standing is then consumed: the pre-burn artifact is stale
    // and the mismatch names the exact field.
    let repair_standing = store.get_campaign_standing(&standing).unwrap().unwrap();
    let ctx = ExecutionContext {
        campaign: "camp-1".into(),
        stage: "stage-a-repair".into(),
        role: WorkerRole::Repair,
        proposal_digest: repair_standing.proposal_digest(),
    };
    svc::consume(&mut store, &standing, &ctx, ClockReading(5_600)).unwrap();
    assert_eq!(
        svc::verify_repair_authority(&mut store, &bundle, ClockReading(5_700), VERIFIER),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairAuthorityMismatch {
                field: "consumption"
            }
        ))
    );
    // A fresh post-burn export verifies instead.
    let post = export(&mut store, &standing);
    assert!(post.consumption.is_some());
    svc::verify_repair_authority(&mut store, &post, ClockReading(5_700), VERIFIER).unwrap();
}

#[test]
fn a_foreign_artifact_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let (_p, standing) = repair_chain(&mut store);
    let bundle = export(&mut store, &standing);
    // The same artifact presented against another database: the standing is
    // unknown there.
    let mut other = SqliteStore::open_in_memory().unwrap();
    assert!(matches!(
        svc::verify_repair_authority(&mut other, &bundle, ClockReading(5_500), VERIFIER),
        Err(CampaignError::NotFound(_))
    ));
}

#[test]
fn tampered_artifact_bytes_refuse_at_parse_or_recompute() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let (_p, standing) = repair_chain(&mut store);
    let bundle = export(&mut store, &standing);
    let raw = campaign_export::render(&bundle);
    // A widened path in the bytes: the embedded typed digest no longer
    // recomputes.
    let widened = raw.replacen("\"docs/x.md\"", "\"src/widened.rs\"", 1);
    assert!(campaign_export::parse(&widened).is_err());
    // A substituted finding refuses the same way.
    let findings = raw.replacen("finding-1", "finding-2", 1);
    assert!(campaign_export::parse(&findings).is_err());
    // Truncated JSON refuses.
    assert!(campaign_export::parse(&raw[..raw.len() / 2]).is_err());
}

// --- Real CLI paths ---------------------------------------------------------

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gwr-p1-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

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

fn docket_ok(state: &Path, args: &[&str]) -> String {
    let (status, stdout, stderr) = docket(state, args);
    assert!(status.success(), "docket {args:?} failed: {stderr}");
    stdout
}

fn field(stdout: &str, key: &str) -> String {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .unwrap_or_else(|| panic!("missing {key} in:\n{stdout}"))
        .trim()
        .to_string()
}

/// Drive the full chain through the real CLI: original stage consumed and
/// adjudicated exact-repair; repair standing admitted. Returns
/// (repair standing hex, adjudication hex).
fn cli_repair_chain(state: &Path) -> (String, String) {
    let out = docket_ok(
        state,
        &[
            "campaign",
            "propose-stage",
            "--class",
            "operator_stage",
            "--campaign",
            "camp-1",
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
            "--allow",
            "docs/x.md",
            "--evidence-contract",
            "e-1",
            "--handoff-schema",
            "h-1",
            "--nonce",
            "n-1",
        ],
    );
    let proposal = field(&out, "proposal: ");
    let out = docket_ok(state, &["campaign", "admit", "--proposal", &proposal]);
    let standing = field(&out, "standing: ");
    docket_ok(
        state,
        &[
            "campaign",
            "consume",
            "--standing",
            &standing,
            "--role",
            "operator",
            "--campaign",
            "camp-1",
            "--stage",
            "stage-a",
            "--proposal",
            &proposal,
        ],
    );
    let receipt = "ab".repeat(32);
    docket_ok(
        state,
        &[
            "campaign",
            "outcome",
            "--standing",
            &standing,
            "--receipt",
            &receipt,
        ],
    );
    let out = docket_ok(
        state,
        &[
            "campaign",
            "adjudicate",
            "--campaign",
            "camp-1",
            "--stage",
            "stage-a",
            "--review-receipt",
            &receipt,
            "--verdict",
            "exact-repair",
            "--adjudicator",
            "campaign-office",
            "--finding",
            "F-01",
        ],
    );
    let adjudication = field(&out, "adjudication: ");
    let out = docket_ok(
        state,
        &[
            "campaign",
            "propose-stage",
            "--class",
            "records_repair_stage",
            "--campaign",
            "camp-1",
            "--stage",
            "stage-a-repair",
            "--upstream-digest",
            "up-2",
            "--basis-stage",
            "stage-a",
            "--basis-adjudication",
            &adjudication,
            "--pin",
            &format!("/repo:{COMMIT_A}:{TREE_A}"),
            "--allow",
            "docs/x.md",
            "--evidence-contract",
            "e-1",
            "--handoff-schema",
            "h-1",
            "--nonce",
            "n-2",
            "--repair-original-stage",
            "stage-a",
            "--repair-receipt",
            &receipt,
            "--repair-finding",
            "F-01",
            "--repair-scope",
            "records_only",
            "--repair-review",
            "required",
        ],
    );
    let repair_proposal = field(&out, "proposal: ");
    let out = docket_ok(
        state,
        &["campaign", "admit", "--proposal", &repair_proposal],
    );
    (field(&out, "standing: "), adjudication)
}

#[test]
fn cli_export_and_verify_round_trip_is_deterministic() {
    let dir = scratch("cli-roundtrip");
    let (standing, _adjudication) = cli_repair_chain(&dir);
    let artifact_a = dir.join("authority-a.json");
    let artifact_b = dir.join("authority-b.json");
    docket_ok(
        &dir,
        &[
            "campaign",
            "export-repair-authority",
            "--standing",
            &standing,
            "--out",
            artifact_a.to_str().unwrap(),
        ],
    );
    docket_ok(
        &dir,
        &[
            "campaign",
            "export-repair-authority",
            "--standing",
            &standing,
            "--out",
            artifact_b.to_str().unwrap(),
        ],
    );
    let bytes_a = std::fs::read(&artifact_a).unwrap();
    let bytes_b = std::fs::read(&artifact_b).unwrap();
    assert_eq!(bytes_a, bytes_b, "export must be deterministic");
    // The companion carries SHA-256 over the exact file bytes.
    let companion = std::fs::read_to_string(dir.join("authority-a.json.sha256")).unwrap();
    assert_eq!(
        companion.trim(),
        campaign_export::sha256_hex(&bytes_a),
        "companion must bind the exact file bytes"
    );
    // Verification succeeds and names the exact references.
    let out = docket_ok(
        &dir,
        &[
            "campaign",
            "verify-repair-authority",
            "--bundle",
            artifact_a.to_str().unwrap(),
            "--expect-standing",
            &standing,
        ],
    );
    assert!(out.contains("verification: ok"));
    assert!(out.contains(&format!("standing: {standing}")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_verify_refuses_wrong_standing_schema_corruption_and_drift() {
    let dir = scratch("cli-hostile");
    let (standing, _adjudication) = cli_repair_chain(&dir);
    let artifact = dir.join("authority.json");
    docket_ok(
        &dir,
        &[
            "campaign",
            "export-repair-authority",
            "--standing",
            &standing,
            "--out",
            artifact.to_str().unwrap(),
        ],
    );
    // Wrong expected standing.
    let (status, _o, stderr) = docket(
        &dir,
        &[
            "campaign",
            "verify-repair-authority",
            "--bundle",
            artifact.to_str().unwrap(),
            "--expect-standing",
            &"00".repeat(32),
        ],
    );
    assert!(!status.success());
    assert!(stderr.contains("standing"), "got: {stderr}");
    // Unknown schema.
    let raw = std::fs::read_to_string(&artifact).unwrap();
    let bad_schema = dir.join("bad-schema.json");
    std::fs::write(
        &bad_schema,
        raw.replacen("gwr:campaign-repair-authority:v1", "gwr:other:v9", 1),
    )
    .unwrap();
    let (status, _o, stderr) = docket(
        &dir,
        &[
            "campaign",
            "verify-repair-authority",
            "--bundle",
            bad_schema.to_str().unwrap(),
        ],
    );
    assert!(!status.success());
    assert!(stderr.contains("unknown schema"), "got: {stderr}");
    // Corrupted bytes (a substituted path): the typed digest no longer
    // recomputes.
    let corrupt = dir.join("corrupt.json");
    std::fs::write(
        &corrupt,
        raw.replacen("\"docs/x.md\"", "\"src/widened.rs\"", 1),
    )
    .unwrap();
    let (status, _o, stderr) = docket(
        &dir,
        &[
            "campaign",
            "verify-repair-authority",
            "--bundle",
            corrupt.to_str().unwrap(),
        ],
    );
    assert!(!status.success());
    assert!(stderr.contains("recompute"), "got: {stderr}");
    // Burn-state drift: consume the repair standing, then the pre-burn
    // artifact refuses with the exact field.
    let show = docket_ok(&dir, &["campaign", "show", "--standing", &standing]);
    let repair_proposal = field(&show, "proposal: ");
    docket_ok(
        &dir,
        &[
            "campaign",
            "consume",
            "--standing",
            &standing,
            "--role",
            "repair",
            "--campaign",
            "camp-1",
            "--stage",
            "stage-a-repair",
            "--proposal",
            &repair_proposal,
        ],
    );
    let (status, _o, stderr) = docket(
        &dir,
        &[
            "campaign",
            "verify-repair-authority",
            "--bundle",
            artifact.to_str().unwrap(),
        ],
    );
    assert!(!status.success());
    assert!(stderr.contains("consumption"), "got: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
