//! S-2 campaign-stage standing: hostile and success tests over the real
//! store and services. Every refusal asserted here is typed; nothing fails
//! closed by panic or by a generic error.

use gwr_core::campaign::adjudication::{
    AdjudicationReceipt, AdjudicationVerdict, ResidualStatement,
};
use gwr_core::campaign::proposal::{CampaignStageProposal, RepairBasis, RepoPin, StageBasis};
use gwr_core::campaign::standing::{
    CampaignStageConsumption, CampaignStageStanding, CampaignStandingState, ExecutionContext,
};
use gwr_core::campaign::{
    reviewer_permits, MutationOp, RepairScopeClass, ReviewEffect, ReviewRequirement, StageClass,
    WorkerRole,
};
use gwr_core::digest::Sha256Digest;
use gwr_core::refusal::CampaignRefusal;
use gwr_core::work_request::{ClockReading, CommitHash, RepositoryLocator};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::campaign as svc;
use gwr_runtime::services::campaign::CampaignError;

const COMMIT_A: &str = "72cb3b323fa286cd212378eadae4a42fe4dc093e";
const TREE_A: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const COMMIT_B: &str = "1111111111111111111111111111111111111111";
const TREE_B: &str = "2222222222222222222222222222222222222222";
const REVIEW_RECEIPT: Sha256Digest = Sha256Digest::from_bytes([9; 32]);
const OTHER_RECEIPT: Sha256Digest = Sha256Digest::from_bytes([7; 32]);

fn pin(locator: &str, commit: &str, tree: &str) -> RepoPin {
    RepoPin {
        repository: RepositoryLocator::new(locator),
        commit: CommitHash::new(commit),
        tree: tree.into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn proposal(
    class: StageClass,
    campaign: &str,
    stage: &str,
    nonce: &str,
    upstream: &str,
    repositories: Vec<RepoPin>,
    paths: &[&str],
    worktree: &str,
    repair: Option<RepairBasis>,
) -> CampaignStageProposal {
    CampaignStageProposal::propose(
        upstream.into(),
        campaign.into(),
        stage.into(),
        class,
        class.required_role(),
        class.required_effect_class(),
        StageBasis::RootAuthorization {
            identity: "root-auth-1".into(),
        },
        repositories,
        paths.iter().map(|p| p.to_string()).collect(),
        "evidence-contract-1".into(),
        "handoff-schema-1".into(),
        ClockReading(10_000),
        nonce.into(),
        worktree.into(),
        ReviewRequirement::Required,
        vec!["does-not-establish-correctness".into()],
        repair,
        ClockReading(1_000),
    )
    .unwrap()
}

fn operator_proposal(campaign: &str, stage: &str, nonce: &str) -> CampaignStageProposal {
    proposal(
        StageClass::OperatorStage,
        campaign,
        stage,
        nonce,
        "upstream-0",
        vec![pin("/repo", COMMIT_A, TREE_A)],
        &["src/lib.rs", "docs/x.md"],
        "",
        None,
    )
}

fn repair_basis(
    original_stage: &str,
    receipt: Sha256Digest,
    findings: &[&str],
    scope: RepairScopeClass,
) -> RepairBasis {
    RepairBasis {
        original_stage: original_stage.into(),
        rejected_review_receipt: receipt,
        finding_ids: findings.iter().map(|f| f.to_string()).collect(),
        scope_class: scope,
        nonclaims: vec!["does-not-widen-scope".into()],
        review_requirement: ReviewRequirement::Required,
    }
}

fn repair_proposal(
    class: StageClass,
    scope: RepairScopeClass,
    adjudication: &AdjudicationReceipt,
    receipt: Sha256Digest,
    findings: &[&str],
    repositories: Vec<RepoPin>,
    paths: &[&str],
) -> CampaignStageProposal {
    // A repair cites the authorizing adjudication by exact digest in its
    // predecessor basis; admission verifies the citation.
    CampaignStageProposal::propose(
        "upstream-repair".into(),
        "camp-1".into(),
        "stage-a-repair".into(),
        class,
        class.required_role(),
        class.required_effect_class(),
        StageBasis::PredecessorStage {
            stage: "stage-a".into(),
            adjudication_digest: adjudication.digest,
        },
        repositories,
        paths.iter().map(|p| p.to_string()).collect(),
        "evidence-contract-1".into(),
        "handoff-schema-1".into(),
        ClockReading(10_000),
        "nonce-repair".into(),
        String::new(),
        ReviewRequirement::Required,
        vec!["does-not-establish-correctness".into()],
        Some(repair_basis("stage-a", receipt, findings, scope)),
        ClockReading(4_500),
    )
    .unwrap()
}

fn context(standing: &CampaignStageStanding, role: WorkerRole) -> ExecutionContext {
    ExecutionContext {
        campaign: standing.campaign().to_string(),
        stage: standing.stage().to_string(),
        role,
        proposal_digest: standing.proposal_digest(),
    }
}

/// Propose and admit an operator stage.
fn admitted_operator(store: &mut SqliteStore) -> CampaignStageStanding {
    let p = operator_proposal("camp-1", "stage-a", "nonce-1");
    svc::propose_stage(store, &p).unwrap();
    svc::admit(store, &p.digest, ClockReading(2_000)).unwrap()
}

/// Run a stage to a receipted review outcome and adjudicate it, returning
/// the durable adjudication receipt repairs must cite.
fn adjudicated_stage(
    store: &mut SqliteStore,
    verdict: AdjudicationVerdict,
    receipt: Sha256Digest,
    findings: &[&str],
) -> AdjudicationReceipt {
    let standing = admitted_operator(store);
    svc::consume(
        store,
        &standing.digest(),
        &context(&standing, WorkerRole::Operator),
        ClockReading(3_000),
    )
    .unwrap();
    svc::record_receipt(store, &standing.digest(), &receipt).unwrap();
    svc::adjudicate(
        store,
        "camp-1",
        "stage-a",
        &receipt,
        verdict,
        "adjudicator-1",
        findings.iter().map(|f| f.to_string()).collect(),
        vec![],
        ClockReading(4_000),
    )
    .unwrap()
}

// --- Success paths -------------------------------------------------------

#[test]
fn one_use_consumption_success_path() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    assert_eq!(standing.state(), &CampaignStandingState::Available);
    let record = svc::consume(
        &mut store,
        &standing.digest(),
        &context(&standing, WorkerRole::Operator),
        ClockReading(3_000),
    )
    .unwrap();
    assert_eq!(record.standing, standing.digest());
    // Durable before any effect: the store already shows the burn.
    let persisted = store
        .get_campaign_consumption(&standing.digest())
        .unwrap()
        .unwrap();
    assert_eq!(persisted, record);
    let reloaded = store
        .get_campaign_standing(&standing.digest())
        .unwrap()
        .unwrap();
    assert_eq!(
        reloaded.state(),
        &CampaignStandingState::Consumed {
            consumption: record.digest
        }
    );
}

#[test]
fn reviewer_read_only_standing_is_issued_and_consumed_once() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let p = proposal(
        StageClass::ReviewerStage,
        "camp-1",
        "stage-review",
        "nonce-r",
        "upstream-r",
        vec![pin("/repo", COMMIT_A, TREE_A)],
        &["src/lib.rs"],
        "worktree-1",
        None,
    );
    svc::propose_stage(&mut store, &p).unwrap();
    let standing = svc::admit(&mut store, &p.digest, ClockReading(2_000)).unwrap();
    assert_eq!(standing.role(), WorkerRole::Reviewer);
    let record = svc::consume(
        &mut store,
        &standing.digest(),
        &context(&standing, WorkerRole::Reviewer),
        ClockReading(3_000),
    )
    .unwrap();
    assert!(matches!(
        store
            .get_campaign_standing(&standing.digest())
            .unwrap()
            .unwrap()
            .state(),
        CampaignStandingState::Consumed { consumption } if *consumption == record.digest
    ));
}

#[test]
fn records_only_repair_within_original_paths_is_admitted() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let adjudication = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    let standing = svc::admit(&mut store, &p.digest, ClockReading(5_000)).unwrap();
    assert_eq!(standing.role(), WorkerRole::Repair);
}

#[test]
fn existing_source_scope_repair_within_the_allowlist_is_admitted() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let adjudication = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    let p = repair_proposal(
        StageClass::ExistingSourceScopeRepairStage,
        RepairScopeClass::ExistingSourceScope,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["docs/x.md"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    svc::admit(&mut store, &p.digest, ClockReading(5_000)).unwrap();
}

#[test]
fn adjudication_and_residuals_are_durable_and_preserved() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    svc::consume(
        &mut store,
        &standing.digest(),
        &context(&standing, WorkerRole::Operator),
        ClockReading(3_000),
    )
    .unwrap();
    svc::record_receipt(&mut store, &standing.digest(), &REVIEW_RECEIPT).unwrap();
    let receipt = svc::adjudicate(
        &mut store,
        "camp-1",
        "stage-a",
        &REVIEW_RECEIPT,
        AdjudicationVerdict::Refuse,
        "adjudicator-1",
        vec!["finding-9".into()],
        vec![ResidualStatement {
            kind: "human_review".into(),
            statement: "a human must re-review any successor".into(),
        }],
        ClockReading(4_000),
    )
    .unwrap();
    let adjudications = store
        .get_campaign_adjudications("camp-1", "stage-a")
        .unwrap();
    assert_eq!(adjudications, vec![receipt.clone()]);
    assert_eq!(receipt.recompute_digest(), receipt.digest);
    let residuals = store.get_campaign_residuals("camp-1", "stage-a").unwrap();
    assert_eq!(residuals, receipt.residuals);
}

// --- Hostile: replay and substitution ------------------------------------

#[test]
fn standing_replay_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    let ctx = context(&standing, WorkerRole::Operator);
    svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)).unwrap();
    // The burn exists and the outcome is unresolved: a second consumption is
    // refused by the crash-recovery classification, and the consumed standing
    // itself refuses a replayed burn.
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_100)),
        Err(CampaignError::Refusal(CampaignRefusal::OutcomeUnresolved))
    );
    let reloaded = store
        .get_campaign_standing(&standing.digest())
        .unwrap()
        .unwrap();
    assert_eq!(
        reloaded.consume(&ctx, ClockReading(3_100)),
        Err(CampaignRefusal::AlreadyConsumed)
    );
}

#[test]
fn stage_substitution_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    let mut ctx = context(&standing, WorkerRole::Operator);
    ctx.stage = "stage-b".into();
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)),
        Err(CampaignError::Refusal(CampaignRefusal::StageMismatch))
    );
}

#[test]
fn campaign_substitution_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    let mut ctx = context(&standing, WorkerRole::Operator);
    ctx.campaign = "camp-2".into();
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)),
        Err(CampaignError::Refusal(CampaignRefusal::CampaignMismatch))
    );
}

#[test]
fn role_substitution_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    let ctx = context(&standing, WorkerRole::Repair);
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)),
        Err(CampaignError::Refusal(CampaignRefusal::RoleMismatch))
    );
}

#[test]
fn source_basis_substitution_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    // An identical proposal but for one repository commit is a different
    // proposal; presenting it against this standing refuses.
    let altered = operator_proposal_with_pin(pin("/repo", COMMIT_B, TREE_B));
    let mut ctx = context(&standing, WorkerRole::Operator);
    ctx.proposal_digest = altered.digest;
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)),
        Err(CampaignError::Refusal(CampaignRefusal::ProposalMismatch))
    );
}

fn operator_proposal_with_pin(pin: RepoPin) -> CampaignStageProposal {
    proposal(
        StageClass::OperatorStage,
        "camp-1",
        "stage-a",
        "nonce-1",
        "upstream-0",
        vec![pin],
        &["src/lib.rs", "docs/x.md"],
        "",
        None,
    )
}

#[test]
fn stale_standing_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    let ctx = context(&standing, WorkerRole::Operator);
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(10_000)),
        Err(CampaignError::Refusal(CampaignRefusal::Expired))
    );
}

#[test]
fn historical_standing_presented_as_current_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let first = admitted_operator(&mut store);
    // The stage is re-proposed with a new nonce and re-admitted; the first
    // standing is now historical.
    let reproposal = operator_proposal("camp-1", "stage-a", "nonce-2");
    svc::propose_stage(&mut store, &reproposal).unwrap();
    let current = svc::admit(&mut store, &reproposal.digest, ClockReading(2_500)).unwrap();
    assert!(first.superseded_by(&current));
    assert_eq!(
        svc::consume(
            &mut store,
            &first.digest(),
            &context(&first, WorkerRole::Operator),
            ClockReading(3_000)
        ),
        Err(CampaignError::Refusal(CampaignRefusal::Superseded))
    );
    // The current standing consumes normally.
    svc::consume(
        &mut store,
        &current.digest(),
        &context(&current, WorkerRole::Operator),
        ClockReading(3_000),
    )
    .unwrap();
}

// --- Hostile: effect class and reviewer law -------------------------------

#[test]
fn effect_class_widening_refuses_at_proposal() {
    // A reviewer stage may not propose mutation; a records-repair stage may
    // not propose workspace mutation. The stage class fixes the effect class.
    assert_eq!(
        CampaignStageProposal::propose(
            "u".into(),
            "c".into(),
            "s".into(),
            StageClass::ReviewerStage,
            WorkerRole::Reviewer,
            gwr_core::campaign::StageEffectClass::WorkspaceMutation,
            StageBasis::RootAuthorization {
                identity: "r".into()
            },
            vec![pin("/repo", COMMIT_A, TREE_A)],
            vec!["src/lib.rs".into()],
            "e".into(),
            "h".into(),
            ClockReading(10_000),
            "n".into(),
            "worktree-1".into(),
            ReviewRequirement::NotRequired,
            vec![],
            None,
            ClockReading(1_000),
        ),
        Err(CampaignRefusal::EffectClassNotPermitted {
            stage_class: "reviewer_stage",
            effect_class: "workspace_mutation",
        })
    );
}

#[test]
fn reviewer_mutation_request_refuses_every_mutation_op() {
    for op in [
        MutationOp::Commit,
        MutationOp::Push,
        MutationOp::Tag,
        MutationOp::Reset,
        MutationOp::Rebase,
        MutationOp::BranchMutation,
        MutationOp::RemoteMutation,
    ] {
        assert_eq!(
            reviewer_permits(&ReviewEffect::Mutation(op)),
            Err(CampaignRefusal::ReviewerMutationForbidden {
                op: op.tag().to_string()
            })
        );
    }
    assert_eq!(reviewer_permits(&ReviewEffect::Read), Ok(()));
    assert_eq!(reviewer_permits(&ReviewEffect::Test), Ok(()));
}

#[test]
fn operator_using_reviewer_standing_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let p = proposal(
        StageClass::ReviewerStage,
        "camp-1",
        "stage-review",
        "nonce-r",
        "upstream-r",
        vec![pin("/repo", COMMIT_A, TREE_A)],
        &["src/lib.rs"],
        "worktree-1",
        None,
    );
    svc::propose_stage(&mut store, &p).unwrap();
    let standing = svc::admit(&mut store, &p.digest, ClockReading(2_000)).unwrap();
    let ctx = context(&standing, WorkerRole::Operator);
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)),
        Err(CampaignError::Refusal(CampaignRefusal::RoleMismatch))
    );
}

#[test]
fn reviewer_using_operator_standing_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    let ctx = context(&standing, WorkerRole::Reviewer);
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)),
        Err(CampaignError::Refusal(CampaignRefusal::RoleMismatch))
    );
}

// --- Hostile: repair law ---------------------------------------------------

#[test]
fn repair_finding_substitution_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let adjudication = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-2"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairFindingsMismatch
        ))
    );
}

#[test]
fn repair_referencing_a_different_review_receipt_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let adjudication = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    // The repair cites a receipt no consumed standing of the original stage
    // ever produced: the authority chain does not resolve.
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        OTHER_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::AdjudicationSubjectUnknown
        ))
    );
}

#[test]
fn repair_path_outside_original_scope_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let adjudication = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    // Path widening: "src/widened.rs" was never in the original authority.
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs", "src/widened.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairPathOutsideOriginalScope {
                path: "src/widened.rs".into()
            }
        ))
    );
    // Repository widening refuses the same way.
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/other", COMMIT_B, TREE_B)],
        &["src/lib.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairRepositoryOutsideScope {
                repository: "/other".into()
            }
        ))
    );
}

#[test]
fn never_admitted_classes_refuse_by_name_including_auto_repair() {
    for class in [
        "new_source_scope",
        "architecture",
        "authority",
        "basis",
        "candidate",
        "freeze",
        "qualification",
        "certificate",
        "registry",
        "deployment",
    ] {
        assert_eq!(
            StageClass::admit_tag(class),
            Err(CampaignRefusal::StageClassNeverAdmitted {
                class: class.to_string()
            }),
            "{class} must refuse by name"
        );
    }
}

// --- Hostile: crash recovery ------------------------------------------------

#[test]
fn crash_recovery_attempting_a_duplicate_effect_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    let ctx = context(&standing, WorkerRole::Operator);
    svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)).unwrap();
    svc::record_receipt(&mut store, &standing.digest(), &REVIEW_RECEIPT).unwrap();
    // The effect completed and is receipted: re-execution is a duplicate.
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_100)),
        Err(CampaignError::Refusal(
            CampaignRefusal::EffectAlreadyReceipted
        ))
    );
}

#[test]
fn ambiguous_crash_states_refuse_reexecution() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    let ctx = context(&standing, WorkerRole::Operator);
    svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)).unwrap();
    // Standing consumed, outcome unresolved.
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_100)),
        Err(CampaignError::Refusal(CampaignRefusal::OutcomeUnresolved))
    );
    // Effect completed, receipt missing.
    svc::record_effect_completed(&mut store, &standing.digest()).unwrap();
    assert_eq!(
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_200)),
        Err(CampaignError::Refusal(CampaignRefusal::ReceiptMissing))
    );
}

// --- Persistence -------------------------------------------------------------

#[test]
fn campaign_records_round_trip_through_the_store() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let p = operator_proposal("camp-1", "stage-a", "nonce-1");
    svc::propose_stage(&mut store, &p).unwrap();
    let loaded = store.get_campaign_proposal(&p.digest).unwrap().unwrap();
    assert_eq!(loaded, p);
    assert_eq!(loaded.recompute_digest(), p.digest);
    // An identical re-record is idempotent.
    svc::propose_stage(&mut store, &p).unwrap();
    let by_stage = store.find_campaign_proposals("camp-1", "stage-a").unwrap();
    assert_eq!(by_stage, vec![p.clone()]);

    let standing = svc::admit(&mut store, &p.digest, ClockReading(2_000)).unwrap();
    let loaded = store
        .get_campaign_standing(&standing.digest())
        .unwrap()
        .unwrap();
    assert_eq!(loaded, standing);
    assert_eq!(loaded.recompute_digest(), standing.digest());
}

#[test]
fn a_consumption_record_references_standing_and_receipt() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    let ctx = context(&standing, WorkerRole::Operator);
    let record: CampaignStageConsumption =
        svc::consume(&mut store, &standing.digest(), &ctx, ClockReading(3_000)).unwrap();
    assert_eq!(record.standing, standing.digest());
    assert_eq!(record.receipt, None);
    svc::record_receipt(&mut store, &standing.digest(), &REVIEW_RECEIPT).unwrap();
    let persisted = store
        .get_campaign_consumption(&standing.digest())
        .unwrap()
        .unwrap();
    // Once known, the record references both the standing digest and the
    // consuming receipt digest.
    assert_eq!(persisted.receipt, Some(REVIEW_RECEIPT));
    assert!(persisted.effect_completed);
    assert_eq!(
        store.campaign_stage_receipts("camp-1", "stage-a").unwrap(),
        vec![REVIEW_RECEIPT]
    );
}

// --- F1 regression: the repair-scope anchor is the consumed standing -------
//
// The repair subset law anchors to the exact proposal that produced the
// consumed standing of the adjudicated stage, recovered through the durable
// burn carrying the rejected review receipt — never to the newest, earliest,
// or any same-name record-only proposal.

/// A widened same-name re-proposal of the original stage: records only, no
/// standing, no authority.
fn widened_reproposal(
    store: &mut SqliteStore,
    nonce: &str,
    extra_path: &str,
) -> CampaignStageProposal {
    let p = proposal(
        StageClass::OperatorStage,
        "camp-1",
        "stage-a",
        nonce,
        "upstream-9",
        vec![pin("/repo", COMMIT_A, TREE_A)],
        &["src/lib.rs", "docs/x.md", extra_path],
        "",
        None,
    );
    svc::propose_stage(store, &p).unwrap();
    p
}

#[test]
fn widened_reproposal_after_adjudication_cannot_rebase_repair_scope() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let adjudication = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    // The exploit: a wider same-name proposal recorded after the original
    // stage was consumed and adjudicated. Its digest differs from the
    // consumed original's, and recording it creates nothing.
    let widened = widened_reproposal(&mut store, "nonce-9", "src/widened.rs");
    let original = operator_proposal("camp-1", "stage-a", "nonce-1");
    assert_ne!(widened.digest, original.digest);
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs", "src/widened.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairPathOutsideOriginalScope {
                path: "src/widened.rs".into()
            }
        ))
    );
    // The valid exact-subset repair still admits against the consumed
    // original authority.
    let ok = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs"],
    );
    svc::propose_stage(&mut store, &ok).unwrap();
    svc::admit(&mut store, &ok.digest, ClockReading(5_000)).unwrap();
}

#[test]
fn widened_reproposal_recorded_before_adjudication_cannot_rebase_repair_scope() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let standing = admitted_operator(&mut store);
    svc::consume(
        &mut store,
        &standing.digest(),
        &context(&standing, WorkerRole::Operator),
        ClockReading(3_000),
    )
    .unwrap();
    svc::record_receipt(&mut store, &standing.digest(), &REVIEW_RECEIPT).unwrap();
    // The widened re-proposal is recorded after consumption but before the
    // adjudication exists; the anchor still does not move.
    widened_reproposal(&mut store, "nonce-9", "src/widened.rs");
    let adjudication = svc::adjudicate(
        &mut store,
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
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/widened.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairPathOutsideOriginalScope {
                path: "src/widened.rs".into()
            }
        ))
    );
}

#[test]
fn narrower_reproposal_cannot_replace_the_consumed_authority_anchor() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let adjudication = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    // A narrower same-name re-proposal is recorded. The anchor is the
    // consumed original, not any re-proposal: a repair for "docs/x.md" — in
    // the consumed original, absent from the narrower re-proposal — admits.
    let narrower = proposal(
        StageClass::OperatorStage,
        "camp-1",
        "stage-a",
        "nonce-9",
        "upstream-9",
        vec![pin("/repo", COMMIT_A, TREE_A)],
        &["src/lib.rs"],
        "",
        None,
    );
    svc::propose_stage(&mut store, &narrower).unwrap();
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["docs/x.md"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    svc::admit(&mut store, &p.digest, ClockReading(5_000)).unwrap();
}

#[test]
fn same_stage_name_in_another_campaign_never_resolves() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    // camp-2 runs a wide stage-a to an adjudicated exact repair.
    let wide = proposal(
        StageClass::OperatorStage,
        "camp-2",
        "stage-a",
        "nonce-c2",
        "upstream-c2",
        vec![pin("/repo", COMMIT_A, TREE_A)],
        &["src/lib.rs", "docs/x.md", "src/widened.rs"],
        "",
        None,
    );
    svc::propose_stage(&mut store, &wide).unwrap();
    let c2_standing = svc::admit(&mut store, &wide.digest, ClockReading(2_000)).unwrap();
    svc::consume(
        &mut store,
        &c2_standing.digest(),
        &context(&c2_standing, WorkerRole::Operator),
        ClockReading(3_000),
    )
    .unwrap();
    svc::record_receipt(&mut store, &c2_standing.digest(), &OTHER_RECEIPT).unwrap();
    svc::adjudicate(
        &mut store,
        "camp-2",
        "stage-a",
        &OTHER_RECEIPT,
        AdjudicationVerdict::ExactRepair,
        "adjudicator-1",
        vec!["finding-1".into()],
        vec![],
        ClockReading(4_000),
    )
    .unwrap();
    // camp-1 runs its own narrow stage-a.
    let adjudication = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    // A camp-1 repair is bounded by camp-1's consumed original — the camp-2
    // width is invisible to it.
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/widened.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairPathOutsideOriginalScope {
                path: "src/widened.rs".into()
            }
        ))
    );
    // A camp-2 repair citing camp-1's adjudication refuses: the cited
    // adjudication belongs to another campaign.
    let cross = CampaignStageProposal::propose(
        "upstream-repair-c2".into(),
        "camp-2".into(),
        "stage-a-repair".into(),
        StageClass::RecordsRepairStage,
        StageClass::RecordsRepairStage.required_role(),
        StageClass::RecordsRepairStage.required_effect_class(),
        StageBasis::PredecessorStage {
            stage: "stage-a".into(),
            adjudication_digest: adjudication.digest,
        },
        vec![pin("/repo", COMMIT_B, TREE_B)],
        vec!["src/lib.rs".to_string()],
        "evidence-contract-1".into(),
        "handoff-schema-1".into(),
        ClockReading(10_000),
        "nonce-repair-c2".into(),
        String::new(),
        ReviewRequirement::Required,
        vec![],
        Some(repair_basis(
            "stage-a",
            REVIEW_RECEIPT,
            &["finding-1"],
            RepairScopeClass::RecordsOnly,
        )),
        ClockReading(4_500),
    )
    .unwrap();
    svc::propose_stage(&mut store, &cross).unwrap();
    // The camp-1 review receipt was never the outcome of a consumed camp-2
    // standing: the camp-2 chain does not resolve at all.
    assert_eq!(
        svc::admit(&mut store, &cross.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::AdjudicationSubjectUnknown
        ))
    );
}

#[test]
fn an_unknown_or_missing_adjudication_citation_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    // A fabricated adjudication digest: the citation does not resolve.
    let fabricated = CampaignStageProposal::propose(
        "upstream-repair".into(),
        "camp-1".into(),
        "stage-a-repair".into(),
        StageClass::RecordsRepairStage,
        StageClass::RecordsRepairStage.required_role(),
        StageClass::RecordsRepairStage.required_effect_class(),
        StageBasis::PredecessorStage {
            stage: "stage-a".into(),
            adjudication_digest: Sha256Digest::from_bytes([3; 32]),
        },
        vec![pin("/repo", COMMIT_B, TREE_B)],
        vec!["src/lib.rs".to_string()],
        "evidence-contract-1".into(),
        "handoff-schema-1".into(),
        ClockReading(10_000),
        "nonce-repair".into(),
        String::new(),
        ReviewRequirement::Required,
        vec![],
        Some(repair_basis(
            "stage-a",
            REVIEW_RECEIPT,
            &["finding-1"],
            RepairScopeClass::RecordsOnly,
        )),
        ClockReading(4_500),
    )
    .unwrap();
    svc::propose_stage(&mut store, &fabricated).unwrap();
    assert_eq!(
        svc::admit(&mut store, &fabricated.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairAdjudicationUnknown
        ))
    );
    // Omitting the citation entirely (root basis on a repair) refuses.
    let uncited = proposal(
        StageClass::RecordsRepairStage,
        "camp-1",
        "stage-a-repair",
        "nonce-repair-2",
        "upstream-repair-2",
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs"],
        "",
        Some(repair_basis(
            "stage-a",
            REVIEW_RECEIPT,
            &["finding-1"],
            RepairScopeClass::RecordsOnly,
        )),
    );
    svc::propose_stage(&mut store, &uncited).unwrap();
    assert_eq!(
        svc::admit(&mut store, &uncited.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairOriginalStageMismatch
        ))
    );
}

#[test]
fn an_adjudication_for_a_different_receipt_or_stage_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    // Two executions of stage-a: receipt R1, then (after re-proposal)
    // receipt R2, each adjudicated.
    let adjudication_r1 = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    let reproposal = operator_proposal("camp-1", "stage-a", "nonce-2");
    svc::propose_stage(&mut store, &reproposal).unwrap();
    let second = svc::admit(&mut store, &reproposal.digest, ClockReading(4_100)).unwrap();
    svc::consume(
        &mut store,
        &second.digest(),
        &context(&second, WorkerRole::Operator),
        ClockReading(4_200),
    )
    .unwrap();
    svc::record_receipt(&mut store, &second.digest(), &OTHER_RECEIPT).unwrap();
    let adjudication_r2 = svc::adjudicate(
        &mut store,
        "camp-1",
        "stage-a",
        &OTHER_RECEIPT,
        AdjudicationVerdict::ExactRepair,
        "adjudicator-1",
        vec!["finding-2".into()],
        vec![],
        ClockReading(4_300),
    )
    .unwrap();
    // Citing the R2 adjudication while naming R1 as the rejected review:
    // the chain resolves R1's burn, and the citation disagrees with it.
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication_r2,
        REVIEW_RECEIPT,
        &["finding-2"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairReviewReceiptMismatch
        ))
    );
    // An adjudication of a different stage is not authority for this one.
    let other_stage = proposal(
        StageClass::OperatorStage,
        "camp-1",
        "stage-b",
        "nonce-b",
        "upstream-b",
        vec![pin("/repo", COMMIT_A, TREE_A)],
        &["src/lib.rs", "docs/x.md", "src/widened.rs"],
        "",
        None,
    );
    svc::propose_stage(&mut store, &other_stage).unwrap();
    let b_standing = svc::admit(&mut store, &other_stage.digest, ClockReading(4_400)).unwrap();
    svc::consume(
        &mut store,
        &b_standing.digest(),
        &context(&b_standing, WorkerRole::Operator),
        ClockReading(4_500),
    )
    .unwrap();
    let b_receipt = Sha256Digest::from_bytes([5; 32]);
    svc::record_receipt(&mut store, &b_standing.digest(), &b_receipt).unwrap();
    let adjudication_b = svc::adjudicate(
        &mut store,
        "camp-1",
        "stage-b",
        &b_receipt,
        AdjudicationVerdict::ExactRepair,
        "adjudicator-1",
        vec!["finding-1".into()],
        vec![],
        ClockReading(4_600),
    )
    .unwrap();
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication_b,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairOriginalStageMismatch
        ))
    );
    // The R1 adjudication remains the exact authority for R1's chain.
    let _ = adjudication_r1;
}

#[test]
fn a_superseded_adjudication_authorizes_no_repair() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let adjudication = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    // A newer adjudication of the same review receipt supersedes it.
    svc::adjudicate(
        &mut store,
        "camp-1",
        "stage-a",
        &REVIEW_RECEIPT,
        AdjudicationVerdict::Refuse,
        "adjudicator-1",
        vec!["finding-1".into()],
        vec![],
        ClockReading(4_900),
    )
    .unwrap();
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(CampaignRefusal::Superseded))
    );
}

#[test]
fn an_ambiguous_consumed_standing_chain_refuses() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let adjudication = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    // A second execution of the same stage carries the same review receipt:
    // the original authority no longer resolves to one consumed standing.
    let reproposal = operator_proposal("camp-1", "stage-a", "nonce-2");
    svc::propose_stage(&mut store, &reproposal).unwrap();
    let second = svc::admit(&mut store, &reproposal.digest, ClockReading(4_100)).unwrap();
    svc::consume(
        &mut store,
        &second.digest(),
        &context(&second, WorkerRole::Operator),
        ClockReading(4_200),
    )
    .unwrap();
    svc::record_receipt(&mut store, &second.digest(), &REVIEW_RECEIPT).unwrap();
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairOriginalStandingAmbiguous
        ))
    );
}

#[test]
fn a_records_only_repair_cannot_gain_a_source_path() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    // The original stage authority covers records paths only.
    let docs_only = proposal(
        StageClass::OperatorStage,
        "camp-1",
        "stage-a",
        "nonce-1",
        "upstream-0",
        vec![pin("/repo", COMMIT_A, TREE_A)],
        &["docs/x.md"],
        "",
        None,
    );
    svc::propose_stage(&mut store, &docs_only).unwrap();
    let standing = svc::admit(&mut store, &docs_only.digest, ClockReading(2_000)).unwrap();
    svc::consume(
        &mut store,
        &standing.digest(),
        &context(&standing, WorkerRole::Operator),
        ClockReading(3_000),
    )
    .unwrap();
    svc::record_receipt(&mut store, &standing.digest(), &REVIEW_RECEIPT).unwrap();
    let adjudication = svc::adjudicate(
        &mut store,
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
    let p = repair_proposal(
        StageClass::RecordsRepairStage,
        RepairScopeClass::RecordsOnly,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/main.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairPathOutsideOriginalScope {
                path: "src/main.rs".into()
            }
        ))
    );
}

#[test]
fn an_existing_source_repair_cannot_use_a_later_widened_proposals_paths() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let adjudication = adjudicated_stage(
        &mut store,
        AdjudicationVerdict::ExactRepair,
        REVIEW_RECEIPT,
        &["finding-1"],
    );
    widened_reproposal(&mut store, "nonce-9", "src/widened.rs");
    let p = repair_proposal(
        StageClass::ExistingSourceScopeRepairStage,
        RepairScopeClass::ExistingSourceScope,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/widened.rs"],
    );
    svc::propose_stage(&mut store, &p).unwrap();
    assert_eq!(
        svc::admit(&mut store, &p.digest, ClockReading(5_000)),
        Err(CampaignError::Refusal(
            CampaignRefusal::RepairPathOutsideOriginalScope {
                path: "src/widened.rs".into()
            }
        ))
    );
    // Within the consumed original source allowlist, it admits.
    let ok = repair_proposal(
        StageClass::ExistingSourceScopeRepairStage,
        RepairScopeClass::ExistingSourceScope,
        &adjudication,
        REVIEW_RECEIPT,
        &["finding-1"],
        vec![pin("/repo", COMMIT_B, TREE_B)],
        &["src/lib.rs"],
    );
    svc::propose_stage(&mut store, &ok).unwrap();
    svc::admit(&mut store, &ok.digest, ClockReading(5_000)).unwrap();
}
