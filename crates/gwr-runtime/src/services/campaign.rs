//! Campaign-stage standing services (S-2): propose, admit, consume, record
//! outcome, adjudicate.
//!
//! These services coordinate the store; the law lives in `gwr_core::campaign`.
//! Burn-before-effect is structural: `consume` makes the one consumption
//! durable before the caller runs any effect, and a second consumption hits
//! the crash-recovery classification and refuses — ambiguous states are never
//! guessed and re-run.

use crate::ports::store::{CampaignBurn, Store, StoreError};
use gwr_core::campaign::adjudication::{
    AdjudicationReceipt, AdjudicationVerdict, ResidualStatement,
};
use gwr_core::campaign::authority::RepairAuthorityV1;
use gwr_core::campaign::proposal::{CampaignStageProposal, StageBasis};
use gwr_core::campaign::repair::validate_repair;
use gwr_core::campaign::standing::{
    classify, reexecution_decision, CampaignStageConsumption, CampaignStageStanding,
    ExecutionContext,
};
use gwr_core::digest::Sha256Digest;
use gwr_core::refusal::CampaignRefusal;
use gwr_core::work_request::ClockReading;

#[derive(Debug, PartialEq, Eq)]
pub enum CampaignError {
    Store(StoreError),
    Refusal(CampaignRefusal),
    /// The named proposal or standing is not recorded.
    NotFound(String),
}

impl From<StoreError> for CampaignError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<CampaignRefusal> for CampaignError {
    fn from(e: CampaignRefusal) -> Self {
        Self::Refusal(e)
    }
}

/// Record an exact stage proposal. Idempotent for an identical proposal; the
/// digest is the content address, so a rebind is impossible by construction.
/// Creates no standing.
pub fn propose_stage(
    store: &mut dyn Store,
    proposal: &CampaignStageProposal,
) -> Result<Sha256Digest, CampaignError> {
    store.record_campaign_proposal(proposal)?;
    Ok(proposal.digest)
}

/// The exact repair-authority chain (F1), shared by admission and by the
/// read-only repair-authority export: the repair's predecessor basis cites
/// the authorizing adjudication by digest; the adjudicated rejected review
/// receipt resolves through the durable burn carrying it to the one consumed
/// standing of the original stage; that standing's `proposal_digest` names
/// the original stage authority. Returns the verified adjudication, the
/// consumed original standing, and the original proposal — with the subset
/// law (`validate_repair`) already applied. No stage-name query substitutes
/// for any edge of this chain.
fn resolve_repair_authority_chain(
    store: &mut dyn Store,
    proposal: &CampaignStageProposal,
) -> Result<
    (
        AdjudicationReceipt,
        CampaignStageStanding,
        CampaignStageProposal,
    ),
    CampaignError,
> {
    let basis = proposal
        .repair
        .as_ref()
        .ok_or(CampaignRefusal::RepairBasisMissing)?;
    // The repair must cite the authorizing adjudication by exact digest
    // in its predecessor basis, naming the original stage.
    let cited = match &proposal.basis {
        StageBasis::PredecessorStage {
            stage,
            adjudication_digest,
        } if stage == &basis.original_stage => *adjudication_digest,
        _ => return Err(CampaignRefusal::RepairOriginalStageMismatch.into()),
    };
    let adjudication = store
        .get_campaign_adjudication(&cited)?
        .ok_or(CampaignRefusal::RepairAdjudicationUnknown)?;
    // A cited adjudication superseded by a newer adjudication of the
    // same review receipt authorizes nothing current.
    for other in store.get_campaign_adjudications(&proposal.campaign, &basis.original_stage)? {
        if other.digest != adjudication.digest
            && other.review_receipt == adjudication.review_receipt
            && other.adjudicated_at >= adjudication.adjudicated_at
        {
            return Err(CampaignRefusal::Superseded.into());
        }
    }
    // The original authority chain: the adjudicated review receipt is
    // carried by exactly one durable burn of the original stage; that
    // burn's standing names the exact proposal that was executed.
    let burns = store.find_campaign_consumptions_by_receipt(
        &proposal.campaign,
        &basis.original_stage,
        &basis.rejected_review_receipt,
    )?;
    let [burn] = burns.as_slice() else {
        return Err(if burns.is_empty() {
            CampaignRefusal::AdjudicationSubjectUnknown.into()
        } else {
            CampaignRefusal::RepairOriginalStandingAmbiguous.into()
        });
    };
    let original_standing = store
        .get_campaign_standing(&burn.standing)?
        .ok_or_else(|| CampaignError::NotFound(format!("standing {}", burn.standing)))?;
    let original = store
        .get_campaign_proposal(&original_standing.proposal_digest())?
        .ok_or_else(|| {
            CampaignError::NotFound(format!("proposal {}", original_standing.proposal_digest()))
        })?;
    validate_repair(proposal, &original, &adjudication)?;
    Ok((adjudication, original_standing, original))
}

/// Admit a recorded proposal and issue the standing it justifies.
///
/// For repair stage classes this is where the subset decision is made, and
/// the anchor is exact: the repair's predecessor basis cites the authorizing
/// adjudication by digest; the adjudication's rejected review receipt
/// resolves, through the durable consumption row that carries it, to the one
/// consumed standing of the original stage; that standing's
/// `proposal_digest` names the original stage authority. The subset check
/// runs against that proposal — never against the newest, earliest, or any
/// same-name record-only proposal, which carry no authority. The sidecar
/// never makes this decision.
pub fn admit(
    store: &mut dyn Store,
    proposal_digest: &Sha256Digest,
    now: ClockReading,
) -> Result<CampaignStageStanding, CampaignError> {
    let proposal = store
        .get_campaign_proposal(proposal_digest)?
        .ok_or_else(|| CampaignError::NotFound(format!("proposal {proposal_digest}")))?;
    if proposal.repair.is_some() {
        resolve_repair_authority_chain(store, &proposal)?;
    }
    let standing = CampaignStageStanding::issue(&proposal, now)?;
    store.record_campaign_standing(&standing)?;
    Ok(standing)
}

/// Export the exact Docket authority for one repair stage's execution
/// (P1): a read-only, content-addressed projection of the durable records —
/// the repair standing and proposal, the cited adjudication, the rejected
/// review receipt, and the consumed original stage authority resolved
/// through the F1 chain. Export re-verifies the chain and current law
/// (adjudication and standing supersession, expiry, the subset check), so a
/// drifted or unlawful authority cannot be exported. `verifier` names the
/// emitting adapter generation; it is file-level metadata, not part of the
/// typed content address.
pub fn export_repair_authority(
    store: &mut dyn Store,
    standing_digest: &Sha256Digest,
    now: ClockReading,
    verifier: &str,
) -> Result<RepairAuthorityV1, CampaignError> {
    let standing = store
        .get_campaign_standing(standing_digest)?
        .ok_or_else(|| CampaignError::NotFound(format!("standing {standing_digest}")))?;
    if !standing.stage_class().is_repair() {
        return Err(CampaignRefusal::RepairAuthorityMismatch {
            field: "stage_class",
        }
        .into());
    }
    let proposal = store
        .get_campaign_proposal(&standing.proposal_digest())?
        .ok_or_else(|| {
            CampaignError::NotFound(format!("proposal {}", standing.proposal_digest()))
        })?;
    let (adjudication, original_standing, original) =
        resolve_repair_authority_chain(store, &proposal)?;
    let basis = proposal
        .repair
        .as_ref()
        .expect("repair basis checked above");
    // Current law: a superseded repair standing is historical, and an
    // expired window justifies nothing.
    if let Some(latest) = store.latest_campaign_standing(standing.campaign(), standing.stage())? {
        if standing.superseded_by(&latest) {
            return Err(CampaignRefusal::Superseded.into());
        }
    }
    if now >= standing.expires_at() {
        return Err(CampaignRefusal::Expired.into());
    }
    // Exact burn state of the repair standing: absent before the burn, the
    // burn digest afterwards. A pre-burn bundle and a post-burn bundle are
    // different artifacts.
    let consumption = store
        .get_campaign_consumption(standing_digest)?
        .map(|c| c.digest);
    Ok(RepairAuthorityV1::issue(
        standing.campaign().to_string(),
        standing.stage().to_string(),
        standing.role(),
        standing.stage_class(),
        standing.effect_class(),
        standing.digest(),
        standing.proposal_digest(),
        consumption,
        basis.original_stage.clone(),
        original.digest,
        original_standing.digest(),
        store
            .find_campaign_consumptions_by_receipt(
                standing.campaign(),
                &basis.original_stage,
                &basis.rejected_review_receipt,
            )?
            .first()
            .expect("chain resolved exactly one burn above")
            .digest,
        basis.rejected_review_receipt,
        adjudication.digest,
        adjudication.verdict,
        basis.finding_ids.clone(),
        basis.scope_class,
        standing.repositories().to_vec(),
        standing.allowed_paths().to_vec(),
        standing.expires_at(),
        standing.nonce().to_string(),
        proposal.nonclaims.clone(),
        verifier.to_string(),
    )?)
}

/// Verify a repair-authority bundle against Docket's own durable state:
/// the bundle's typed digest must recompute from its fields, and the bundle
/// must equal, field for field, the authority Docket re-derives right now —
/// including the exact burn state — under the verifier's clock. Any
/// disagreement refuses with the first differing field named; a stale,
/// superseded, corrupted, or foreign artifact never verifies.
pub fn verify_repair_authority(
    store: &mut dyn Store,
    bundle: &RepairAuthorityV1,
    now: ClockReading,
    verifier: &str,
) -> Result<(), CampaignError> {
    if bundle.recompute_digest() != bundle.digest {
        return Err(CampaignRefusal::RepairAuthorityMismatch { field: "digest" }.into());
    }
    let derived = export_repair_authority(store, &bundle.standing, now, verifier)?;
    if derived != *bundle {
        return Err(CampaignRefusal::RepairAuthorityMismatch {
            field: first_authority_difference(&derived, bundle),
        }
        .into());
    }
    Ok(())
}

/// The first field in which two bundles disagree, in canonical order.
fn first_authority_difference(a: &RepairAuthorityV1, b: &RepairAuthorityV1) -> &'static str {
    if a.campaign != b.campaign {
        return "campaign";
    }
    if a.repair_stage != b.repair_stage {
        return "repair_stage";
    }
    if a.role != b.role {
        return "role";
    }
    if a.stage_class != b.stage_class {
        return "stage_class";
    }
    if a.effect_class != b.effect_class {
        return "effect_class";
    }
    if a.standing != b.standing {
        return "standing";
    }
    if a.proposal_digest != b.proposal_digest {
        return "proposal_digest";
    }
    if a.consumption != b.consumption {
        return "consumption";
    }
    if a.original_stage != b.original_stage {
        return "original_stage";
    }
    if a.original_proposal_digest != b.original_proposal_digest {
        return "original_proposal_digest";
    }
    if a.original_standing != b.original_standing {
        return "original_standing";
    }
    if a.original_consumption != b.original_consumption {
        return "original_consumption";
    }
    if a.rejected_review_receipt != b.rejected_review_receipt {
        return "rejected_review_receipt";
    }
    if a.adjudication != b.adjudication {
        return "adjudication";
    }
    if a.adjudication_verdict != b.adjudication_verdict {
        return "adjudication_verdict";
    }
    if a.finding_ids != b.finding_ids {
        return "finding_ids";
    }
    if a.scope_class != b.scope_class {
        return "scope_class";
    }
    if a.repositories != b.repositories {
        return "repositories";
    }
    if a.allowed_paths != b.allowed_paths {
        return "allowed_paths";
    }
    if a.expires_at != b.expires_at {
        return "expires_at";
    }
    if a.nonce != b.nonce {
        return "nonce";
    }
    if a.nonclaims != b.nonclaims {
        return "nonclaims";
    }
    "verifier"
}

/// Burn standing before the stage's effect runs. The consumption record is
/// durable before this call returns; the effect happens afterwards, outside
/// this runtime.
///
/// Refusals, in order: supersession (a newer standing exists for this stage;
/// the presented one is historical), the crash-recovery classification of any
/// existing burn (replay, ambiguous outcome, duplicate effect), then the
/// standing's own scope, expiry, and one-use validation. The fast-path reads
/// preserve this exact refusal vocabulary; the atomic burn re-decides
/// supersession and existence inside one immediate transaction, so exactly
/// one concurrent consumer — across threads, processes, and service
/// instances — receives success, and every other consumer receives the exact
/// classification of the durable winner's row.
pub fn consume(
    store: &mut dyn Store,
    standing_digest: &Sha256Digest,
    context: &ExecutionContext,
    now: ClockReading,
) -> Result<CampaignStageConsumption, CampaignError> {
    let standing = store
        .get_campaign_standing(standing_digest)?
        .ok_or_else(|| CampaignError::NotFound(format!("standing {standing_digest}")))?;
    if let Some(latest) = store.latest_campaign_standing(standing.campaign(), standing.stage())? {
        if standing.superseded_by(&latest) {
            return Err(CampaignRefusal::Superseded.into());
        }
    }
    let existing = store.get_campaign_consumption(standing_digest)?;
    reexecution_decision(classify(existing.as_ref()))?;
    let record = standing.preflight(context, now)?;
    match store.burn_campaign_standing(&standing, &record)? {
        CampaignBurn::Burned => Ok(record),
        CampaignBurn::Superseded => Err(CampaignRefusal::Superseded.into()),
        CampaignBurn::Existing(row) => Err(existing_burn_refusal(&row).into()),
    }
}

/// The exact refusal for a burn that already exists: the four-state
/// recovery classification of the durable row. A row is never
/// `EffectNotBegun`; the unreachable arm fails closed as `AlreadyConsumed`
/// rather than panic.
fn existing_burn_refusal(row: &CampaignStageConsumption) -> CampaignRefusal {
    match reexecution_decision(classify(Some(row))) {
        Err(refusal) => refusal,
        Ok(()) => CampaignRefusal::AlreadyConsumed,
    }
}

/// Record that the effect of a consumed standing completed, with the receipt
/// not yet known. Moves the durable classification from
/// consumed-outcome-unresolved to effect-completed-receipt-missing; both are
/// ambiguous and refuse re-execution.
pub fn record_effect_completed(
    store: &mut dyn Store,
    standing_digest: &Sha256Digest,
) -> Result<(), CampaignError> {
    if store.get_campaign_consumption(standing_digest)?.is_none() {
        return Err(CampaignError::NotFound(format!(
            "consumption for standing {standing_digest}"
        )));
    }
    store.mark_campaign_effect_completed(standing_digest)?;
    Ok(())
}

/// Record the consuming receipt's digest (AG-NG effect/runtime receipt or
/// sidecar execution-envelope vocabulary), verbatim, once known. Implies
/// effect completion.
pub fn record_receipt(
    store: &mut dyn Store,
    standing_digest: &Sha256Digest,
    receipt: &Sha256Digest,
) -> Result<(), CampaignError> {
    if store.get_campaign_consumption(standing_digest)?.is_none() {
        return Err(CampaignError::NotFound(format!(
            "consumption for standing {standing_digest}"
        )));
    }
    store.record_campaign_receipt(standing_digest, receipt)?;
    Ok(())
}

/// Adjudicate a review receipt for a stage: continue, exact repair, or
/// refuse, as a durable receipt. The adjudicated review receipt must be one
/// this runtime recorded as the outcome of a consumed standing for this
/// campaign and stage — adjudicating a fictitious review refuses.
#[allow(clippy::too_many_arguments)]
pub fn adjudicate(
    store: &mut dyn Store,
    campaign: &str,
    stage: &str,
    review_receipt: &Sha256Digest,
    verdict: AdjudicationVerdict,
    adjudicator: &str,
    findings: Vec<String>,
    residuals: Vec<ResidualStatement>,
    now: ClockReading,
) -> Result<AdjudicationReceipt, CampaignError> {
    let known = store.campaign_stage_receipts(campaign, stage)?;
    if !known.contains(review_receipt) {
        return Err(CampaignRefusal::AdjudicationSubjectUnknown.into());
    }
    let receipt = AdjudicationReceipt::adjudicate(
        campaign.to_string(),
        stage.to_string(),
        *review_receipt,
        verdict,
        adjudicator.to_string(),
        findings,
        residuals,
        now,
    )?;
    store.record_campaign_adjudication(&receipt)?;
    Ok(receipt)
}
