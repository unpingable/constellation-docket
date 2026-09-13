//! The issued campaign-stage standing instrument: content-addressed,
//! role-bound, stage-bound, basis-bound, path-bound, effect-bound, expiring,
//! consumable exactly once.
//!
//! Standing is consumed, not checked: the one consumption is durable before
//! the stage's effect runs (burn-before-effect), and a replayed consumption
//! refuses. Standing is issued only from an exact proposal — never from a
//! historical receipt — and no path widens it after issuance: a worker's
//! output cannot broaden paths, repositories, role, effect class, or window.
//! Fields are private for the same reason as `domain::standing::StandingGrant`:
//! an editable expiry is not expiry.
//!
//! Non-transferable across roles: consumption presents an execution context
//! (campaign, stage, role, proposal digest) and every divergence refuses.

use crate::campaign::proposal::{CampaignStageProposal, RepoPin};
use crate::campaign::{StageClass, StageEffectClass, WorkerRole};
use crate::digest::{Sha256Digest, Transcript};
use crate::refusal::CampaignRefusal;
use crate::work_request::ClockReading;

/// The versioned transcript domain tag for standing digests.
pub const STANDING_TRANSCRIPT: &str = "gwr:campaign-stage-standing:v1";
/// The versioned transcript domain tag for consumption digests.
pub const CONSUMPTION_TRANSCRIPT: &str = "gwr:campaign-stage-consumption:v1";

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CampaignStandingState {
    Available,
    Consumed { consumption: Sha256Digest },
}

/// The context an execution presents when it burns standing. Every element
/// must equal what the standing binds; substitution of any of them is a
/// typed refusal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExecutionContext {
    pub campaign: String,
    pub stage: String,
    pub role: WorkerRole,
    /// The digest of the exact proposal being executed. A proposal whose
    /// source basis (or anything else) was altered has a different digest
    /// and refuses here.
    pub proposal_digest: Sha256Digest,
}

/// A campaign-stage standing instrument. Issued once, consumed once.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CampaignStageStanding {
    digest: Sha256Digest,
    proposal_digest: Sha256Digest,
    /// The upstream office's proposal digest, verbatim from the proposal.
    upstream_digest: String,
    campaign: String,
    stage: String,
    stage_class: StageClass,
    role: WorkerRole,
    effect_class: StageEffectClass,
    repositories: Vec<RepoPin>,
    allowed_paths: Vec<String>,
    expires_at: ClockReading,
    nonce: String,
    issued_at: ClockReading,
    state: CampaignStandingState,
}

impl CampaignStageStanding {
    /// Issue standing from an exact proposal. The standing's window is never
    /// wider than the proposal's; an already-expired proposal justifies
    /// nothing. Pure: the caller persists.
    pub fn issue(
        proposal: &CampaignStageProposal,
        now: ClockReading,
    ) -> Result<Self, CampaignRefusal> {
        if now >= proposal.expires_at {
            return Err(CampaignRefusal::Expired);
        }
        let digest = Self::transcribe(
            &proposal.digest,
            &proposal.upstream_digest,
            &proposal.campaign,
            &proposal.stage,
            proposal.stage_class,
            proposal.role,
            proposal.effect_class,
            &proposal.repositories,
            &proposal.allowed_paths,
            proposal.expires_at,
            &proposal.nonce,
            now,
        );
        Ok(Self {
            digest,
            proposal_digest: proposal.digest,
            upstream_digest: proposal.upstream_digest.clone(),
            campaign: proposal.campaign.clone(),
            stage: proposal.stage.clone(),
            stage_class: proposal.stage_class,
            role: proposal.role,
            effect_class: proposal.effect_class,
            repositories: proposal.repositories.clone(),
            allowed_paths: proposal.allowed_paths.clone(),
            expires_at: proposal.expires_at,
            nonce: proposal.nonce.clone(),
            issued_at: now,
            state: CampaignStandingState::Available,
        })
    }

    /// Rebuild a standing as the store recorded it. Adapter-only: the
    /// persisted rows are the authority on consumption state.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted(
        digest: Sha256Digest,
        proposal_digest: Sha256Digest,
        upstream_digest: String,
        campaign: String,
        stage: String,
        stage_class: StageClass,
        role: WorkerRole,
        effect_class: StageEffectClass,
        repositories: Vec<RepoPin>,
        allowed_paths: Vec<String>,
        expires_at: ClockReading,
        nonce: String,
        issued_at: ClockReading,
        state: CampaignStandingState,
    ) -> Self {
        Self {
            digest,
            proposal_digest,
            upstream_digest,
            campaign,
            stage,
            stage_class,
            role,
            effect_class,
            repositories,
            allowed_paths,
            expires_at,
            nonce,
            issued_at,
            state,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn transcribe(
        proposal_digest: &Sha256Digest,
        upstream_digest: &str,
        campaign: &str,
        stage: &str,
        stage_class: StageClass,
        role: WorkerRole,
        effect_class: StageEffectClass,
        repositories: &[RepoPin],
        allowed_paths: &[String],
        expires_at: ClockReading,
        nonce: &str,
        issued_at: ClockReading,
    ) -> Sha256Digest {
        let mut t = Transcript::new(STANDING_TRANSCRIPT)
            .field("proposal_digest", proposal_digest.as_bytes())
            .text_field("upstream_digest", upstream_digest)
            .text_field("campaign", campaign)
            .text_field("stage", stage)
            .text_field("stage_class", stage_class.tag())
            .text_field("role", role.tag())
            .text_field("effect_class", effect_class.tag());
        for pin in repositories {
            t = t
                .text_field("repository.locator", pin.repository.as_str())
                .text_field("repository.commit", pin.commit.as_str())
                .text_field("repository.tree", &pin.tree);
        }
        for path in allowed_paths {
            t = t.text_field("allowed_path", path);
        }
        t.field("expires_at", &expires_at.0.to_be_bytes())
            .text_field("nonce", nonce)
            .field("issued_at", &issued_at.0.to_be_bytes())
            .finalize()
    }

    /// Recompute the digest from the record's bound fields; the store's read
    /// path compares it against the persisted digest.
    pub fn recompute_digest(&self) -> Sha256Digest {
        Self::transcribe(
            &self.proposal_digest,
            &self.upstream_digest,
            &self.campaign,
            &self.stage,
            self.stage_class,
            self.role,
            self.effect_class,
            &self.repositories,
            &self.allowed_paths,
            self.expires_at,
            &self.nonce,
            self.issued_at,
        )
    }

    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub fn proposal_digest(&self) -> Sha256Digest {
        self.proposal_digest
    }

    pub fn upstream_digest(&self) -> &str {
        &self.upstream_digest
    }

    pub fn campaign(&self) -> &str {
        &self.campaign
    }

    pub fn stage(&self) -> &str {
        &self.stage
    }

    pub fn stage_class(&self) -> StageClass {
        self.stage_class
    }

    pub fn role(&self) -> WorkerRole {
        self.role
    }

    pub fn effect_class(&self) -> StageEffectClass {
        self.effect_class
    }

    pub fn repositories(&self) -> &[RepoPin] {
        &self.repositories
    }

    pub fn allowed_paths(&self) -> &[String] {
        &self.allowed_paths
    }

    pub fn expires_at(&self) -> ClockReading {
        self.expires_at
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn issued_at(&self) -> ClockReading {
        self.issued_at
    }

    pub fn state(&self) -> &CampaignStandingState {
        &self.state
    }

    /// Whether `other` supersedes this standing: same campaign and stage,
    /// issued later. A superseded standing is historical; presenting it as
    /// current refuses at consumption.
    pub fn superseded_by(&self, other: &CampaignStageStanding) -> bool {
        self.campaign == other.campaign
            && self.stage == other.stage
            && other.issued_at > self.issued_at
            && other.digest != self.digest
    }

    /// The execution-context and window checks, shared by `consume` and
    /// `preflight`. Consumption state is deliberately not checked here: the
    /// durable store is the one-use authority.
    fn validate_execution(
        &self,
        context: &ExecutionContext,
        now: ClockReading,
    ) -> Result<(), CampaignRefusal> {
        if self.campaign != context.campaign {
            return Err(CampaignRefusal::CampaignMismatch);
        }
        if self.stage != context.stage {
            return Err(CampaignRefusal::StageMismatch);
        }
        if self.role != context.role {
            return Err(CampaignRefusal::RoleMismatch);
        }
        if self.proposal_digest != context.proposal_digest {
            return Err(CampaignRefusal::ProposalMismatch);
        }
        if now >= self.expires_at {
            return Err(CampaignRefusal::Expired);
        }
        Ok(())
    }

    /// Consume the one use against a presented execution context. Pure;
    /// refusals consume nothing. The returned consumption record must be
    /// durable before the stage's effect runs — burn-before-effect.
    pub fn consume(
        &self,
        context: &ExecutionContext,
        now: ClockReading,
    ) -> Result<(CampaignStageStanding, CampaignStageConsumption), CampaignRefusal> {
        self.validate_execution(context, now)?;
        if matches!(self.state, CampaignStandingState::Consumed { .. }) {
            return Err(CampaignRefusal::AlreadyConsumed);
        }
        let consumption = CampaignStageConsumption::record(self.digest, context, now);
        let consumed = CampaignStageStanding {
            state: CampaignStandingState::Consumed {
                consumption: consumption.digest,
            },
            ..self.clone()
        };
        Ok((consumed, consumption))
    }

    /// Validate the execution context and window and build the burn record,
    /// without checking consumption state. The service's atomic burn is the
    /// one durable winner; a burn that already exists is classified from the
    /// durable row, never from this value's in-memory state.
    pub fn preflight(
        &self,
        context: &ExecutionContext,
        now: ClockReading,
    ) -> Result<CampaignStageConsumption, CampaignRefusal> {
        self.validate_execution(context, now)?;
        Ok(CampaignStageConsumption::record(self.digest, context, now))
    }
}

/// The durable record of the one burn. Created before the effect runs;
/// `effect_completed` and `receipt` are filled in afterwards by the runtime
/// as the outcome becomes known, and are not part of the burn digest.
///
/// The receipt digest, once known, is the consuming effect/runtime receipt's
/// own digest (AG-NG or sidecar vocabulary), recorded verbatim — the same
/// dual-identity pattern as the upstream proposal digest.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CampaignStageConsumption {
    pub digest: Sha256Digest,
    pub standing: Sha256Digest,
    pub campaign: String,
    pub stage: String,
    pub role: WorkerRole,
    pub consumed_at: ClockReading,
    pub effect_completed: bool,
    pub receipt: Option<Sha256Digest>,
}

impl CampaignStageConsumption {
    fn record(standing: Sha256Digest, context: &ExecutionContext, now: ClockReading) -> Self {
        let digest = Transcript::new(CONSUMPTION_TRANSCRIPT)
            .field("standing", standing.as_bytes())
            .text_field("campaign", &context.campaign)
            .text_field("stage", &context.stage)
            .text_field("role", context.role.tag())
            .field("consumed_at", &now.0.to_be_bytes())
            .finalize();
        Self {
            digest,
            standing,
            campaign: context.campaign.clone(),
            stage: context.stage.clone(),
            role: context.role,
            consumed_at: now,
            effect_completed: false,
            receipt: None,
        }
    }
}

/// Crash-recovery classification of a stage execution: exactly these four
/// states, read back from the durable records.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsumptionState {
    /// No burn is recorded. The effect has not begun; it may proceed.
    EffectNotBegun,
    /// Standing consumed, effect outcome unresolved. Ambiguous: the effect
    /// may or may not have run. Re-execution refuses.
    ConsumedOutcomeUnresolved,
    /// Effect completed, receipt missing. Ambiguous: the outcome exists but
    /// is not receipted. Re-execution refuses.
    EffectCompletedReceiptMissing,
    /// Effect completed and receipted. Terminal: re-execution is a duplicate
    /// effect and refuses.
    EffectCompletedReceipted,
}

/// Classify from the durable consumption record alone.
pub fn classify(consumption: Option<&CampaignStageConsumption>) -> ConsumptionState {
    match consumption {
        None => ConsumptionState::EffectNotBegun,
        Some(c) if !c.effect_completed => ConsumptionState::ConsumedOutcomeUnresolved,
        Some(c) => match c.receipt {
            None => ConsumptionState::EffectCompletedReceiptMissing,
            Some(_) => ConsumptionState::EffectCompletedReceipted,
        },
    }
}

/// The re-execution law. Only `EffectNotBegun` may proceed; the ambiguous
/// states refuse rather than guess and re-run, and the receipted state
/// refuses a duplicate effect.
pub fn reexecution_decision(state: ConsumptionState) -> Result<(), CampaignRefusal> {
    match state {
        ConsumptionState::EffectNotBegun => Ok(()),
        ConsumptionState::ConsumedOutcomeUnresolved => Err(CampaignRefusal::OutcomeUnresolved),
        ConsumptionState::EffectCompletedReceiptMissing => Err(CampaignRefusal::ReceiptMissing),
        ConsumptionState::EffectCompletedReceipted => Err(CampaignRefusal::EffectAlreadyReceipted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::proposal::tests::{operator_proposal, COMMIT, TREE};
    use crate::campaign::StageClass;
    use crate::work_request::{CommitHash, RepositoryLocator};

    fn standing() -> CampaignStageStanding {
        CampaignStageStanding::issue(&operator_proposal(), ClockReading(2_000)).unwrap()
    }

    fn context(standing: &CampaignStageStanding) -> ExecutionContext {
        ExecutionContext {
            campaign: standing.campaign().to_string(),
            stage: standing.stage().to_string(),
            role: standing.role(),
            proposal_digest: standing.proposal_digest(),
        }
    }

    #[test]
    fn issuance_binds_the_exact_proposal() {
        let proposal = operator_proposal();
        let s = CampaignStageStanding::issue(&proposal, ClockReading(2_000)).unwrap();
        assert_eq!(s.proposal_digest(), proposal.digest);
        assert_eq!(s.upstream_digest(), proposal.upstream_digest);
        assert_eq!(s.recompute_digest(), s.digest());
        assert_eq!(s.state(), &CampaignStandingState::Available);
        // An already-expired proposal justifies nothing.
        assert_eq!(
            CampaignStageStanding::issue(&proposal, ClockReading(10_000)),
            Err(CampaignRefusal::Expired)
        );
    }

    #[test]
    fn consumption_burns_exactly_once_and_refuses_replay() {
        let s = standing();
        let ctx = context(&s);
        let (consumed, record) = s.consume(&ctx, ClockReading(3_000)).unwrap();
        assert_eq!(record.standing, s.digest());
        assert!(!record.effect_completed);
        assert_eq!(record.receipt, None);
        assert_eq!(
            consumed.state(),
            &CampaignStandingState::Consumed {
                consumption: record.digest
            }
        );
        assert_eq!(
            consumed.consume(&ctx, ClockReading(3_100)),
            Err(CampaignRefusal::AlreadyConsumed)
        );
        // The original value is untouched (pure).
        assert_eq!(s.state(), &CampaignStandingState::Available);
    }

    #[test]
    fn substitution_of_campaign_stage_role_or_proposal_refuses() {
        let s = standing();
        let ctx = context(&s);
        let mut bad = ctx.clone();
        bad.campaign = "campaign-2".into();
        assert_eq!(
            s.consume(&bad, ClockReading(3_000)),
            Err(CampaignRefusal::CampaignMismatch)
        );
        let mut bad = ctx.clone();
        bad.stage = "stage-b".into();
        assert_eq!(
            s.consume(&bad, ClockReading(3_000)),
            Err(CampaignRefusal::StageMismatch)
        );
        let mut bad = ctx.clone();
        bad.role = WorkerRole::Reviewer;
        assert_eq!(
            s.consume(&bad, ClockReading(3_000)),
            Err(CampaignRefusal::RoleMismatch)
        );
        // Source-basis substitution: an identical proposal but for one
        // repository commit has a different digest and refuses.
        let mut altered = operator_proposal();
        altered.repositories = vec![crate::campaign::proposal::RepoPin {
            repository: RepositoryLocator::new("/repo"),
            commit: CommitHash::new(TREE),
            tree: COMMIT.into(),
        }];
        let mut bad = ctx.clone();
        bad.proposal_digest = altered.recompute_digest();
        assert_eq!(
            s.consume(&bad, ClockReading(3_000)),
            Err(CampaignRefusal::ProposalMismatch)
        );
    }

    #[test]
    fn a_stale_standing_refuses_consumption() {
        let s = standing();
        let ctx = context(&s);
        assert_eq!(
            s.consume(&ctx, ClockReading(10_000)),
            Err(CampaignRefusal::Expired)
        );
    }

    #[test]
    fn the_four_state_recovery_law_refuses_everything_but_not_begun() {
        let s = standing();
        let ctx = context(&s);
        assert_eq!(classify(None), ConsumptionState::EffectNotBegun);
        assert_eq!(
            reexecution_decision(ConsumptionState::EffectNotBegun),
            Ok(())
        );

        let (_consumed, mut record) = s.consume(&ctx, ClockReading(3_000)).unwrap();
        assert_eq!(
            classify(Some(&record)),
            ConsumptionState::ConsumedOutcomeUnresolved
        );
        assert_eq!(
            reexecution_decision(classify(Some(&record))),
            Err(CampaignRefusal::OutcomeUnresolved)
        );

        record.effect_completed = true;
        assert_eq!(
            classify(Some(&record)),
            ConsumptionState::EffectCompletedReceiptMissing
        );
        assert_eq!(
            reexecution_decision(classify(Some(&record))),
            Err(CampaignRefusal::ReceiptMissing)
        );

        record.receipt = Some(Sha256Digest::of_bytes(b"receipt"));
        assert_eq!(
            classify(Some(&record)),
            ConsumptionState::EffectCompletedReceipted
        );
        assert_eq!(
            reexecution_decision(classify(Some(&record))),
            Err(CampaignRefusal::EffectAlreadyReceipted)
        );
    }

    #[test]
    fn a_standing_superseded_by_a_newer_one_for_the_same_stage_is_historical() {
        let proposal = operator_proposal();
        let first = CampaignStageStanding::issue(&proposal, ClockReading(2_000)).unwrap();
        // A re-proposal of the same stage carries a new nonce and yields a
        // new standing; the first is then historical.
        let mut later_proposal = operator_proposal();
        later_proposal.nonce = "nonce-2".into();
        later_proposal.digest = later_proposal.recompute_digest();
        let second = CampaignStageStanding::issue(&later_proposal, ClockReading(3_000)).unwrap();
        assert!(first.superseded_by(&second));
        assert!(!second.superseded_by(&first));
        assert!(!second.superseded_by(&second));
        assert_eq!(first.stage_class(), StageClass::OperatorStage);
    }
}
