//! The repair-authority bundle (P1): an exact, content-addressed projection
//! of the Docket records that authorize one repair stage's execution.
//!
//! A repair stage must not execute because a local file claims an
//! adjudication happened. This bundle is Docket's own read-only export: it
//! binds the repair standing, its proposal, the exact cited adjudication,
//! the rejected review receipt, and the consumed original stage authority
//! (resolved through the F1 consumed-standing chain), plus the repair
//! scope, window, nonce, and nonclaims. The typed digest is Docket's
//! content address over `gwr:campaign-repair-authority:v1`; the canonical
//! JSON file bytes (assembled by the gwr-local adapter) carry their own
//! SHA-256 alongside, per the cross-repository interop rule — consumers
//! recompute and equality-check, nobody re-canonicalizes.
//!
//! Verification re-derives this exact bundle from the durable store and
//! evaluates current law — standing and adjudication supersession, expiry,
//! chain exactness, consumption state — so a stale, substituted, corrupted,
//! or foreign artifact refuses.

use crate::campaign::adjudication::AdjudicationVerdict;
use crate::campaign::proposal::RepoPin;
use crate::campaign::{RepairScopeClass, StageClass, StageEffectClass, WorkerRole};
use crate::digest::{Sha256Digest, Transcript};
use crate::refusal::CampaignRefusal;
use crate::work_request::ClockReading;

/// The versioned transcript domain tag for repair-authority digests.
pub const REPAIR_AUTHORITY_TRANSCRIPT: &str = "gwr:campaign-repair-authority:v1";

/// The exact Docket authority for one repair stage's execution.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RepairAuthorityV1 {
    /// Docket's typed content address over the fields below (not over the
    /// file bytes; the file carries its own SHA-256 alongside).
    pub digest: Sha256Digest,
    pub campaign: String,
    /// The repair stage this bundle authorizes.
    pub repair_stage: String,
    pub role: WorkerRole,
    pub stage_class: StageClass,
    pub effect_class: StageEffectClass,
    /// The repair standing digest.
    pub standing: Sha256Digest,
    /// The repair proposal digest.
    pub proposal_digest: Sha256Digest,
    /// The repair standing's burn digest once consumed; absent before the
    /// burn. Exact state: a bundle exported before the burn does not equal
    /// one exported after it, and verification refuses the mismatch.
    pub consumption: Option<Sha256Digest>,
    /// The original (adjudicated, rejected) stage.
    pub original_stage: String,
    /// The proposal digest of the consumed original stage authority (the
    /// F1 chain anchor).
    pub original_proposal_digest: Sha256Digest,
    /// The consumed original standing digest.
    pub original_standing: Sha256Digest,
    /// The original stage's burn digest — the row carrying the rejected
    /// review receipt.
    pub original_consumption: Sha256Digest,
    pub rejected_review_receipt: Sha256Digest,
    /// The exact adjudication digest the repair cites.
    pub adjudication: Sha256Digest,
    pub adjudication_verdict: AdjudicationVerdict,
    pub finding_ids: Vec<String>,
    pub scope_class: RepairScopeClass,
    pub repositories: Vec<RepoPin>,
    pub allowed_paths: Vec<String>,
    pub expires_at: ClockReading,
    pub nonce: String,
    pub nonclaims: Vec<String>,
    /// Verifier-generation identity (adapter name and crate version).
    pub verifier: String,
}

impl RepairAuthorityV1 {
    /// Construct and content-address a bundle. A refusal creates nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        campaign: String,
        repair_stage: String,
        role: WorkerRole,
        stage_class: StageClass,
        effect_class: StageEffectClass,
        standing: Sha256Digest,
        proposal_digest: Sha256Digest,
        consumption: Option<Sha256Digest>,
        original_stage: String,
        original_proposal_digest: Sha256Digest,
        original_standing: Sha256Digest,
        original_consumption: Sha256Digest,
        rejected_review_receipt: Sha256Digest,
        adjudication: Sha256Digest,
        adjudication_verdict: AdjudicationVerdict,
        finding_ids: Vec<String>,
        scope_class: RepairScopeClass,
        repositories: Vec<RepoPin>,
        allowed_paths: Vec<String>,
        expires_at: ClockReading,
        nonce: String,
        nonclaims: Vec<String>,
        verifier: String,
    ) -> Result<Self, CampaignRefusal> {
        if !stage_class.is_repair() {
            return Err(CampaignRefusal::RepairAuthorityMismatch {
                field: "stage_class",
            });
        }
        if adjudication_verdict != AdjudicationVerdict::ExactRepair {
            return Err(CampaignRefusal::RepairNotAuthorized {
                verdict: adjudication_verdict.tag(),
            });
        }
        let digest = Self::transcribe(
            &campaign,
            &repair_stage,
            role,
            stage_class,
            effect_class,
            &standing,
            &proposal_digest,
            consumption.as_ref(),
            &original_stage,
            &original_proposal_digest,
            &original_standing,
            &original_consumption,
            &rejected_review_receipt,
            &adjudication,
            adjudication_verdict,
            &finding_ids,
            scope_class,
            &repositories,
            &allowed_paths,
            expires_at,
            &nonce,
            &nonclaims,
        );
        Ok(Self {
            digest,
            campaign,
            repair_stage,
            role,
            stage_class,
            effect_class,
            standing,
            proposal_digest,
            consumption,
            original_stage,
            original_proposal_digest,
            original_standing,
            original_consumption,
            rejected_review_receipt,
            adjudication,
            adjudication_verdict,
            finding_ids,
            scope_class,
            repositories,
            allowed_paths,
            expires_at,
            nonce,
            nonclaims,
            verifier,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn transcribe(
        campaign: &str,
        repair_stage: &str,
        role: WorkerRole,
        stage_class: StageClass,
        effect_class: StageEffectClass,
        standing: &Sha256Digest,
        proposal_digest: &Sha256Digest,
        consumption: Option<&Sha256Digest>,
        original_stage: &str,
        original_proposal_digest: &Sha256Digest,
        original_standing: &Sha256Digest,
        original_consumption: &Sha256Digest,
        rejected_review_receipt: &Sha256Digest,
        adjudication: &Sha256Digest,
        adjudication_verdict: AdjudicationVerdict,
        finding_ids: &[String],
        scope_class: RepairScopeClass,
        repositories: &[RepoPin],
        allowed_paths: &[String],
        expires_at: ClockReading,
        nonce: &str,
        nonclaims: &[String],
    ) -> Sha256Digest {
        let mut t = Transcript::new(REPAIR_AUTHORITY_TRANSCRIPT)
            .text_field("campaign", campaign)
            .text_field("repair_stage", repair_stage)
            .text_field("role", role.tag())
            .text_field("stage_class", stage_class.tag())
            .text_field("effect_class", effect_class.tag())
            .field("standing", standing.as_bytes())
            .field("proposal_digest", proposal_digest.as_bytes());
        t = match consumption {
            Some(c) => t
                .text_field("consumption", "present")
                .field("consumption.digest", c.as_bytes()),
            None => t.text_field("consumption", "absent"),
        };
        t = t
            .text_field("original_stage", original_stage)
            .field(
                "original_proposal_digest",
                original_proposal_digest.as_bytes(),
            )
            .field("original_standing", original_standing.as_bytes())
            .field("original_consumption", original_consumption.as_bytes())
            .field(
                "rejected_review_receipt",
                rejected_review_receipt.as_bytes(),
            )
            .field("adjudication", adjudication.as_bytes())
            .text_field("adjudication_verdict", adjudication_verdict.tag());
        for finding in finding_ids {
            t = t.text_field("finding_id", finding);
        }
        t = t.text_field("scope_class", scope_class.tag());
        for pin in repositories {
            t = t
                .text_field("repository.locator", pin.repository.as_str())
                .text_field("repository.commit", pin.commit.as_str())
                .text_field("repository.tree", &pin.tree);
        }
        for path in allowed_paths {
            t = t.text_field("allowed_path", path);
        }
        t = t
            .field("expires_at", &expires_at.0.to_be_bytes())
            .text_field("nonce", nonce);
        for nonclaim in nonclaims {
            t = t.text_field("nonclaim", nonclaim);
        }
        t.finalize()
    }

    /// Recompute the typed content address from the record's fields.
    pub fn recompute_digest(&self) -> Sha256Digest {
        Self::transcribe(
            &self.campaign,
            &self.repair_stage,
            self.role,
            self.stage_class,
            self.effect_class,
            &self.standing,
            &self.proposal_digest,
            self.consumption.as_ref(),
            &self.original_stage,
            &self.original_proposal_digest,
            &self.original_standing,
            &self.original_consumption,
            &self.rejected_review_receipt,
            &self.adjudication,
            self.adjudication_verdict,
            &self.finding_ids,
            self.scope_class,
            &self.repositories,
            &self.allowed_paths,
            self.expires_at,
            &self.nonce,
            &self.nonclaims,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::proposal::tests::{COMMIT, TREE};
    use crate::work_request::{CommitHash, RepositoryLocator};

    fn bundle() -> RepairAuthorityV1 {
        RepairAuthorityV1::issue(
            "campaign-1".into(),
            "stage-a-repair".into(),
            WorkerRole::Repair,
            StageClass::RecordsRepairStage,
            StageEffectClass::RecordsOnly,
            Sha256Digest::of_bytes(b"standing"),
            Sha256Digest::of_bytes(b"proposal"),
            None,
            "stage-a".into(),
            Sha256Digest::of_bytes(b"original-proposal"),
            Sha256Digest::of_bytes(b"original-standing"),
            Sha256Digest::of_bytes(b"original-consumption"),
            Sha256Digest::from_bytes([9; 32]),
            Sha256Digest::of_bytes(b"adjudication"),
            AdjudicationVerdict::ExactRepair,
            vec!["finding-1".into()],
            RepairScopeClass::RecordsOnly,
            vec![RepoPin {
                repository: RepositoryLocator::new("/repo"),
                commit: CommitHash::new(COMMIT),
                tree: TREE.into(),
            }],
            vec!["docs/x.md".into()],
            ClockReading(10_000),
            "nonce-1".into(),
            vec!["does-not-widen-scope".into()],
            "gwr-local 0.1.0".into(),
        )
        .unwrap()
    }

    #[test]
    fn a_bundle_is_content_addressed_and_deterministic() {
        let a = bundle();
        let b = bundle();
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.recompute_digest(), a.digest);
        // The verifier identity is file-level metadata, not part of the
        // typed address.
        assert_eq!(a.verifier, "gwr-local 0.1.0");
    }

    #[test]
    fn every_authority_field_changes_the_digest() {
        let base = bundle();
        let mut altered = bundle();
        altered.allowed_paths = vec!["docs/x.md".into(), "src/widened.rs".into()];
        assert_ne!(altered.recompute_digest(), base.digest);
        let mut altered = bundle();
        altered.consumption = Some(Sha256Digest::of_bytes(b"burn"));
        assert_ne!(altered.recompute_digest(), base.digest);
        let mut altered = bundle();
        altered.finding_ids = vec!["finding-2".into()];
        assert_ne!(altered.recompute_digest(), base.digest);
    }

    #[test]
    fn non_repair_classes_and_other_verdicts_issue_nothing() {
        let mut b = bundle();
        b.stage_class = StageClass::OperatorStage;
        assert!(matches!(
            RepairAuthorityV1::issue(
                b.campaign.clone(),
                b.repair_stage.clone(),
                b.role,
                b.stage_class,
                b.effect_class,
                b.standing,
                b.proposal_digest,
                b.consumption,
                b.original_stage.clone(),
                b.original_proposal_digest,
                b.original_standing,
                b.original_consumption,
                b.rejected_review_receipt,
                b.adjudication,
                b.adjudication_verdict,
                b.finding_ids.clone(),
                b.scope_class,
                b.repositories.clone(),
                b.allowed_paths.clone(),
                b.expires_at,
                b.nonce.clone(),
                b.nonclaims.clone(),
                b.verifier.clone(),
            ),
            Err(CampaignRefusal::RepairAuthorityMismatch {
                field: "stage_class"
            })
        ));
        assert!(matches!(
            RepairAuthorityV1::issue(
                "c".into(),
                "s".into(),
                WorkerRole::Repair,
                StageClass::RecordsRepairStage,
                StageEffectClass::RecordsOnly,
                Sha256Digest::of_bytes(b"s"),
                Sha256Digest::of_bytes(b"p"),
                None,
                "o".into(),
                Sha256Digest::of_bytes(b"op"),
                Sha256Digest::of_bytes(b"os"),
                Sha256Digest::of_bytes(b"oc"),
                Sha256Digest::from_bytes([9; 32]),
                Sha256Digest::of_bytes(b"a"),
                AdjudicationVerdict::Continue,
                vec!["f".into()],
                RepairScopeClass::RecordsOnly,
                vec![],
                vec![],
                ClockReading(1),
                "n".into(),
                vec![],
                "v".into(),
            ),
            Err(CampaignRefusal::RepairNotAuthorized { .. })
        ));
    }
}
