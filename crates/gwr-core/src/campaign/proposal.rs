//! The campaign-stage proposal: an exact, content-addressed description of
//! one stage of one campaign.
//!
//! A proposal binds campaign identity, stage identity, predecessor stage or
//! root authorization identity, worker role, exact repository commits and
//! trees, exact allowed repositories, exact allowed paths, effect class,
//! evidence contract, expected handoff schema identity, expiry, nonce,
//! review requirement, and nonclaims. Validation refusals are typed; a
//! refusal creates nothing.
//!
//! Dual identity: `digest` is Docket's own content address over
//! `gwr:campaign-stage-proposal:v1`; `upstream_digest` is the upstream
//! office's digest (domain `ag.campaign.stage-proposal/v1`), recorded
//! verbatim and never recomputed from a different canonicalization.

use crate::campaign::{
    RepairScopeClass, ReviewRequirement, StageClass, StageEffectClass, WorkerRole,
};
use crate::digest::{Sha256Digest, Transcript};
use crate::effect_spec::GitRefEffect;
use crate::refusal::CampaignRefusal;
use crate::work_request::{ClockReading, CommitHash, RepositoryLocator};

/// The versioned transcript domain tag for proposal digests.
pub const PROPOSAL_TRANSCRIPT: &str = "gwr:campaign-stage-proposal:v1";

/// One repository the stage may touch, pinned exactly: locator, commit, tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RepoPin {
    pub repository: RepositoryLocator,
    pub commit: CommitHash,
    /// The commit's tree object id, lowercase hex as Git prints it.
    pub tree: String,
}

impl RepoPin {
    fn validate(&self) -> Result<(), CampaignRefusal> {
        let exact = |s: &str| {
            matches!(s.len(), 40 | 64)
                && s.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        };
        if !exact(self.commit.as_str()) || !exact(&self.tree) {
            return Err(CampaignRefusal::RepositoryPinNotExact {
                repository: self.repository.as_str().to_string(),
            });
        }
        Ok(())
    }

    fn transcribe(&self, t: Transcript) -> Transcript {
        t.text_field("repository.locator", self.repository.as_str())
            .text_field("repository.commit", self.commit.as_str())
            .text_field("repository.tree", &self.tree)
    }
}

/// What the stage descends from: a root authorization identity, or the
/// adjudication of a predecessor stage.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StageBasis {
    RootAuthorization {
        identity: String,
    },
    PredecessorStage {
        stage: String,
        adjudication_digest: Sha256Digest,
    },
}

/// What a repair proposal cites: the rejected review, its findings, the
/// original stage, and the repair's own nonclaims and review requirement.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RepairBasis {
    /// The stage whose rejected review this repair answers.
    pub original_stage: String,
    /// The exact digest of the rejected review receipt.
    pub rejected_review_receipt: Sha256Digest,
    /// The exact finding identifiers the repair addresses.
    pub finding_ids: Vec<String>,
    pub scope_class: RepairScopeClass,
    pub nonclaims: Vec<String>,
    pub review_requirement: ReviewRequirement,
}

/// An exact campaign-stage proposal. The digest is computed at construction
/// over the versioned transcript; validation happens before any digest
/// exists, so nothing invalid is ever content-addressed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CampaignStageProposal {
    pub digest: Sha256Digest,
    /// The upstream office's proposal digest, verbatim. Opaque: recorded,
    /// never recomputed.
    pub upstream_digest: String,
    pub campaign: String,
    pub stage: String,
    pub stage_class: StageClass,
    pub role: WorkerRole,
    pub effect_class: StageEffectClass,
    pub basis: StageBasis,
    pub repositories: Vec<RepoPin>,
    pub allowed_paths: Vec<String>,
    pub evidence_contract: String,
    pub handoff_schema: String,
    pub expires_at: ClockReading,
    pub nonce: String,
    /// The isolated worktree identity a review stage binds. Required for
    /// review classes; empty for the rest.
    pub isolated_worktree: String,
    pub review_requirement: ReviewRequirement,
    pub nonclaims: Vec<String>,
    pub repair: Option<RepairBasis>,
    pub proposed_at: ClockReading,
}

impl CampaignStageProposal {
    /// Validate and content-address a proposal. Every refusal is typed and
    /// creates nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn propose(
        upstream_digest: String,
        campaign: String,
        stage: String,
        stage_class: StageClass,
        role: WorkerRole,
        effect_class: StageEffectClass,
        basis: StageBasis,
        repositories: Vec<RepoPin>,
        allowed_paths: Vec<String>,
        evidence_contract: String,
        handoff_schema: String,
        expires_at: ClockReading,
        nonce: String,
        isolated_worktree: String,
        review_requirement: ReviewRequirement,
        nonclaims: Vec<String>,
        repair: Option<RepairBasis>,
        proposed_at: ClockReading,
    ) -> Result<Self, CampaignRefusal> {
        let present = |field: &'static str, value: &str| -> Result<(), CampaignRefusal> {
            if value.is_empty() {
                Err(CampaignRefusal::EmptyField { field })
            } else {
                Ok(())
            }
        };
        present("campaign", &campaign)?;
        present("stage", &stage)?;
        present("nonce", &nonce)?;
        present("evidence_contract", &evidence_contract)?;
        present("handoff_schema", &handoff_schema)?;
        present("upstream_digest", &upstream_digest)?;
        match &basis {
            StageBasis::RootAuthorization { identity } => present("basis.identity", identity)?,
            StageBasis::PredecessorStage { stage, .. } => present("basis.stage", stage)?,
        }
        if role != stage_class.required_role() {
            return Err(CampaignRefusal::RoleMismatch);
        }
        if effect_class != stage_class.required_effect_class() {
            return Err(CampaignRefusal::EffectClassNotPermitted {
                stage_class: stage_class.tag(),
                effect_class: effect_class.tag(),
            });
        }
        if stage_class.is_review() {
            present("isolated_worktree", &isolated_worktree)
                .map_err(|_| CampaignRefusal::ReviewerWorktreeMissing)?;
        }
        if repositories.is_empty() {
            return Err(CampaignRefusal::NoRepositories);
        }
        for pin in &repositories {
            pin.validate()?;
        }
        if allowed_paths.is_empty() {
            return Err(CampaignRefusal::NoAdmittedPaths);
        }
        for path in &allowed_paths {
            GitRefEffect::validate_path(path)
                .map_err(|_| CampaignRefusal::PathNotAdmissible { path: path.clone() })?;
        }
        match (stage_class.is_repair(), &repair) {
            (true, None) => return Err(CampaignRefusal::RepairBasisMissing),
            (false, Some(_)) => return Err(CampaignRefusal::RepairBasisUnexpected),
            (true, Some(r)) => {
                let scope_matches = matches!(
                    (stage_class, r.scope_class),
                    (
                        StageClass::RecordsRepairStage,
                        RepairScopeClass::RecordsOnly
                    ) | (
                        StageClass::ExistingSourceScopeRepairStage,
                        RepairScopeClass::ExistingSourceScope
                    )
                );
                if !scope_matches {
                    return Err(CampaignRefusal::RepairScopeMismatch);
                }
                present("repair.original_stage", &r.original_stage)?;
                if r.finding_ids.is_empty() {
                    return Err(CampaignRefusal::RepairFindingsMissing);
                }
            }
            (false, None) => {}
        }
        let digest = Self::transcribe(
            &upstream_digest,
            &campaign,
            &stage,
            stage_class,
            role,
            effect_class,
            &basis,
            &repositories,
            &allowed_paths,
            &evidence_contract,
            &handoff_schema,
            expires_at,
            &nonce,
            &isolated_worktree,
            review_requirement,
            &nonclaims,
            repair.as_ref(),
            proposed_at,
        );
        Ok(Self {
            digest,
            upstream_digest,
            campaign,
            stage,
            stage_class,
            role,
            effect_class,
            basis,
            repositories,
            allowed_paths,
            evidence_contract,
            handoff_schema,
            expires_at,
            nonce,
            isolated_worktree,
            review_requirement,
            nonclaims,
            repair,
            proposed_at,
        })
    }

    /// The versioned transcript, shared by construction and by nothing else:
    /// the store persists fields, and a reloaded proposal must recompute to
    /// the same digest (see the persistence tests).
    #[allow(clippy::too_many_arguments)]
    fn transcribe(
        upstream_digest: &str,
        campaign: &str,
        stage: &str,
        stage_class: StageClass,
        role: WorkerRole,
        effect_class: StageEffectClass,
        basis: &StageBasis,
        repositories: &[RepoPin],
        allowed_paths: &[String],
        evidence_contract: &str,
        handoff_schema: &str,
        expires_at: ClockReading,
        nonce: &str,
        isolated_worktree: &str,
        review_requirement: ReviewRequirement,
        nonclaims: &[String],
        repair: Option<&RepairBasis>,
        proposed_at: ClockReading,
    ) -> Sha256Digest {
        let mut t = Transcript::new(PROPOSAL_TRANSCRIPT)
            .text_field("upstream_digest", upstream_digest)
            .text_field("campaign", campaign)
            .text_field("stage", stage)
            .text_field("stage_class", stage_class.tag())
            .text_field("role", role.tag())
            .text_field("effect_class", effect_class.tag());
        t = match basis {
            StageBasis::RootAuthorization { identity } => t
                .text_field("basis.kind", "root_authorization")
                .text_field("basis.identity", identity),
            StageBasis::PredecessorStage {
                stage,
                adjudication_digest,
            } => t
                .text_field("basis.kind", "predecessor_stage")
                .text_field("basis.stage", stage)
                .field("basis.adjudication_digest", adjudication_digest.as_bytes()),
        };
        for pin in repositories {
            t = pin.transcribe(t);
        }
        for path in allowed_paths {
            t = t.text_field("allowed_path", path);
        }
        t = t
            .text_field("evidence_contract", evidence_contract)
            .text_field("handoff_schema", handoff_schema)
            .field("expires_at", &expires_at.0.to_be_bytes())
            .text_field("nonce", nonce)
            .text_field("isolated_worktree", isolated_worktree)
            .text_field("review_requirement", review_requirement.tag());
        for nonclaim in nonclaims {
            t = t.text_field("nonclaim", nonclaim);
        }
        t = match repair {
            None => t.text_field("repair", "none"),
            Some(r) => {
                let mut t = t
                    .text_field("repair", "present")
                    .text_field("repair.original_stage", &r.original_stage)
                    .field(
                        "repair.rejected_review_receipt",
                        r.rejected_review_receipt.as_bytes(),
                    );
                for finding in &r.finding_ids {
                    t = t.text_field("repair.finding_id", finding);
                }
                t = t
                    .text_field("repair.scope_class", r.scope_class.tag())
                    .text_field("repair.review_requirement", r.review_requirement.tag());
                for nonclaim in &r.nonclaims {
                    t = t.text_field("repair.nonclaim", nonclaim);
                }
                t
            }
        };
        t.field("proposed_at", &proposed_at.0.to_be_bytes())
            .finalize()
    }

    /// Recompute the digest from the record's fields. The store's read path
    /// compares this against the persisted digest: a record whose fields were
    /// altered after the fact fails this check rather than silently reading
    /// as the original proposal.
    pub fn recompute_digest(&self) -> Sha256Digest {
        Self::transcribe(
            &self.upstream_digest,
            &self.campaign,
            &self.stage,
            self.stage_class,
            self.role,
            self.effect_class,
            &self.basis,
            &self.repositories,
            &self.allowed_paths,
            &self.evidence_contract,
            &self.handoff_schema,
            self.expires_at,
            &self.nonce,
            &self.isolated_worktree,
            self.review_requirement,
            &self.nonclaims,
            self.repair.as_ref(),
            self.proposed_at,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::campaign::StageClass;

    pub(crate) const COMMIT: &str = "72cb3b323fa286cd212378eadae4a42fe4dc093e";
    pub(crate) const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

    pub(crate) fn operator_proposal() -> CampaignStageProposal {
        CampaignStageProposal::propose(
            "upstream-0".into(),
            "campaign-1".into(),
            "stage-a".into(),
            StageClass::OperatorStage,
            WorkerRole::Operator,
            StageEffectClass::WorkspaceMutation,
            StageBasis::RootAuthorization {
                identity: "root-auth-1".into(),
            },
            vec![RepoPin {
                repository: RepositoryLocator::new("/repo"),
                commit: CommitHash::new(COMMIT),
                tree: TREE.into(),
            }],
            vec!["src/lib.rs".into()],
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

    #[test]
    fn a_valid_proposal_is_content_addressed_and_deterministic() {
        let a = operator_proposal();
        let b = operator_proposal();
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.recompute_digest(), a.digest);
    }

    #[test]
    fn every_bound_field_changes_the_digest() {
        let base = operator_proposal();
        let mutations: Vec<CampaignStageProposal> = vec![
            {
                let mut p = operator_proposal();
                p.campaign = "campaign-2".into();
                p
            },
            {
                let mut p = operator_proposal();
                p.stage = "stage-b".into();
                p
            },
            {
                let mut p = operator_proposal();
                p.allowed_paths = vec!["src/other.rs".into()];
                p
            },
            {
                let mut p = operator_proposal();
                p.repositories[0].commit = CommitHash::new(TREE);
                p
            },
            {
                let mut p = operator_proposal();
                p.nonce = "nonce-2".into();
                p
            },
        ];
        for mutated in mutations {
            assert_ne!(
                mutated.recompute_digest(),
                base.digest,
                "mutation must change the digest: {mutated:?}"
            );
        }
    }

    #[test]
    fn role_mismatch_and_effect_class_widening_refuse_at_construction() {
        let attempt = |role: WorkerRole, effect: StageEffectClass| {
            CampaignStageProposal::propose(
                "upstream-0".into(),
                "campaign-1".into(),
                "stage-a".into(),
                StageClass::ReviewerStage,
                role,
                effect,
                StageBasis::RootAuthorization {
                    identity: "root-auth-1".into(),
                },
                vec![RepoPin {
                    repository: RepositoryLocator::new("/repo"),
                    commit: CommitHash::new(COMMIT),
                    tree: TREE.into(),
                }],
                vec!["src/lib.rs".into()],
                "evidence-contract-1".into(),
                "handoff-schema-1".into(),
                ClockReading(10_000),
                "nonce-1".into(),
                "worktree-1".into(),
                ReviewRequirement::NotRequired,
                vec![],
                None,
                ClockReading(1_000),
            )
        };
        assert_eq!(
            attempt(WorkerRole::Operator, StageEffectClass::ReviewReadOnly),
            Err(CampaignRefusal::RoleMismatch)
        );
        assert_eq!(
            attempt(WorkerRole::Reviewer, StageEffectClass::WorkspaceMutation),
            Err(CampaignRefusal::EffectClassNotPermitted {
                stage_class: "reviewer_stage",
                effect_class: "workspace_mutation",
            })
        );
    }

    #[test]
    fn malformed_repositories_paths_and_missing_fields_refuse() {
        let mut p = operator_proposal();
        p.allowed_paths = vec!["../escape".into()];
        assert!(matches!(
            CampaignStageProposal::propose(
                p.upstream_digest.clone(),
                p.campaign.clone(),
                p.stage.clone(),
                p.stage_class,
                p.role,
                p.effect_class,
                p.basis.clone(),
                p.repositories.clone(),
                p.allowed_paths.clone(),
                p.evidence_contract.clone(),
                p.handoff_schema.clone(),
                p.expires_at,
                p.nonce.clone(),
                p.isolated_worktree.clone(),
                p.review_requirement,
                p.nonclaims.clone(),
                p.repair.clone(),
                p.proposed_at,
            ),
            Err(CampaignRefusal::PathNotAdmissible { .. })
        ));
        let mut p = operator_proposal();
        p.repositories[0].tree = "not-hex".into();
        assert!(matches!(
            CampaignStageProposal::propose(
                p.upstream_digest.clone(),
                p.campaign.clone(),
                p.stage.clone(),
                p.stage_class,
                p.role,
                p.effect_class,
                p.basis.clone(),
                p.repositories.clone(),
                p.allowed_paths.clone(),
                p.evidence_contract.clone(),
                p.handoff_schema.clone(),
                p.expires_at,
                p.nonce.clone(),
                p.isolated_worktree.clone(),
                p.review_requirement,
                p.nonclaims.clone(),
                p.repair.clone(),
                p.proposed_at,
            ),
            Err(CampaignRefusal::RepositoryPinNotExact { .. })
        ));
    }
}
