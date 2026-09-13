//! Campaign-stage standing (S-2): authority for one stage of an orchestrated
//! campaign, issued from an exact proposal, consumed exactly once before the
//! stage's effect runs.
//!
//! This is a distinct standing domain alongside the effect-standing domain
//! (`domain::standing`, act `git-ref-update:v1`). Neither domain mints,
//! consumes, validates, or substitutes for the other; there is deliberately
//! no conversion between their refusals. See
//! `docs/governed-runtime/campaign-stage-standing.md`.
//!
//! Cross-repository identity is by digest only. The upstream orchestration
//! office's proposal digest (domain `ag.campaign.stage-proposal/v1`) is
//! recorded verbatim as an opaque upstream identity — Docket never recomputes
//! it from a different canonicalization — alongside Docket's own proposal
//! digest over `gwr:campaign-stage-proposal:v1`.

pub mod adjudication;
pub mod authority;
pub mod proposal;
pub mod repair;
pub mod standing;

use crate::refusal::CampaignRefusal;

/// The stage classes this runtime can issue standing for. Every other class
/// in the campaign vocabulary is named in [`StageClass::admit_tag`] and
/// refused there — recognized, and declined.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StageClass {
    OperatorStage,
    ReviewerStage,
    RecordsRepairStage,
    ExistingSourceScopeRepairStage,
    FinalReviewStage,
}

impl StageClass {
    /// The one tag vocabulary, shared by the store encoding and every read
    /// surface.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::OperatorStage => "operator_stage",
            Self::ReviewerStage => "reviewer_stage",
            Self::RecordsRepairStage => "records_repair_stage",
            Self::ExistingSourceScopeRepairStage => "existing_source_scope_repair_stage",
            Self::FinalReviewStage => "final_review_stage",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "operator_stage" => Self::OperatorStage,
            "reviewer_stage" => Self::ReviewerStage,
            "records_repair_stage" => Self::RecordsRepairStage,
            "existing_source_scope_repair_stage" => Self::ExistingSourceScopeRepairStage,
            "final_review_stage" => Self::FinalReviewStage,
            _ => return None,
        })
    }

    /// Classes that exist in the campaign vocabulary but for which this
    /// runtime never issues standing. Requesting one is a typed refusal that
    /// names the class — not an unknown-class error, and never a silent drop
    /// to a weaker class.
    pub fn is_never_admitted(tag: &str) -> bool {
        matches!(
            tag,
            "new_source_scope"
                | "architecture"
                | "authority"
                | "basis"
                | "candidate"
                | "freeze"
                | "qualification"
                | "certificate"
                | "registry"
                | "deployment"
        )
    }

    /// Admission of a requested stage class: the admitted classes pass, the
    /// never-admitted classes refuse by name, anything else is unknown.
    pub fn admit_tag(tag: &str) -> Result<Self, CampaignRefusal> {
        if let Some(class) = Self::from_tag(tag) {
            return Ok(class);
        }
        if Self::is_never_admitted(tag) {
            return Err(CampaignRefusal::StageClassNeverAdmitted {
                class: tag.to_string(),
            });
        }
        Err(CampaignRefusal::UnknownStageClass {
            class: tag.to_string(),
        })
    }

    /// The one worker role a stage of this class may be issued to.
    pub fn required_role(&self) -> WorkerRole {
        match self {
            Self::OperatorStage => WorkerRole::Operator,
            Self::ReviewerStage | Self::FinalReviewStage => WorkerRole::Reviewer,
            Self::RecordsRepairStage | Self::ExistingSourceScopeRepairStage => WorkerRole::Repair,
        }
    }

    /// The one effect class a stage of this class may propose.
    pub fn required_effect_class(&self) -> StageEffectClass {
        match self {
            Self::OperatorStage => StageEffectClass::WorkspaceMutation,
            Self::ReviewerStage | Self::FinalReviewStage => StageEffectClass::ReviewReadOnly,
            Self::RecordsRepairStage => StageEffectClass::RecordsOnly,
            Self::ExistingSourceScopeRepairStage => StageEffectClass::ExistingSourceScope,
        }
    }

    /// Whether this class carries a repair basis and answers to a rejected
    /// review.
    pub fn is_repair(&self) -> bool {
        matches!(
            self,
            Self::RecordsRepairStage | Self::ExistingSourceScopeRepairStage
        )
    }

    /// Whether this class is a review class: reviewer role, read-only
    /// effects, isolated worktree.
    pub fn is_review(&self) -> bool {
        matches!(self, Self::ReviewerStage | Self::FinalReviewStage)
    }
}

/// Who a stage's standing is issued to. Standing is non-transferable across
/// roles: consumption presents a role and a mismatch refuses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WorkerRole {
    Operator,
    Reviewer,
    Repair,
}

impl WorkerRole {
    /// The one tag vocabulary, shared by the store encoding and every read
    /// surface.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Reviewer => "reviewer",
            Self::Repair => "repair",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "operator" => Self::Operator,
            "reviewer" => Self::Reviewer,
            "repair" => Self::Repair,
            _ => return None,
        })
    }
}

/// What a stage's standing permits. The class is fixed by the stage class;
/// a proposal asking for anything else is effect-class widening and refuses
/// at validation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StageEffectClass {
    /// Mutation inside the pinned repositories, within the allowed paths.
    WorkspaceMutation,
    /// Read and test effects only. Every mutation is forbidden.
    ReviewReadOnly,
    /// Mutation of records paths only, within the original stage authority's
    /// scope.
    RecordsOnly,
    /// Mutation within the original stage authority's existing source scope.
    ExistingSourceScope,
}

impl StageEffectClass {
    /// The one tag vocabulary, shared by the store encoding and every read
    /// surface.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::WorkspaceMutation => "workspace_mutation",
            Self::ReviewReadOnly => "review_read_only",
            Self::RecordsOnly => "records_only",
            Self::ExistingSourceScope => "existing_source_scope",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "workspace_mutation" => Self::WorkspaceMutation,
            "review_read_only" => Self::ReviewReadOnly,
            "records_only" => Self::RecordsOnly,
            "existing_source_scope" => Self::ExistingSourceScope,
            _ => return None,
        })
    }
}

/// The mutations reviewer standing never permits. Named so a refusal can say
/// exactly which operation was requested.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MutationOp {
    Commit,
    Push,
    Tag,
    Reset,
    Rebase,
    BranchMutation,
    RemoteMutation,
}

impl MutationOp {
    /// The one tag vocabulary, shared by the store encoding and every read
    /// surface.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Push => "push",
            Self::Tag => "tag",
            Self::Reset => "reset",
            Self::Rebase => "rebase",
            Self::BranchMutation => "branch_mutation",
            Self::RemoteMutation => "remote_mutation",
        }
    }
}

/// An effect a reviewer might request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReviewEffect {
    Read,
    Test,
    Mutation(MutationOp),
}

/// Reviewer standing permits read/test effects only. Every mutation —
/// commit, push, tag, reset, rebase, branch mutation, remote mutation —
/// refuses with the operation named.
pub fn reviewer_permits(effect: &ReviewEffect) -> Result<(), CampaignRefusal> {
    match effect {
        ReviewEffect::Read | ReviewEffect::Test => Ok(()),
        ReviewEffect::Mutation(op) => Err(CampaignRefusal::ReviewerMutationForbidden {
            op: op.tag().to_string(),
        }),
    }
}

/// Whether a stage's output must pass review before a successor stage can
/// cite it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReviewRequirement {
    NotRequired,
    Required,
}

impl ReviewRequirement {
    /// The one tag vocabulary, shared by the store encoding and every read
    /// surface.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Required => "required",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "not_required" => Self::NotRequired,
            "required" => Self::Required,
            _ => return None,
        })
    }
}

/// The two repair scope classes eligible for repair standing. Nothing else
/// is repairable through this domain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RepairScopeClass {
    RecordsOnly,
    ExistingSourceScope,
}

impl RepairScopeClass {
    /// The one tag vocabulary, shared by the store encoding and every read
    /// surface.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::RecordsOnly => "records_only",
            Self::ExistingSourceScope => "existing_source_scope",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "records_only" => Self::RecordsOnly,
            "existing_source_scope" => Self::ExistingSourceScope,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_never_admitted_classes_refuse_by_name() {
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
        assert_eq!(
            StageClass::admit_tag("surreptitious_stage"),
            Err(CampaignRefusal::UnknownStageClass {
                class: "surreptitious_stage".to_string()
            })
        );
    }

    #[test]
    fn each_admitted_class_fixes_one_role_and_one_effect_class() {
        for class in [
            StageClass::OperatorStage,
            StageClass::ReviewerStage,
            StageClass::RecordsRepairStage,
            StageClass::ExistingSourceScopeRepairStage,
            StageClass::FinalReviewStage,
        ] {
            assert_eq!(StageClass::from_tag(class.tag()), Some(class));
            // Round-trips through the vocabulary are exact.
            assert_eq!(
                WorkerRole::from_tag(class.required_role().tag()),
                Some(class.required_role())
            );
            assert_eq!(
                StageEffectClass::from_tag(class.required_effect_class().tag()),
                Some(class.required_effect_class())
            );
        }
    }

    #[test]
    fn reviewer_permits_read_and_test_and_refuses_every_mutation() {
        assert_eq!(reviewer_permits(&ReviewEffect::Read), Ok(()));
        assert_eq!(reviewer_permits(&ReviewEffect::Test), Ok(()));
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
                }),
                "{op:?} must be forbidden"
            );
        }
    }
}
