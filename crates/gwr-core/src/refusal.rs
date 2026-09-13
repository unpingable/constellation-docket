//! Typed, domain-narrow refusals.
//!
//! Refusals are evidence, not errors: things the system correctly declined, each
//! carrying what was refused, on what ground, within which domain. There is
//! deliberately no shared refusal trait, no unified refusal type, and no
//! conversion between refusal domains — a unifier is the failure this design
//! exists to prevent.

use crate::ids::{AttemptId, DispatchId};

/// Refusals from validating standing at the ratification bridge.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StandingRefusal {
    IntegrityFailure,
    ScopeMismatch,
    Expired,
    AlreadyUsed,
}

/// Refusals from ratification itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RatificationRefusal {
    DigestMismatch,
    BasisMismatch,
    Standing(StandingRefusal),
}

/// Refusals from reservation and its use at dispatch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReservationRefusal {
    Conflict,
    Expired,
    AlreadyUsed,
    AttemptMismatch,
    RatificationMissing,
    /// A second dispatch identity was presented for the same attempt.
    DispatchIdentityConflict,
}

/// Grounds on which the broker definitively refused the effect. A refusal here
/// means the ref update did not occur — distinct forever from indeterminacy and
/// from a later `ProvenNotCommitted`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DispatchRefusalGround {
    BasisMoved,
    ForbiddenPath,
    InvalidPatch,
    EnvelopeMismatch,
}

impl DispatchRefusalGround {
    /// The one tag vocabulary, shared by the store encoding and every read
    /// surface.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::BasisMoved => "basis_moved",
            Self::ForbiddenPath => "forbidden_path",
            Self::InvalidPatch => "invalid_patch",
            Self::EnvelopeMismatch => "envelope_mismatch",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "basis_moved" => Self::BasisMoved,
            "forbidden_path" => Self::ForbiddenPath,
            "invalid_patch" => Self::InvalidPatch,
            "envelope_mismatch" => Self::EnvelopeMismatch,
            _ => return None,
        })
    }
}

/// Refusals from effect-class admission.
///
/// v0 admits exactly one effect class — the atomic Git target-ref transition,
/// `git-ref-update:v1`. A proposal that cannot be expressed in an admitted
/// class is refused **here**, at request creation and candidate admission:
/// before any standing is issued or consumed, before any reservation is
/// created, before any dispatch identity is minted, and before any provider
/// or Git invocation. A category error must not travel eleven steps to die as
/// a mechanical Git refusal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EffectClassRefusal {
    /// No admitted effect class can describe the proposal: the target is not a
    /// Git ref name, so this is not a Git ref effect, and there is no other
    /// kind. Carries the proposed target so the refusal says what was refused.
    UnsupportedEffectClass { target: String },
    /// Expressible only as a Git ref effect, but the basis is not an exact
    /// lowercase-hex commit hash, so no exact effect is being proposed.
    BasisNotACommitHash { basis: String },
    /// The Git class admits no effect over zero paths: an effect that may
    /// touch nothing is not an effect.
    NoAdmittedPaths,
    /// An admitted path is not repository-relative (absolute, traversing, or
    /// malformed), so the path authorization it names is not expressible.
    PathNotAdmissible { path: String },
}

/// Refusals of pure lifecycle transitions. An invalid transition mutates nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransitionRefusal {
    NotPrepared,
    NotRatified,
    NotReserved,
    NotDispatching,
    NotIndeterminate,
    AlreadyDispatched,
    AlreadyTerminal,
    /// The presented reservation use does not belong to the reserved claim.
    ReservationMismatch,
}

/// Refusals from the observation admission path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObservationRefusal {
    /// The observation ran against a different commit than the effect produced.
    ScopeMismatch,
    /// The named command did not exit successfully; it admits nothing.
    ObservationFailed,
}

/// Consumer-side reliance refusals. First-class: the absence of a bridge, or an
/// inadmissible claim, produces one of these — never a default, a fallback, or a
/// pass-through. A reliance refusal does not mutate its source record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RelianceRefusal {
    /// No bridge exists for this source, consumer, and claim.
    NoBridge,
    /// The bridge exists but not at the presented version. No fallback.
    BridgeVersionUnsupported {
        presented: u32,
    },
    /// The claim is one this bridge refuses to transport (e.g. correctness,
    /// completion, merge safety, discharge, closure).
    ClaimNotAdmissible,
    /// The source record is outside the scope the bridge transports.
    OutOfScope,
    Observation(ObservationRefusal),
}

impl RelianceRefusal {
    /// Stable kind tag plus optional detail, shared by the store encoding and
    /// every read surface.
    pub fn tags(&self) -> (&'static str, Option<String>) {
        match self {
            Self::NoBridge => ("no_bridge", None),
            Self::BridgeVersionUnsupported { presented } => {
                ("bridge_version_unsupported", Some(presented.to_string()))
            }
            Self::ClaimNotAdmissible => ("claim_not_admissible", None),
            Self::OutOfScope => ("out_of_scope", None),
            Self::Observation(ObservationRefusal::ScopeMismatch) => {
                ("observation_scope_mismatch", None)
            }
            Self::Observation(ObservationRefusal::ObservationFailed) => {
                ("observation_failed", None)
            }
        }
    }

    pub fn from_tags(kind: &str, detail: Option<&str>) -> Option<Self> {
        Some(match kind {
            "no_bridge" => Self::NoBridge,
            "bridge_version_unsupported" => Self::BridgeVersionUnsupported {
                presented: detail?.parse().ok()?,
            },
            "claim_not_admissible" => Self::ClaimNotAdmissible,
            "out_of_scope" => Self::OutOfScope,
            "observation_scope_mismatch" => Self::Observation(ObservationRefusal::ScopeMismatch),
            "observation_failed" => Self::Observation(ObservationRefusal::ObservationFailed),
            _ => return None,
        })
    }
}

/// Refusals from the campaign-stage standing domain.
///
/// Deliberately a separate domain from [`StandingRefusal`]: campaign-stage
/// standing is not effect standing, shares no scope type with it, and never
/// converts into it. Variants that name a class, path, or repository carry it
/// so the refusal says what was refused.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CampaignRefusal {
    /// The requested stage class is not in the campaign vocabulary at all.
    UnknownStageClass { class: String },
    /// The class is in the vocabulary, but this runtime never issues standing
    /// for it (new source scope, architecture, authority, basis, candidate,
    /// freeze, qualification, certificate, registry, deployment).
    StageClassNeverAdmitted { class: String },
    /// A required proposal field was empty.
    EmptyField { field: &'static str },
    /// A repository pin's commit or tree is not an exact lowercase-hex object
    /// id, so no exact basis is being proposed.
    RepositoryPinNotExact { repository: String },
    /// A stage over zero repositories governs nothing.
    NoRepositories,
    /// A stage over zero paths authorizes nothing.
    NoAdmittedPaths,
    /// A path is not repository-relative (absolute, traversing, or malformed).
    PathNotAdmissible { path: String },
    /// The proposal's worker role is not the role its stage class requires.
    RoleMismatch,
    /// The proposal's effect class is not the one its stage class permits.
    EffectClassNotPermitted {
        stage_class: &'static str,
        effect_class: &'static str,
    },
    /// Reviewer standing permits read/test effects only; the requested
    /// mutation is named in the refusal.
    ReviewerMutationForbidden { op: String },
    /// Reviewer standing binds an isolated worktree identity; none was given.
    ReviewerWorktreeMissing,
    /// A repair stage class was proposed without a repair basis.
    RepairBasisMissing,
    /// A non-repair stage class carried a repair basis.
    RepairBasisUnexpected,
    /// The repair scope class does not match the repair stage class.
    RepairScopeMismatch,
    /// A repair basis named no findings.
    RepairFindingsMissing,
    /// No adjudication authorizing exact repair covers this review receipt.
    RepairNotAuthorized { verdict: &'static str },
    /// The repair proposal's predecessor basis cites no recorded
    /// adjudication by exact digest — or cites no adjudication at all.
    /// Repair standing requires the exact adjudication identity; a stage
    /// name or a receipt alone does not identify one.
    RepairAdjudicationUnknown,
    /// More than one consumed standing for the original stage carries the
    /// adjudicated review receipt, so the original stage authority cannot be
    /// resolved exactly. Admission refuses rather than guess.
    RepairOriginalStandingAmbiguous,
    /// A repair-authority bundle disagrees with Docket's own re-derived
    /// authority in the named field — a substituted, corrupted, or foreign
    /// artifact.
    RepairAuthorityMismatch { field: &'static str },
    /// The repair basis cites a different review receipt than the one the
    /// authorizing adjudication records.
    RepairReviewReceiptMismatch,
    /// The repair basis's finding set differs from the adjudication's.
    RepairFindingsMismatch,
    /// The repair basis names a different original stage than the proposal
    /// whose authority it claims to repair within.
    RepairOriginalStageMismatch,
    /// A requested repair path lies outside the original stage authority's
    /// allowed paths.
    RepairPathOutsideOriginalScope { path: String },
    /// A requested repair repository lies outside the original stage
    /// authority's repositories.
    RepairRepositoryOutsideScope { repository: String },
    /// The execution context names a different campaign than the standing.
    CampaignMismatch,
    /// The execution context names a different stage than the standing.
    StageMismatch,
    /// The execution context presents a different proposal digest than the
    /// standing binds — including a proposal whose source basis was altered.
    ProposalMismatch,
    /// The standing's window has closed against the runtime clock.
    Expired,
    /// The standing's one consumption is already spent.
    AlreadyConsumed,
    /// A newer standing exists for this campaign and stage; this one is
    /// historical and cannot be presented as current.
    Superseded,
    /// Standing consumed, effect outcome unresolved: re-execution would guess.
    OutcomeUnresolved,
    /// Effect completed but no receipt is recorded: re-execution would guess.
    ReceiptMissing,
    /// The effect completed and is receipted; a second execution is a
    /// duplicate effect.
    EffectAlreadyReceipted,
    /// The review receipt an adjudication names was never recorded as the
    /// outcome of a consumed standing for that campaign and stage.
    AdjudicationSubjectUnknown,
}

/// Refusals from recovery resolution.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoveryRefusal {
    AttemptMismatch {
        fact_names: AttemptId,
        resolving: AttemptId,
    },
    DispatchMismatch {
        fact_names: DispatchId,
        resolving: DispatchId,
    },
    BindingIncomplete,
    /// The fact names a different repository than the attempt it would resolve.
    RepositoryMismatch,
    /// The fact names a different target ref than the attempt's effect.
    TargetRefMismatch,
    /// The fact names a different basis than the attempt was specified against.
    BasisMismatch,
    /// The fact's journal digest is not the one recorded when this dispatch
    /// became indeterminate: the journal it describes is not the journal the
    /// runtime saw.
    JournalDigestMismatch,
    /// The fact's observed ref disagrees with what the runtime read.
    ObservedRefMismatch,
    /// The fact's expected result disagrees with the digest-verified journal.
    ExpectedResultMismatch,
    /// The observed commit is already attributed to a different attempt, so it
    /// cannot settle this one.
    CommitAttributedElsewhere,
    StandingInsufficient,
    StandingExpired,
    StandingAlreadyUsed,
    /// Conflicting evidence resolves nothing; the attempt remains indeterminate.
    ConflictingEvidence,
}
