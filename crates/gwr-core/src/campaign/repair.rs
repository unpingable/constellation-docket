//! Repair standing admission: the subset decision lives here, in Docket.
//!
//! A repair proposal is admissible only against an adjudication that
//! authorizes exact repair of the cited rejected review receipt, with the
//! exact finding set, for the exact original stage — and only within the
//! original stage authority's repositories and paths. The sidecar never
//! makes this decision; it presents a proposal and Docket refuses or admits.
//!
//! Eligible scope classes are exactly `records_only` and
//! `existing_source_scope` (enforced structurally: only the two repair stage
//! classes can carry a repair basis, and each binds its scope class at
//! proposal validation). Everything else refuses.

use crate::campaign::adjudication::{AdjudicationReceipt, AdjudicationVerdict};
use crate::campaign::proposal::CampaignStageProposal;
use crate::refusal::CampaignRefusal;

/// Validate a repair proposal against the original stage's proposal and the
/// adjudication the repair cites. Pure: the service gathers the records;
/// this function decides.
pub fn validate_repair(
    repair_proposal: &CampaignStageProposal,
    original: &CampaignStageProposal,
    adjudication: &AdjudicationReceipt,
) -> Result<(), CampaignRefusal> {
    let basis = repair_proposal
        .repair
        .as_ref()
        .ok_or(CampaignRefusal::RepairBasisMissing)?;
    // The adjudication must be an exact-repair verdict on the original
    // stage of the same campaign.
    if adjudication.campaign != repair_proposal.campaign
        || adjudication.stage != basis.original_stage
        || original.stage != basis.original_stage
        || original.campaign != repair_proposal.campaign
    {
        return Err(CampaignRefusal::RepairOriginalStageMismatch);
    }
    if adjudication.verdict != AdjudicationVerdict::ExactRepair {
        return Err(CampaignRefusal::RepairNotAuthorized {
            verdict: adjudication.verdict.tag(),
        });
    }
    if adjudication.review_receipt != basis.rejected_review_receipt {
        return Err(CampaignRefusal::RepairReviewReceiptMismatch);
    }
    // Finding sets are compared as exact sets: a substituted, dropped, or
    // added finding refuses, regardless of order.
    let mut cited = basis.finding_ids.clone();
    let mut recorded = adjudication.findings.clone();
    cited.sort();
    recorded.sort();
    if cited != recorded {
        return Err(CampaignRefusal::RepairFindingsMismatch);
    }
    // The subset law: requested repositories and paths must lie within the
    // original stage authority's. Repair may narrow scope, never widen it.
    for pin in &repair_proposal.repositories {
        if !original
            .repositories
            .iter()
            .any(|o| o.repository == pin.repository)
        {
            return Err(CampaignRefusal::RepairRepositoryOutsideScope {
                repository: pin.repository.as_str().to_string(),
            });
        }
    }
    for path in &repair_proposal.allowed_paths {
        if !original.allowed_paths.contains(path) {
            return Err(CampaignRefusal::RepairPathOutsideOriginalScope { path: path.clone() });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::proposal::tests::{operator_proposal, COMMIT, TREE};
    use crate::campaign::proposal::{RepairBasis, RepoPin, StageBasis};
    use crate::campaign::{RepairScopeClass, ReviewRequirement, StageClass};
    use crate::digest::Sha256Digest;
    use crate::work_request::{ClockReading, CommitHash, RepositoryLocator};

    pub(crate) const REVIEW_RECEIPT: Sha256Digest = Sha256Digest::from_bytes([9; 32]);

    pub(crate) fn adjudication(
        verdict: AdjudicationVerdict,
        receipt: Sha256Digest,
        findings: &[&str],
    ) -> AdjudicationReceipt {
        AdjudicationReceipt::adjudicate(
            "campaign-1".into(),
            "stage-a".into(),
            receipt,
            verdict,
            "adjudicator-1".into(),
            findings.iter().map(|f| f.to_string()).collect(),
            vec![],
            ClockReading(5_000),
        )
        .unwrap()
    }

    pub(crate) fn repair_proposal(
        stage_class: StageClass,
        scope_class: RepairScopeClass,
        receipt: Sha256Digest,
        findings: &[&str],
        paths: &[&str],
        repositories: Vec<RepoPin>,
    ) -> CampaignStageProposal {
        CampaignStageProposal::propose(
            "upstream-repair-1".into(),
            "campaign-1".into(),
            "stage-a-repair".into(),
            stage_class,
            stage_class.required_role(),
            stage_class.required_effect_class(),
            StageBasis::PredecessorStage {
                stage: "stage-a".into(),
                adjudication_digest: Sha256Digest::from_bytes([8; 32]),
            },
            repositories,
            paths.iter().map(|p| p.to_string()).collect(),
            "evidence-contract-1".into(),
            "handoff-schema-1".into(),
            ClockReading(10_000),
            "nonce-repair-1".into(),
            String::new(),
            ReviewRequirement::Required,
            vec![],
            Some(RepairBasis {
                original_stage: "stage-a".into(),
                rejected_review_receipt: receipt,
                finding_ids: findings.iter().map(|f| f.to_string()).collect(),
                scope_class,
                nonclaims: vec!["does-not-widen-scope".into()],
                review_requirement: ReviewRequirement::Required,
            }),
            ClockReading(6_000),
        )
        .unwrap()
    }

    pub(crate) fn original_pin() -> RepoPin {
        RepoPin {
            repository: RepositoryLocator::new("/repo"),
            commit: CommitHash::new(COMMIT),
            tree: TREE.into(),
        }
    }

    fn records_repair(paths: &[&str]) -> CampaignStageProposal {
        repair_proposal(
            StageClass::RecordsRepairStage,
            RepairScopeClass::RecordsOnly,
            REVIEW_RECEIPT,
            &["finding-1"],
            paths,
            vec![original_pin()],
        )
    }

    #[test]
    fn a_records_only_repair_within_the_original_paths_is_admitted() {
        let adj = adjudication(
            AdjudicationVerdict::ExactRepair,
            REVIEW_RECEIPT,
            &["finding-1"],
        );
        assert_eq!(
            validate_repair(&records_repair(&["src/lib.rs"]), &operator_proposal(), &adj),
            Ok(())
        );
    }

    #[test]
    fn an_existing_source_scope_repair_within_the_allowlist_is_admitted() {
        let adj = adjudication(
            AdjudicationVerdict::ExactRepair,
            REVIEW_RECEIPT,
            &["finding-1"],
        );
        let proposal = repair_proposal(
            StageClass::ExistingSourceScopeRepairStage,
            RepairScopeClass::ExistingSourceScope,
            REVIEW_RECEIPT,
            &["finding-1"],
            &["src/lib.rs"],
            vec![original_pin()],
        );
        assert_eq!(
            validate_repair(&proposal, &operator_proposal(), &adj),
            Ok(())
        );
    }

    #[test]
    fn a_repair_path_outside_the_original_scope_refuses() {
        let adj = adjudication(
            AdjudicationVerdict::ExactRepair,
            REVIEW_RECEIPT,
            &["finding-1"],
        );
        assert_eq!(
            validate_repair(
                &records_repair(&["src/lib.rs", "src/widened.rs"]),
                &operator_proposal(),
                &adj
            ),
            Err(CampaignRefusal::RepairPathOutsideOriginalScope {
                path: "src/widened.rs".into()
            })
        );
    }

    #[test]
    fn a_repair_repository_outside_the_original_scope_refuses() {
        let adj = adjudication(
            AdjudicationVerdict::ExactRepair,
            REVIEW_RECEIPT,
            &["finding-1"],
        );
        let proposal = repair_proposal(
            StageClass::RecordsRepairStage,
            RepairScopeClass::RecordsOnly,
            REVIEW_RECEIPT,
            &["finding-1"],
            &["src/lib.rs"],
            vec![RepoPin {
                repository: RepositoryLocator::new("/other-repo"),
                commit: CommitHash::new(COMMIT),
                tree: TREE.into(),
            }],
        );
        assert_eq!(
            validate_repair(&proposal, &operator_proposal(), &adj),
            Err(CampaignRefusal::RepairRepositoryOutsideScope {
                repository: "/other-repo".into()
            })
        );
    }

    #[test]
    fn a_repair_citing_a_different_review_receipt_refuses() {
        let adj = adjudication(
            AdjudicationVerdict::ExactRepair,
            REVIEW_RECEIPT,
            &["finding-1"],
        );
        let proposal = repair_proposal(
            StageClass::RecordsRepairStage,
            RepairScopeClass::RecordsOnly,
            Sha256Digest::from_bytes([7; 32]),
            &["finding-1"],
            &["src/lib.rs"],
            vec![original_pin()],
        );
        assert_eq!(
            validate_repair(&proposal, &operator_proposal(), &adj),
            Err(CampaignRefusal::RepairReviewReceiptMismatch)
        );
    }

    #[test]
    fn a_repair_with_substituted_findings_refuses() {
        let adj = adjudication(
            AdjudicationVerdict::ExactRepair,
            REVIEW_RECEIPT,
            &["finding-1"],
        );
        let proposal = repair_proposal(
            StageClass::RecordsRepairStage,
            RepairScopeClass::RecordsOnly,
            REVIEW_RECEIPT,
            &["finding-2"],
            &["src/lib.rs"],
            vec![original_pin()],
        );
        assert_eq!(
            validate_repair(&proposal, &operator_proposal(), &adj),
            Err(CampaignRefusal::RepairFindingsMismatch)
        );
    }

    #[test]
    fn verdicts_other_than_exact_repair_authorize_no_repair() {
        for verdict in [AdjudicationVerdict::Continue, AdjudicationVerdict::Refuse] {
            let adj = adjudication(verdict, REVIEW_RECEIPT, &["finding-1"]);
            assert_eq!(
                validate_repair(&records_repair(&["src/lib.rs"]), &operator_proposal(), &adj),
                Err(CampaignRefusal::RepairNotAuthorized {
                    verdict: verdict.tag()
                })
            );
        }
    }
}
