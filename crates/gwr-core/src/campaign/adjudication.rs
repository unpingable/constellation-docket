//! Adjudication of a campaign-stage review verdict, as a durable receipt.
//!
//! A verdict is continue, exact repair, or refuse. The receipt binds the
//! campaign, the stage, the exact review receipt adjudicated, the verdict,
//! the adjudicator, the findings, and the residual obligations. Residuals
//! are recorded and preserved; following the runtime's reconciliation law,
//! there is no discharge API and nothing here ever removes one.

use crate::digest::{Sha256Digest, Transcript};
use crate::refusal::CampaignRefusal;
use crate::work_request::ClockReading;

/// The versioned transcript domain tag for adjudication digests.
pub const ADJUDICATION_TRANSCRIPT: &str = "gwr:campaign-stage-adjudication:v1";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdjudicationVerdict {
    Continue,
    ExactRepair,
    Refuse,
}

impl AdjudicationVerdict {
    /// The one tag vocabulary, shared by the store encoding and every read
    /// surface.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::ExactRepair => "exact_repair",
            Self::Refuse => "refuse",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "continue" => Self::Continue,
            "exact_repair" => Self::ExactRepair,
            "refuse" => Self::Refuse,
            _ => return None,
        })
    }
}

/// One residual obligation left by an adjudication, in the adjudicator's
/// vocabulary. Preserved verbatim; never discharged by this runtime.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResidualStatement {
    pub kind: String,
    pub statement: String,
}

/// The durable adjudication receipt, content-addressed over the versioned
/// transcript.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AdjudicationReceipt {
    pub digest: Sha256Digest,
    pub campaign: String,
    pub stage: String,
    /// The exact review receipt this verdict adjudicates.
    pub review_receipt: Sha256Digest,
    pub verdict: AdjudicationVerdict,
    pub adjudicator: String,
    pub findings: Vec<String>,
    pub residuals: Vec<ResidualStatement>,
    pub adjudicated_at: ClockReading,
}

impl AdjudicationReceipt {
    /// Construct and content-address an adjudication. A refusal creates
    /// nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn adjudicate(
        campaign: String,
        stage: String,
        review_receipt: Sha256Digest,
        verdict: AdjudicationVerdict,
        adjudicator: String,
        findings: Vec<String>,
        residuals: Vec<ResidualStatement>,
        adjudicated_at: ClockReading,
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
        present("adjudicator", &adjudicator)?;
        for residual in &residuals {
            present("residual.kind", &residual.kind)?;
            present("residual.statement", &residual.statement)?;
        }
        let digest = Self::transcribe(
            &campaign,
            &stage,
            &review_receipt,
            verdict,
            &adjudicator,
            &findings,
            &residuals,
            adjudicated_at,
        );
        Ok(Self {
            digest,
            campaign,
            stage,
            review_receipt,
            verdict,
            adjudicator,
            findings,
            residuals,
            adjudicated_at,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn transcribe(
        campaign: &str,
        stage: &str,
        review_receipt: &Sha256Digest,
        verdict: AdjudicationVerdict,
        adjudicator: &str,
        findings: &[String],
        residuals: &[ResidualStatement],
        adjudicated_at: ClockReading,
    ) -> Sha256Digest {
        let mut t = Transcript::new(ADJUDICATION_TRANSCRIPT)
            .text_field("campaign", campaign)
            .text_field("stage", stage)
            .field("review_receipt", review_receipt.as_bytes())
            .text_field("verdict", verdict.tag())
            .text_field("adjudicator", adjudicator);
        for finding in findings {
            t = t.text_field("finding", finding);
        }
        for residual in residuals {
            t = t
                .text_field("residual.kind", &residual.kind)
                .text_field("residual.statement", &residual.statement);
        }
        t.field("adjudicated_at", &adjudicated_at.0.to_be_bytes())
            .finalize()
    }

    /// Recompute the digest from the record's fields; the store's read path
    /// compares it against the persisted digest.
    pub fn recompute_digest(&self) -> Sha256Digest {
        Self::transcribe(
            &self.campaign,
            &self.stage,
            &self.review_receipt,
            self.verdict,
            &self.adjudicator,
            &self.findings,
            &self.residuals,
            self.adjudicated_at,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjudication_is_content_addressed_and_verdicts_round_trip() {
        let receipt = AdjudicationReceipt::adjudicate(
            "campaign-1".into(),
            "stage-a".into(),
            Sha256Digest::of_bytes(b"review"),
            AdjudicationVerdict::ExactRepair,
            "adjudicator-1".into(),
            vec!["finding-1".into()],
            vec![ResidualStatement {
                kind: "human_review".into(),
                statement: "a human must re-review the repair".into(),
            }],
            ClockReading(5_000),
        )
        .unwrap();
        assert_eq!(receipt.recompute_digest(), receipt.digest);
        for verdict in [
            AdjudicationVerdict::Continue,
            AdjudicationVerdict::ExactRepair,
            AdjudicationVerdict::Refuse,
        ] {
            assert_eq!(AdjudicationVerdict::from_tag(verdict.tag()), Some(verdict));
        }
    }

    #[test]
    fn the_verdict_changes_the_digest() {
        let base = AdjudicationReceipt::adjudicate(
            "campaign-1".into(),
            "stage-a".into(),
            Sha256Digest::of_bytes(b"review"),
            AdjudicationVerdict::Refuse,
            "adjudicator-1".into(),
            vec![],
            vec![],
            ClockReading(5_000),
        )
        .unwrap();
        let other = AdjudicationReceipt::adjudicate(
            "campaign-1".into(),
            "stage-a".into(),
            Sha256Digest::of_bytes(b"review"),
            AdjudicationVerdict::Continue,
            "adjudicator-1".into(),
            vec![],
            vec![],
            ClockReading(5_000),
        )
        .unwrap();
        assert_ne!(base.digest, other.digest);
    }
}
