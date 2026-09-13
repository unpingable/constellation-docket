//! Exact, explicit encodings between core types and SQLite columns. No JSON,
//! no serde: every tag and list format here is part of the store's schema.

use gwr_core::campaign::adjudication::{AdjudicationVerdict, ResidualStatement};
use gwr_core::campaign::proposal::{RepairBasis, RepoPin, StageBasis};
use gwr_core::campaign::{
    RepairScopeClass, ReviewRequirement, StageClass, StageEffectClass, WorkerRole,
};
use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::StandingAct;
use gwr_core::ids::*;
use gwr_core::lifecycle::{
    AttemptState, DispatchRef, RatificationRef, RecoveryResolutionRef, RecoveryVerdict,
    ReservationRef,
};
use gwr_core::preparation::PreparationEnd;
use gwr_core::reconciliation::ObligationKind;
use gwr_core::recovery::FactSource;
use gwr_core::refusal::{DispatchRefusalGround, RelianceRefusal};
use gwr_core::work_request::{CommitHash, RefName, RepositoryLocator};
use gwr_runtime::ports::store::StoreError;

/// List encoding: length-prefixed, so `decode(encode(x)) == x` for every list
/// of strings the admitted domain can contain.
///
/// A delimiter-joined encoding was not injective: a path containing the
/// delimiter split into two on read, so an admitted attempt came back as a
/// different object with a different binding digest, and the digest handed to
/// the operator could never be ratified. Length prefixes cannot be forged by
/// content because the content is never scanned for structure.
///
/// Format: `<byte-len>:<utf8 bytes>` per element, concatenated.
pub fn join_list<S: AsRef<str>>(items: &[S]) -> String {
    let mut out = String::new();
    for item in items {
        let s = item.as_ref();
        out.push_str(&s.len().to_string());
        out.push(':');
        out.push_str(s);
    }
    out
}

pub fn split_list(encoded: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = encoded.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let Some(colon) = bytes[i..].iter().position(|b| *b == b':') else {
            break;
        };
        let colon = i + colon;
        let Ok(len) = std::str::from_utf8(&bytes[i..colon])
            .unwrap_or("")
            .parse::<usize>()
        else {
            break;
        };
        let start = colon + 1;
        let end = start + len;
        if end > bytes.len() {
            break;
        }
        out.push(String::from_utf8_lossy(&bytes[start..end]).into_owned());
        i = end;
    }
    out
}

pub fn id16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub trait FromBytes16 {
    fn from16(bytes: [u8; 16]) -> Self;
}

macro_rules! impl_from16 {
    ($($t:ty),+ $(,)?) => {
        $(impl FromBytes16 for $t {
            fn from16(bytes: [u8; 16]) -> Self {
                Self::from_bytes(bytes)
            }
        })+
    };
}

impl_from16!(
    WorkRequestId,
    PreparationRunId,
    CandidateArtifactId,
    RepositoryId,
    AttemptId,
    RatificationId,
    StandingGrantId,
    StandingUseId,
    ReservationId,
    ReservationUseId,
    DispatchId,
    ObservationId,
    RecoveryFactId,
    RecoveryResolutionId,
    ObligationId,
    ActorId,
);

/// A persisted column that failed to decode. Carried through `rusqlite`'s
/// row-mapping error channel and surfaced as `StoreError::Corrupt` — a typed
/// read error, never a panic and never a defaulted value.
#[derive(Debug)]
pub struct CorruptColumn(pub String);

impl std::fmt::Display for CorruptColumn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "corrupt persisted column: {}", self.0)
    }
}

impl std::error::Error for CorruptColumn {}

/// Wrap a decode failure so it can cross a `rusqlite` row-mapping closure.
pub fn sql_corrupt(e: CorruptColumn) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
}

fn hex_bytes(hex: &str, out: &mut [u8]) -> Result<(), CorruptColumn> {
    if hex.len() != out.len() * 2 || !hex.is_ascii() {
        return Err(CorruptColumn(format!("bad hex length or bytes: {hex:?}")));
    }
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)
            .map_err(|_| CorruptColumn(format!("bad hex bytes: {hex:?}")))?;
        out[i] = u8::from_str_radix(s, 16)
            .map_err(|_| CorruptColumn(format!("bad hex digit in {hex:?}")))?;
    }
    Ok(())
}

pub fn parse_id16<T: FromBytes16>(hex: &str) -> Result<T, CorruptColumn> {
    let mut bytes = [0u8; 16];
    hex_bytes(hex, &mut bytes)?;
    Ok(T::from16(bytes))
}

pub fn parse_digest(hex: &str) -> Result<Sha256Digest, CorruptColumn> {
    let mut bytes = [0u8; 32];
    hex_bytes(hex, &mut bytes)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

pub fn repo(s: &str) -> RepositoryLocator {
    RepositoryLocator::new(s)
}

pub fn refname(s: &str) -> RefName {
    RefName::new(s)
}

pub fn commit(s: &str) -> CommitHash {
    CommitHash::new(s)
}

pub fn end_tag(end: PreparationEnd) -> &'static str {
    match end {
        PreparationEnd::CandidateProduced => "candidate_produced",
        PreparationEnd::ProviderRefused => "provider_refused",
        PreparationEnd::ProviderFailed => "provider_failed",
        PreparationEnd::Cancelled => "cancelled",
        PreparationEnd::Expired => "expired",
    }
}

pub fn parse_end_tag(tag: &str) -> Result<PreparationEnd, StoreError> {
    Ok(match tag {
        "candidate_produced" => PreparationEnd::CandidateProduced,
        "provider_refused" => PreparationEnd::ProviderRefused,
        "provider_failed" => PreparationEnd::ProviderFailed,
        "cancelled" => PreparationEnd::Cancelled,
        "expired" => PreparationEnd::Expired,
        other => return Err(StoreError::Backend(format!("unknown end tag {other}"))),
    })
}

// Tag vocabularies live on the core types; the store encodes with them and
// refuses to decode anything outside them.

pub fn act_tag(act: StandingAct) -> &'static str {
    act.tag()
}

pub fn parse_act_tag(tag: &str) -> Result<StandingAct, CorruptColumn> {
    StandingAct::from_tag(tag).ok_or_else(|| CorruptColumn(format!("unknown act tag {tag:?}")))
}

pub fn ground_tag(ground: DispatchRefusalGround) -> &'static str {
    ground.tag()
}

pub fn parse_ground_tag(tag: &str) -> Result<DispatchRefusalGround, StoreError> {
    DispatchRefusalGround::from_tag(tag)
        .ok_or_else(|| StoreError::Corrupt(format!("unknown ground tag {tag:?}")))
}

pub fn verdict_tag(verdict: RecoveryVerdict) -> &'static str {
    verdict.tag()
}

pub fn parse_verdict_tag(tag: &str) -> Result<RecoveryVerdict, CorruptColumn> {
    Ok(match tag {
        "committed_via_recovery" => RecoveryVerdict::CommittedViaRecovery,
        "proven_not_committed" => RecoveryVerdict::ProvenNotCommitted,
        other => return Err(CorruptColumn(format!("unknown verdict tag {other:?}"))),
    })
}

pub fn obligation_tag(kind: ObligationKind) -> &'static str {
    kind.tag()
}

pub fn parse_obligation_tag(tag: &str) -> Result<ObligationKind, CorruptColumn> {
    ObligationKind::from_tag(tag)
        .ok_or_else(|| CorruptColumn(format!("unknown obligation tag {tag:?}")))
}

pub fn source_tags(source: &FactSource) -> (&'static str, Option<String>) {
    source.tags()
}

pub fn parse_source(kind: &str, detail: Option<String>) -> Result<FactSource, CorruptColumn> {
    FactSource::from_tags(kind, detail)
        .ok_or_else(|| CorruptColumn(format!("unknown fact source {kind:?}")))
}

pub fn reliance_refusal_tags(refusal: &RelianceRefusal) -> (&'static str, Option<String>) {
    refusal.tags()
}

pub fn parse_reliance_refusal(
    kind: &str,
    detail: Option<&str>,
) -> Result<RelianceRefusal, CorruptColumn> {
    RelianceRefusal::from_tags(kind, detail)
        .ok_or_else(|| CorruptColumn(format!("unknown reliance refusal kind {kind:?}")))
}

pub fn parse_claim_tag(tag: &str) -> Result<gwr_core::domain::evidence::Claim, CorruptColumn> {
    gwr_core::domain::evidence::Claim::from_tag(tag)
        .ok_or_else(|| CorruptColumn(format!("unknown claim tag {tag:?}")))
}

// Campaign-stage standing (S-2) encodings. Same rule as everywhere else in
// this store: explicit, length-prefixed, versioned by the core transcripts —
// no JSON, no delimiter scanning.

fn corrupt<T>(what: &str) -> Result<T, CorruptColumn> {
    Err(CorruptColumn(format!("corrupt campaign encoding: {what}")))
}

pub fn stage_class_tag(class: StageClass) -> &'static str {
    class.tag()
}

pub fn parse_stage_class(tag: &str) -> Result<StageClass, CorruptColumn> {
    StageClass::from_tag(tag)
        .ok_or_else(|| CorruptColumn(format!("unknown stage class tag {tag:?}")))
}

pub fn role_tag(role: WorkerRole) -> &'static str {
    role.tag()
}

pub fn parse_role(tag: &str) -> Result<WorkerRole, CorruptColumn> {
    WorkerRole::from_tag(tag).ok_or_else(|| CorruptColumn(format!("unknown role tag {tag:?}")))
}

pub fn stage_effect_tag(class: StageEffectClass) -> &'static str {
    class.tag()
}

pub fn parse_stage_effect(tag: &str) -> Result<StageEffectClass, CorruptColumn> {
    StageEffectClass::from_tag(tag)
        .ok_or_else(|| CorruptColumn(format!("unknown stage effect class tag {tag:?}")))
}

pub fn review_requirement_tag(req: ReviewRequirement) -> &'static str {
    req.tag()
}

pub fn parse_review_requirement(tag: &str) -> Result<ReviewRequirement, CorruptColumn> {
    ReviewRequirement::from_tag(tag)
        .ok_or_else(|| CorruptColumn(format!("unknown review requirement tag {tag:?}")))
}

pub fn adjudication_verdict_tag(verdict: AdjudicationVerdict) -> &'static str {
    verdict.tag()
}

pub fn parse_adjudication_verdict(tag: &str) -> Result<AdjudicationVerdict, CorruptColumn> {
    AdjudicationVerdict::from_tag(tag)
        .ok_or_else(|| CorruptColumn(format!("unknown adjudication verdict tag {tag:?}")))
}

/// Repository pins: a length-prefixed list of length-prefixed triples
/// (locator, commit, tree). Nesting is safe because the encoding never scans
/// content for structure.
pub fn encode_pins(pins: &[RepoPin]) -> String {
    let triples: Vec<String> = pins
        .iter()
        .map(|p| {
            join_list(&[
                p.repository.as_str().to_string(),
                p.commit.as_str().to_string(),
                p.tree.clone(),
            ])
        })
        .collect();
    join_list(&triples)
}

pub fn decode_pins(encoded: &str) -> Result<Vec<RepoPin>, CorruptColumn> {
    let mut out = Vec::new();
    for triple in split_list(encoded) {
        let fields = split_list(&triple);
        if fields.len() != 3 {
            return corrupt("repository pin is not a triple");
        }
        out.push(RepoPin {
            repository: repo(&fields[0]),
            commit: commit(&fields[1]),
            tree: fields[2].clone(),
        });
    }
    Ok(out)
}

/// A stage basis: kind tag plus its fields, one encoding per kind.
pub fn encode_basis(basis: &StageBasis) -> (String, String, String, Option<String>) {
    match basis {
        StageBasis::RootAuthorization { identity } => (
            "root_authorization".to_string(),
            identity.clone(),
            String::new(),
            None,
        ),
        StageBasis::PredecessorStage {
            stage,
            adjudication_digest,
        } => (
            "predecessor_stage".to_string(),
            String::new(),
            stage.clone(),
            Some(adjudication_digest.to_hex()),
        ),
    }
}

pub fn decode_basis(
    kind: &str,
    identity: &str,
    stage: &str,
    adjudication: Option<&str>,
) -> Result<StageBasis, CorruptColumn> {
    match kind {
        "root_authorization" => Ok(StageBasis::RootAuthorization {
            identity: identity.to_string(),
        }),
        "predecessor_stage" => Ok(StageBasis::PredecessorStage {
            stage: stage.to_string(),
            adjudication_digest: parse_digest(adjudication.ok_or_else(|| {
                CorruptColumn("predecessor basis lacks adjudication digest".into())
            })?)?,
        }),
        other => corrupt(&format!("unknown basis kind {other:?}")),
    }
}

/// A repair basis: one length-prefixed record of scalar fields and nested
/// length-prefixed lists.
pub fn encode_repair_basis(basis: &RepairBasis) -> String {
    join_list(&[
        basis.original_stage.clone(),
        basis.rejected_review_receipt.to_hex(),
        basis.scope_class.tag().to_string(),
        basis.review_requirement.tag().to_string(),
        join_list(&basis.finding_ids),
        join_list(&basis.nonclaims),
    ])
}

pub fn decode_repair_basis(encoded: &str) -> Result<RepairBasis, CorruptColumn> {
    let fields = split_list(encoded);
    if fields.len() != 6 {
        return corrupt("repair basis does not have six fields");
    }
    Ok(RepairBasis {
        original_stage: fields[0].clone(),
        rejected_review_receipt: parse_digest(&fields[1])?,
        scope_class: RepairScopeClass::from_tag(&fields[2])
            .ok_or_else(|| CorruptColumn(format!("unknown repair scope class {:?}", fields[2])))?,
        review_requirement: parse_review_requirement(&fields[3])?,
        finding_ids: split_list(&fields[4]),
        nonclaims: split_list(&fields[5]),
    })
}

/// Residual statements: a length-prefixed list of (kind, statement) pairs.
pub fn encode_residuals(residuals: &[ResidualStatement]) -> String {
    let pairs: Vec<String> = residuals
        .iter()
        .map(|r| join_list(&[r.kind.clone(), r.statement.clone()]))
        .collect();
    join_list(&pairs)
}

pub fn decode_residuals(encoded: &str) -> Result<Vec<ResidualStatement>, CorruptColumn> {
    let mut out = Vec::new();
    for pair in split_list(encoded) {
        let fields = split_list(&pair);
        if fields.len() != 2 {
            return corrupt("residual is not a (kind, statement) pair");
        }
        out.push(ResidualStatement {
            kind: fields[0].clone(),
            statement: fields[1].clone(),
        });
    }
    Ok(out)
}

/// Nullable projection columns, as read.
pub struct ProjCols {
    pub rat_id: Option<String>,
    pub rat_use: Option<String>,
    pub rsv_id: Option<String>,
    pub rsv_use: Option<String>,
    pub dispatch: Option<String>,
    pub ground: Option<String>,
    pub resolution: Option<String>,
}

/// Rebuild the typed state from projection columns. Missing columns for a tag
/// are a corruption error, never a defaulted state.
pub fn reconstruct_state(
    tag: &str,
    cols: &ProjCols,
    prepared_digest: &Sha256Digest,
) -> Result<AttemptState, StoreError> {
    let corrupt = || StoreError::Corrupt(format!("projection columns incomplete for {tag}"));
    let bad = |e: CorruptColumn| StoreError::Corrupt(e.to_string());
    let rat = || -> Result<RatificationRef, StoreError> {
        Ok(RatificationRef {
            ratification: parse_id16(cols.rat_id.as_ref().ok_or_else(corrupt)?).map_err(bad)?,
            prepared_attempt_digest: *prepared_digest,
            standing_use: parse_id16(cols.rat_use.as_ref().ok_or_else(corrupt)?).map_err(bad)?,
        })
    };
    let rsv = || -> Result<ReservationRef, StoreError> {
        Ok(ReservationRef {
            reservation: parse_id16(cols.rsv_id.as_ref().ok_or_else(corrupt)?).map_err(bad)?,
            reservation_use: parse_id16(cols.rsv_use.as_ref().ok_or_else(corrupt)?).map_err(bad)?,
        })
    };
    let dsp = || -> Result<DispatchRef, StoreError> {
        Ok(DispatchRef {
            dispatch: parse_id16(cols.dispatch.as_ref().ok_or_else(corrupt)?).map_err(bad)?,
        })
    };
    let res = || -> Result<RecoveryResolutionRef, StoreError> {
        Ok(RecoveryResolutionRef {
            resolution: parse_id16(cols.resolution.as_ref().ok_or_else(corrupt)?).map_err(bad)?,
        })
    };
    Ok(match tag {
        "prepared" => AttemptState::Prepared,
        "ratified" => AttemptState::Ratified {
            ratification: rat()?,
        },
        "reserved" => AttemptState::Reserved {
            ratification: rat()?,
            reservation: parse_id16(cols.rsv_id.as_ref().ok_or_else(corrupt)?).map_err(bad)?,
        },
        "dispatching" => AttemptState::Dispatching {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
        },
        "committed" => AttemptState::Committed {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
        },
        "dispatch_refused" => AttemptState::DispatchRefused {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
            ground: parse_ground_tag(cols.ground.as_ref().ok_or_else(corrupt)?)?,
        },
        "indeterminate" => AttemptState::Indeterminate {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
        },
        "committed_via_recovery" => AttemptState::CommittedViaRecovery {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
            resolution: res()?,
        },
        "proven_not_committed" => AttemptState::ProvenNotCommitted {
            ratification: rat()?,
            reservation: rsv()?,
            dispatch: dsp()?,
            resolution: res()?,
        },
        other => return Err(StoreError::Corrupt(format!("unknown state tag {other}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::{join_list, split_list};

    /// V5: `decode(encode(x)) = x` over the whole admitted domain, including
    /// the control characters a delimiter encoding silently re-partitioned.
    #[test]
    fn list_encoding_round_trips_arbitrary_content() {
        let cases: Vec<Vec<String>> = vec![
            vec![],
            vec!["".into()],
            vec!["src/lib.rs".into()],
            vec!["src/lib.rs".into(), "src/main.rs".into()],
            // The exact witness: the former delimiter, inside one element.
            vec!["src/lib.rs\u{1f}evil/pwned.rs".into()],
            vec!["a:b".into(), "12:not-a-length".into()],
            vec![
                "with space".into(),
                "with\nnewline".into(),
                "quote\"".into(),
            ],
            vec!["\u{1f}".into(), "".into(), "\u{1f}\u{1f}".into()],
            vec!["7:sneaky".into()],
            vec!["日本語のパス.rs".into()],
        ];
        for case in cases {
            let round = split_list(&join_list(&case));
            assert_eq!(round, case, "round trip failed for {case:?}");
        }
    }

    /// Distinct lists must not share an encoding — the injectivity the old
    /// delimiter format lacked.
    #[test]
    fn distinct_lists_encode_distinctly() {
        let one = vec!["src/lib.rs\u{1f}evil/pwned.rs".to_string()];
        let two = vec!["src/lib.rs".to_string(), "evil/pwned.rs".to_string()];
        assert_ne!(join_list(&one), join_list(&two));
        assert_eq!(split_list(&join_list(&one)), one);
        assert_eq!(split_list(&join_list(&two)), two);
    }
}
