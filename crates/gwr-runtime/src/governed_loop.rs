//! Platform-neutral governed-loop protocol values and validation law.
//!
//! These values retain the exact external wire projections used by Docket.
//! Serialization is deterministic protocol law; this module performs no I/O,
//! persistence, executable measurement, or process invocation.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const SIGNED_ISSUANCE_SCHEMA_V1: &str = "ag.governed-loop.signed-issuance/v1";
/// Historical AG issuance without a not-after. Verifiable as retained
/// evidence; never accepted for a new custody or dispatch.
pub const AG_ISSUANCE_SCHEMA_V1: &str = "ag.governed-loop.issuance/v1";
/// AG issuance carrying a signed, exclusive `not_after_unix_ms`.
pub const AG_ISSUANCE_SCHEMA_V2: &str = "ag.governed-loop.issuance/v2";
/// Declared snapshot bound: a Docket execution-standing resolution may be
/// relied on for custody and for executor dispatch only while
/// `now - resolved_at <= MAX_STANDING_SNAPSHOT_AGE_MS` and `now < expires_at`.
/// It is re-checked, with a fresh clock reading, immediately before the
/// custody transaction and immediately before `execute`. It is also the
/// upper bound on how long a revocation committed after a resolution can be
/// ignored by a dispatch relying on that resolution.
pub const MAX_STANDING_SNAPSHOT_AGE_MS: u64 = 30_000;
pub const CUSTODY_SCHEMA_V1: &str = "ag.governed-loop.docket-custody/v1";
pub const SETTLEMENT_SCHEMA_V1: &str = "ag.governed-loop.docket-settlement/v1";
pub const STANDING_REQUEST_SCHEMA_V1: &str = "docket.governed-loop.execution-standing-request/v1";
pub const STANDING_RESOLUTION_SCHEMA_V1: &str =
    "docket.governed-loop.execution-standing-resolution/v1";
pub const INSPECTION_SCHEMA_V1: &str = "docket.governed-loop.inspection/v1";
/// Canonical external identity of the Docket-owned executor transport law.
pub const EXECUTOR_TRANSPORT_SCHEMA_V1: &str = "docket.governed-executor-transport/v1";
/// Canonical external identity of the closed, untagged V1 dispatch shape.
pub const EXECUTOR_DISPATCH_SCHEMA_V1: &str = "docket.governed-executor-dispatch/v1";
/// Canonical external identity of the closed, untagged V1 outcome shape.
pub const EXECUTOR_OUTCOME_SCHEMA_V1: &str = "docket.governed-executor-outcome/v1";
/// Exact V1 bound for an executor stdin dispatch or stdout outcome document.
pub const MAX_EXECUTOR_DOCUMENT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorBindingV1 {
    pub identity: String,
    pub program_digest: String,
    pub plan: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceKeyWireV1 {
    pub campaign: String,
    pub occurrence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgIssuanceWireV1 {
    pub schema: String,
    pub issuance: String,
    pub key: OccurrenceKeyWireV1,
    pub program: String,
    pub proposal: String,
    pub work_schema: String,
    pub work: String,
    pub subject: String,
    pub scope: String,
    pub observation: String,
    pub standing_resolution: String,
    pub mandate: String,
    pub spend: String,
    /// Exclusive not-after of the effect (v2 only; absent on historical v1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceAuthenticationWireV1 {
    pub issuer_principal: String,
    pub signer_key_id: String,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedIssuanceEnvelopeWireV1 {
    pub schema: String,
    pub body_b64: String,
    pub authentication: IssuanceAuthenticationWireV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedAgIssuerV1 {
    pub issuer_principal: String,
    pub key_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgIssuerTrustConfigV1 {
    pub issuers: Vec<TrustedAgIssuerV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStandingStatusV1 {
    Current,
    Absent,
    Revoked,
    Superseded,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStandingRequestV1 {
    pub schema: String,
    pub issuance: AgIssuanceWireV1,
    pub now_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStandingResolutionV1 {
    pub schema: String,
    pub resolution: String,
    pub currentness: String,
    pub execution_standing: String,
    pub issuance: String,
    pub campaign: String,
    pub occurrence: String,
    pub subject: String,
    pub scope: String,
    pub status: ExecutionStandingStatusV1,
    pub resolved_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketCustodyWireV1 {
    pub schema: String,
    pub issuance: String,
    pub ag_spend: String,
    pub execution_standing: String,
    pub standing_currentness: String,
    pub attempt: String,
    pub executor_marker: String,
    pub accepted_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorDispatchWireV1 {
    pub attempt: String,
    pub marker: String,
    pub work_schema: String,
    pub work: String,
    pub subject: String,
    pub scope: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorOutcomeClassWireV1 {
    Success,
    Failure,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorOutcomeWireV1 {
    pub attempt: String,
    pub marker: String,
    pub receipt: String,
    pub outcome: ExecutorOutcomeClassWireV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketSettlementWireV1 {
    pub schema: String,
    pub settlement: String,
    pub issuance: String,
    pub attempt: String,
    pub executor_marker: String,
    pub receipt: String,
    pub outcome: KnownOutcomeWireV1,
    pub settled_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownOutcomeWireV1 {
    Success,
    Failure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndeterminateOutcomeWireV1 {
    pub issuance: String,
    pub attempt: String,
    pub reconciliation: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DocketReconciliationWireV1 {
    NotAccepted,
    Accepted(DocketCustodyWireV1),
    Settled {
        custody: DocketCustodyWireV1,
        settlement: DocketSettlementWireV1,
    },
    Indeterminate {
        custody: DocketCustodyWireV1,
        indeterminate: IndeterminateOutcomeWireV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedRecordStatusV1 {
    Accepted,
    Settled,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRecordInspectionV1 {
    pub issuance: AgIssuanceWireV1,
    pub authentication: IssuanceAuthenticationWireV1,
    pub custody: DocketCustodyWireV1,
    pub status: GovernedRecordStatusV1,
    pub settlement: Option<DocketSettlementWireV1>,
    pub indeterminate: Option<IndeterminateOutcomeWireV1>,
    pub executor_binding: String,
    pub executor_program_digest: String,
    pub executor_plan: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedLoopInspectionV1 {
    pub schema: String,
    pub requested_issuance: String,
    pub record: Option<GovernedRecordInspectionV1>,
}

#[derive(Clone, Debug)]
pub struct CustodyRecordV1 {
    pub issuance: AgIssuanceWireV1,
    pub custody: DocketCustodyWireV1,
    pub signed_body_b64: String,
    pub authentication: IssuanceAuthenticationWireV1,
    pub executor_binding: String,
    pub executor_program_digest: String,
    pub executor_plan: String,
    pub status: String,
    pub settlement: Option<DocketSettlementWireV1>,
    pub indeterminate: Option<IndeterminateOutcomeWireV1>,
}

pub fn hash_domain(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ag-ng\0digest\0v1\0");
    hasher.update((domain.len() as u128).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((payload.len() as u128).to_be_bytes());
    hasher.update(payload);
    format!("sha256:{}", lower_hex(&hasher.finalize()))
}

pub fn digest_json_string(domain: &str, value: &str) -> Result<String, String> {
    let payload = serde_json::to_vec(value).map_err(|error| format!("digest-string:{error}"))?;
    Ok(hash_domain(domain, &payload))
}

pub fn require_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("governed-{label}-digest"));
    }
    Ok(())
}

/// Recomputes AG's canonical issuance identity under the carried schema.
/// This is the AG-owned law pinned by the mirrored conformance corpus
/// (`conformance/ag-governed-loop-issuance/v2-vectors.json`).
pub fn issuance_identity(issuance: &AgIssuanceWireV1) -> Result<String, String> {
    let domain = match (issuance.schema.as_str(), issuance.not_after_unix_ms) {
        (AG_ISSUANCE_SCHEMA_V1, None) => AG_ISSUANCE_SCHEMA_V1,
        (AG_ISSUANCE_SCHEMA_V2, Some(not_after)) if not_after > 0 => AG_ISSUANCE_SCHEMA_V2,
        (AG_ISSUANCE_SCHEMA_V1 | AG_ISSUANCE_SCHEMA_V2, _) => {
            return Err("governed-issuance-not-after-shape".to_owned())
        }
        _ => return Err("governed-issuance-schema".to_owned()),
    };
    let mut basis = serde_json::json!({
        "key": {
            "campaign": issuance.key.campaign,
            "occurrence": issuance.key.occurrence,
        },
        "mandate": issuance.mandate,
        "observation": issuance.observation,
        "program": issuance.program,
        "proposal": issuance.proposal,
        "scope": issuance.scope,
        "spend": issuance.spend,
        "standing_resolution": issuance.standing_resolution,
        "subject": issuance.subject,
        "work": issuance.work,
        "work_schema": issuance.work_schema,
    });
    if let Some(not_after) = issuance.not_after_unix_ms {
        basis["not_after_unix_ms"] = serde_json::json!(not_after);
    }
    let canonical =
        serde_json::to_vec(&basis).map_err(|error| format!("governed-issuance-basis:{error}"))?;
    Ok(hash_domain(domain, &canonical))
}

/// Verifies issuance shape and identity. This is verification of a record,
/// not permission to dispatch it: historical v1 issuances pass here so that
/// retained custody remains readable and reconcilable.
pub fn validate_issuance(issuance: &AgIssuanceWireV1) -> Result<(), String> {
    for (value, label) in [
        (&issuance.issuance, "issuance"),
        (&issuance.key.campaign, "campaign"),
        (&issuance.program, "program"),
        (&issuance.proposal, "proposal"),
        (&issuance.work, "work"),
        (&issuance.subject, "subject"),
        (&issuance.scope, "scope"),
        (&issuance.observation, "observation"),
        (&issuance.standing_resolution, "standing resolution"),
        (&issuance.mandate, "mandate"),
        (&issuance.spend, "AG spend"),
    ] {
        require_digest(value, label)?;
    }
    require_uuid(&issuance.key.occurrence)?;
    if issuance.work_schema.is_empty()
        || issuance.work_schema.len() > 128
        || !issuance.work_schema.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
    {
        return Err("governed-issuance-work-schema".to_owned());
    }
    if issuance_identity(issuance)? != issuance.issuance {
        return Err("governed-issuance-identity-mismatch".to_owned());
    }
    Ok(())
}

/// Effect-boundary rule for the AG warrant: the effect may begin only while
/// `now < not_after`. A historical issuance without not-after is never
/// dispatchable. The not-after is signed and identity-bound, so no retry,
/// re-delivery, or reconciliation can refresh it.
pub fn require_issuance_current(issuance: &AgIssuanceWireV1, now: u64) -> Result<(), String> {
    match (issuance.schema.as_str(), issuance.not_after_unix_ms) {
        (AG_ISSUANCE_SCHEMA_V2, Some(not_after)) if now < not_after => Ok(()),
        (AG_ISSUANCE_SCHEMA_V2, Some(_)) => Err("governed-issuance-expired".to_owned()),
        _ => Err("governed-issuance-not-after-absent".to_owned()),
    }
}

/// Declared snapshot bound for Docket's own execution standing (see
/// [`MAX_STANDING_SNAPSHOT_AGE_MS`]). Revocation after resolution stays
/// non-retroactive, but only inside this bounded interval.
pub fn require_standing_snapshot_within_bound(
    standing: &ExecutionStandingResolutionV1,
    now: u64,
) -> Result<(), String> {
    if standing.resolved_at_unix_ms > now {
        return Err("governed-execution-standing-not-current".to_owned());
    }
    if now - standing.resolved_at_unix_ms > MAX_STANDING_SNAPSHOT_AGE_MS {
        return Err("governed-execution-standing-snapshot-stale".to_owned());
    }
    if now >= standing.expires_at_unix_ms {
        return Err("governed-execution-standing-expired".to_owned());
    }
    Ok(())
}

/// Indeterminate evidence recorded when the issuance not-after passed after
/// custody but before `execute`; the executor was not invoked. Deterministic
/// so a reader can recognise the cause from retained state.
pub fn issuance_expired_before_execute_evidence(issuance: &AgIssuanceWireV1) -> String {
    hash_domain(
        "docket.governed-loop.issuance-expired-before-execute/v1",
        format!(
            "{}\0{}",
            issuance.issuance,
            issuance.not_after_unix_ms.unwrap_or_default()
        )
        .as_bytes(),
    )
}

/// Indeterminate evidence recorded when the declared standing snapshot bound
/// was exceeded after custody but before `execute`; the executor was not
/// invoked.
pub fn standing_snapshot_exceeded_before_execute_evidence(
    issuance: &AgIssuanceWireV1,
    custody: &DocketCustodyWireV1,
) -> String {
    hash_domain(
        "docket.governed-loop.standing-snapshot-exceeded-before-execute/v1",
        format!("{}\0{}", issuance.issuance, custody.standing_currentness).as_bytes(),
    )
}

pub fn validate_standing(
    issuance: &AgIssuanceWireV1,
    standing: &ExecutionStandingResolutionV1,
    now: u64,
) -> Result<(), String> {
    if standing.schema != STANDING_RESOLUTION_SCHEMA_V1 {
        return Err("governed-execution-standing-schema".to_owned());
    }
    for (value, label) in [
        (&standing.resolution, "Docket standing resolution"),
        (&standing.currentness, "Docket standing currentness"),
        (&standing.execution_standing, "Docket execution standing"),
    ] {
        require_digest(value, label)?;
    }
    if standing.issuance != issuance.issuance
        || standing.campaign != issuance.key.campaign
        || standing.occurrence != issuance.key.occurrence
        || standing.subject != issuance.subject
        || standing.scope != issuance.scope
    {
        return Err("governed-execution-standing-binding-mismatch".to_owned());
    }
    // Keep the owner's refusal classes distinct at the accept API.
    match standing.status {
        ExecutionStandingStatusV1::Current => {}
        ExecutionStandingStatusV1::Absent => {
            return Err("governed-execution-standing-absent".to_owned())
        }
        ExecutionStandingStatusV1::Revoked => {
            return Err("governed-execution-standing-revoked".to_owned())
        }
        ExecutionStandingStatusV1::Superseded => {
            return Err("governed-execution-standing-superseded".to_owned())
        }
        ExecutionStandingStatusV1::Expired => {
            return Err("governed-execution-standing-expired".to_owned())
        }
    }
    require_standing_snapshot_within_bound(standing, now)
}

pub fn require_same_envelope(
    existing: &CustodyRecordV1,
    envelope: &SignedIssuanceEnvelopeWireV1,
    issuance: &AgIssuanceWireV1,
) -> Result<(), String> {
    if existing.issuance != *issuance
        || existing.signed_body_b64 != envelope.body_b64
        || existing.authentication != envelope.authentication
    {
        return Err("governed-issuance-immutable-rebind".to_owned());
    }
    Ok(())
}

pub fn make_custody(
    issuance: &AgIssuanceWireV1,
    standing: &ExecutionStandingResolutionV1,
    now: u64,
) -> Result<DocketCustodyWireV1, String> {
    validate_standing(issuance, standing, now)?;
    let attempt = digest_json_string("ag.governed-loop.docket-attempt/v1", &issuance.issuance)?;
    let marker = hash_domain(
        "docket.governed-loop.executor-marker/v1",
        attempt.as_bytes(),
    );
    if standing.execution_standing.as_str() == issuance.spend.as_str()
        || standing.execution_standing.as_str() == attempt.as_str()
        || standing.execution_standing.as_str() == marker.as_str()
        || issuance.spend.as_str() == attempt.as_str()
        || issuance.spend.as_str() == marker.as_str()
        || attempt.as_str() == marker.as_str()
    {
        return Err("governed-instrument-substitution".to_owned());
    }
    Ok(DocketCustodyWireV1 {
        schema: CUSTODY_SCHEMA_V1.to_owned(),
        issuance: issuance.issuance.clone(),
        ag_spend: issuance.spend.clone(),
        execution_standing: standing.execution_standing.clone(),
        standing_currentness: standing.currentness.clone(),
        attempt,
        executor_marker: marker,
        accepted_at_unix_ms: now,
    })
}

pub fn executor_dispatch(
    issuance: &AgIssuanceWireV1,
    custody: &DocketCustodyWireV1,
) -> ExecutorDispatchWireV1 {
    ExecutorDispatchWireV1 {
        attempt: custody.attempt.clone(),
        marker: custody.executor_marker.clone(),
        work_schema: issuance.work_schema.clone(),
        work: issuance.work.clone(),
        subject: issuance.subject.clone(),
        scope: issuance.scope.clone(),
    }
}

fn require_uuid(value: &str) -> Result<(), String> {
    if value.len() != 36
        || value.bytes().enumerate().any(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte != b'-',
            _ => !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        })
    {
        return Err("governed-occurrence-uuid".to_owned());
    }
    Ok(())
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
