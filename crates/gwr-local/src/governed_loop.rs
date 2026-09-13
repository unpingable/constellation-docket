//! Docket-owned custody for canonical AG governed-loop issuances.
//!
//! This is intentionally a separate authority domain from AG admission,
//! campaign-stage standing, and executor idempotency.  An authenticated AG
//! issuance is exact evidence of an already-spent AG decision authorization.
//! Docket freshly resolves and consumes its own execution standing, assigns
//! one canonical attempt, persists custody before invoking mechanics, and is
//! the sole producer of the settlement AG may consume.

use gwr_runtime::governed_loop::{
    digest_json_string, hash_domain, require_digest, validate_issuance,
};
pub use gwr_runtime::governed_loop::{
    AgIssuanceWireV1, AgIssuerTrustConfigV1, CustodyRecordV1, DocketCustodyWireV1,
    DocketReconciliationWireV1, DocketSettlementWireV1, ExecutionStandingRequestV1,
    ExecutionStandingResolutionV1, ExecutionStandingStatusV1, ExecutorBindingV1,
    ExecutorDispatchWireV1, ExecutorOutcomeClassWireV1, ExecutorOutcomeWireV1,
    GovernedLoopInspectionV1, GovernedRecordInspectionV1, GovernedRecordStatusV1,
    IndeterminateOutcomeWireV1, IssuanceAuthenticationWireV1, KnownOutcomeWireV1,
    OccurrenceKeyWireV1, SignedIssuanceEnvelopeWireV1, TrustedAgIssuerV1, AG_ISSUANCE_SCHEMA_V1,
    CUSTODY_SCHEMA_V1, EXECUTOR_DISPATCH_SCHEMA_V1, EXECUTOR_OUTCOME_SCHEMA_V1,
    EXECUTOR_TRANSPORT_SCHEMA_V1, INSPECTION_SCHEMA_V1, MAX_EXECUTOR_DOCUMENT_BYTES,
    SETTLEMENT_SCHEMA_V1, SIGNED_ISSUANCE_SCHEMA_V1, STANDING_REQUEST_SCHEMA_V1,
    STANDING_RESOLUTION_SCHEMA_V1,
};
use gwr_runtime::ports::governed_loop::{
    ExecutionStandingResolverV1, GovernedClockV1, GovernedCustodyStoreV1, GovernedExecutorV1,
};
use gwr_runtime::services::governed_loop as governed_service;
use ring::signature::{UnparsedPublicKey, ED25519};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const SIGNATURE_PREFIX_V1: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v1\0";
const MAX_EXECUTOR_PROGRAM_BYTES: u64 = 512 * 1024 * 1024;

/// Authenticates the exact AG issuance bytes against explicit Docket trust.
pub fn verify_signed_issuance(
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
) -> Result<(SignedIssuanceEnvelopeWireV1, AgIssuanceWireV1), String> {
    let envelope: SignedIssuanceEnvelopeWireV1 = strict_json(envelope_bytes, "issuance-envelope")?;
    if envelope.schema != SIGNED_ISSUANCE_SCHEMA_V1 {
        return Err("governed-issuance-envelope-schema".to_owned());
    }
    let trust: AgIssuerTrustConfigV1 = strict_json(trust_bytes, "issuer-trust")?;
    let trusted = trust
        .issuers
        .iter()
        .find(|candidate| {
            candidate.issuer_principal == envelope.authentication.issuer_principal
                && candidate.key_id == envelope.authentication.signer_key_id
        })
        .ok_or_else(|| "governed-issuance-untrusted-issuer".to_owned())?;
    if trusted.public_key != envelope.authentication.signer_public_key {
        return Err("governed-issuance-public-key-substitution".to_owned());
    }
    let body = b64_decode(&envelope.body_b64)?;
    let public_key = b64_decode(&trusted.public_key)?;
    let signature = b64_decode(&envelope.authentication.signature)?;
    let mut signed = Vec::with_capacity(SIGNATURE_PREFIX_V1.len() + body.len());
    signed.extend_from_slice(SIGNATURE_PREFIX_V1);
    signed.extend_from_slice(&body);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signed, &signature)
        .map_err(|_| "governed-issuance-signature-invalid".to_owned())?;
    let issuance: AgIssuanceWireV1 = strict_json(&body, "issuance-body")?;
    validate_issuance(&issuance)?;
    let canonical_value: serde_json::Value = strict_json(&body, "issuance-canonical-value")?;
    let canonical = serde_json::to_vec(&canonical_value)
        .map_err(|error| format!("issuance-canonical:{error}"))?;
    if canonical != body {
        return Err("governed-issuance-body-not-canonical".to_owned());
    }
    Ok((envelope, issuance))
}

/// Accepts one exact issuance, consumes fresh Docket standing transactionally,
/// persists custody, and then invokes exactly one executor delivery.
pub fn accept(
    database: &Path,
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
    standing_resolver: &Path,
    executor: &Path,
    executor_config: &Path,
) -> Result<DocketCustodyWireV1, String> {
    accept_inner(
        database,
        envelope_bytes,
        trust_bytes,
        standing_resolver,
        executor,
        executor_config,
        false,
    )
}

/// Local-standing deployment mode. Every new custody must have an exact
/// immutable local snapshot; there is no per-request fallback to external V1.
pub fn accept_local(
    database: &Path,
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
    standing_resolver: &Path,
    executor: &Path,
    executor_config: &Path,
) -> Result<DocketCustodyWireV1, String> {
    accept_inner(
        database,
        envelope_bytes,
        trust_bytes,
        standing_resolver,
        executor,
        executor_config,
        true,
    )
}

fn accept_inner(
    database: &Path,
    envelope_bytes: &[u8],
    trust_bytes: &[u8],
    standing_resolver: &Path,
    executor: &Path,
    executor_config: &Path,
    require_local_snapshot: bool,
) -> Result<DocketCustodyWireV1, String> {
    let (envelope, issuance) = verify_signed_issuance(envelope_bytes, trust_bytes)?;
    let mut store = SqliteGovernedCustodyStoreV1::open(database, require_local_snapshot)?;
    let effective_local_mode = store.require_local_snapshot;
    let mut resolver = LocalStandingResolverV1 {
        program: standing_resolver,
        deadline: effective_local_mode.then_some(std::time::Duration::from_secs(5)),
    };
    let mut executor = LocalGovernedExecutorV1 {
        program: executor,
        config: executor_config,
    };
    let mut clock = SystemGovernedClockV1;
    governed_service::accept(
        &mut store,
        &envelope,
        &issuance,
        &mut resolver,
        &mut executor,
        &mut clock,
    )
}

/// Reconciles one already-custodied issuance.  The executor command receives
/// the explicit `reconcile` operation; this path never calls `execute`.
pub fn reconcile(
    database: &Path,
    issuance: &str,
    expected_attempt: Option<&str>,
    executor: &Path,
    executor_config: &Path,
) -> Result<DocketReconciliationWireV1, String> {
    require_digest(issuance, "issuance")?;
    let mut store = SqliteGovernedCustodyStoreV1::open(database, false)?;
    let mut executor = LocalGovernedExecutorV1 {
        program: executor,
        config: executor_config,
    };
    let mut clock = SystemGovernedClockV1;
    governed_service::reconcile(
        &mut store,
        issuance,
        expected_attempt,
        &mut executor,
        &mut clock,
    )
}

/// Returns Docket's exact persisted governed-loop record for one issuance.
/// This opens the existing database read-only, invokes no resolver or
/// executor, and never creates or updates state.
pub fn inspect(database: &Path, issuance: &str) -> Result<GovernedLoopInspectionV1, String> {
    require_digest(issuance, "issuance")?;
    let mut store = SqliteGovernedCustodyStoreV1::open_read_only(database)?;
    governed_service::inspect(&mut store, issuance)
}

/// Reads a locally backed standing receipt only after the complete retained
/// custody and immutable grant/revision chain has validated.
pub fn inspect_local_snapshot(
    database: &Path,
    issuance: &str,
) -> Result<Option<crate::local_execution_standing::LocalCustodySnapshotV1>, String> {
    let inspected = inspect(database, issuance)?;
    if inspected.record.is_none() {
        return Ok(None);
    }
    crate::local_execution_standing::inspect_snapshot(database, issuance)
}

struct LocalStandingResolverV1<'a> {
    program: &'a Path,
    deadline: Option<std::time::Duration>,
}

impl ExecutionStandingResolverV1 for LocalStandingResolverV1<'_> {
    fn resolve(
        &mut self,
        request: &ExecutionStandingRequestV1,
    ) -> Result<ExecutionStandingResolutionV1, String> {
        invoke_json_with_deadline(self.program, &[], request, 1_048_576, self.deadline)
    }
}

struct LocalGovernedExecutorV1<'a> {
    program: &'a Path,
    config: &'a Path,
}

impl GovernedExecutorV1 for LocalGovernedExecutorV1<'_> {
    fn resolve_binding(&mut self, expected_plan: &str) -> Result<ExecutorBindingV1, String> {
        resolve_executor_binding(self.program, self.config, expected_plan)
    }

    fn require_binding(&mut self, expected: &ExecutorBindingV1) -> Result<(), String> {
        require_executor_binding(self.program, self.config, expected)
    }

    fn execute(
        &mut self,
        dispatch: &ExecutorDispatchWireV1,
    ) -> Result<ExecutorOutcomeWireV1, String> {
        self.invoke("execute", dispatch)
    }

    fn reconcile(
        &mut self,
        dispatch: &ExecutorDispatchWireV1,
    ) -> Result<ExecutorOutcomeWireV1, String> {
        self.invoke("reconcile", dispatch)
    }
}

impl LocalGovernedExecutorV1<'_> {
    fn invoke(
        &self,
        operation: &str,
        dispatch: &ExecutorDispatchWireV1,
    ) -> Result<ExecutorOutcomeWireV1, String> {
        let config = self
            .config
            .to_str()
            .ok_or_else(|| "executor-config-path-not-utf8".to_owned())?;
        invoke_json(
            self.program,
            &[operation, config],
            dispatch,
            MAX_EXECUTOR_DOCUMENT_BYTES,
        )
    }
}

struct SystemGovernedClockV1;

impl GovernedClockV1 for SystemGovernedClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, String> {
        now_unix_ms()
    }
}

struct SqliteGovernedCustodyStoreV1 {
    connection: Connection,
    require_local_snapshot: bool,
}

impl SqliteGovernedCustodyStoreV1 {
    fn open(database: &Path, require_local_snapshot: bool) -> Result<Self, String> {
        let connection =
            Connection::open(database).map_err(|error| format!("governed-custody-open:{error}"))?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|error| format!("governed-custody-foreign-keys:{error}"))?;
        connection
            .pragma_update(None, "busy_timeout", 5_000_u32)
            .map_err(|error| format!("governed-custody-busy-timeout:{error}"))?;
        crate::local_execution_standing::migrate(&connection)?;
        let enrolled: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM local_execution_standing_deployment
                 WHERE singleton=1 AND mode='snapshot_currentness' AND max_lifetime_ms=300000)",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("local-standing-enrollment-read:{error}"))?;
        Ok(Self {
            connection,
            require_local_snapshot: require_local_snapshot || enrolled,
        })
    }

    fn open_read_only(database: &Path) -> Result<Self, String> {
        let connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| format!("governed-custody-read-open:{error}"))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| format!("governed-custody-read-timeout:{error}"))?;
        Ok(Self {
            connection,
            require_local_snapshot: false,
        })
    }
}

impl GovernedCustodyStoreV1 for SqliteGovernedCustodyStoreV1 {
    fn insert_custody(
        &mut self,
        envelope: &SignedIssuanceEnvelopeWireV1,
        issuance: &AgIssuanceWireV1,
        standing: &ExecutionStandingResolutionV1,
        custody: &DocketCustodyWireV1,
        executor_binding: &ExecutorBindingV1,
    ) -> Result<(), String> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| format!("governed-custody-transaction:{error}"))?;
        let enrolled_now:bool=transaction.query_row("SELECT EXISTS(SELECT 1 FROM local_execution_standing_deployment WHERE singleton=1 AND mode='snapshot_currentness' AND max_lifetime_ms=300000)",[],|row|row.get(0)).map_err(|error|format!("local-standing-enrollment-read:{error}"))?;
        let require_local_snapshot = self.require_local_snapshot || enrolled_now;
        let mut statement = transaction
            .prepare(
                "SELECT r.revision,r.status,g.issued_at,g.expires_at,r.revision_identity,g.operator,r.changed_at
             FROM local_execution_standing_grant g
             JOIN local_execution_standing_revision r USING(execution_standing)
             WHERE g.execution_standing=?1
               AND g.campaign=?2 AND g.occurrence=?3 AND g.program=?4
               AND g.work_schema=?5 AND g.work=?6 AND g.subject=?7 AND g.scope=?8
             ORDER BY r.revision LIMIT 4097",
            )
            .map_err(|error| format!("governed-local-standing-snapshot-prepare:{error}"))?;
        let mapped = statement
            .query_map(
                params![
                    standing.execution_standing,
                    issuance.key.campaign,
                    issuance.key.occurrence,
                    issuance.program,
                    issuance.work_schema,
                    issuance.work,
                    issuance.subject,
                    issuance.scope
                ],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, u64>(6)?,
                    ))
                },
            )
            .map_err(|error| format!("governed-local-standing-snapshot-query:{error}"))?;
        let mut count = 0usize;
        let mut local_snapshot = None;
        for candidate in mapped {
            count += 1;
            if count > 4096 {
                return Err("governed-local-standing-revision-limit".to_owned());
            }
            let candidate = candidate
                .map_err(|error| format!("governed-local-standing-snapshot-row:{error}"))?;
            let input = crate::local_execution_standing::GrantInput {
                operator: &candidate.5,
                campaign: &issuance.key.campaign,
                occurrence: &issuance.key.occurrence,
                program: &issuance.program,
                work_schema: &issuance.work_schema,
                work: &issuance.work,
                subject: &issuance.subject,
                scope: &issuance.scope,
                issued_at_unix_ms: candidate.2,
                expires_at_unix_ms: candidate.3,
            };
            if crate::local_execution_standing::grant_identity(&input)?
                != standing.execution_standing
            {
                return Err("governed-local-standing-grant-identity".to_owned());
            }
            let expected_revision = hash_domain(
                "docket.governed-loop.local-standing-revision/v1",
                format!(
                    "{}\0{}\0{}\0{}",
                    standing.execution_standing, candidate.0, candidate.1, candidate.6
                )
                .as_bytes(),
            );
            if expected_revision != candidate.4 {
                return Err("governed-local-standing-revision-identity".to_owned());
            }
            let expected = hash_domain(
                "docket.governed-loop.local-standing-currentness/v1",
                format!(
                    "{}\0{}\0{}\0{}\0{}\0{}",
                    standing.execution_standing,
                    candidate.0,
                    candidate.4,
                    candidate.1,
                    standing.resolved_at_unix_ms,
                    candidate.3
                )
                .as_bytes(),
            );
            if expected == standing.currentness {
                if local_snapshot.is_some() {
                    return Err("governed-local-standing-snapshot-ambiguous".to_owned());
                }
                local_snapshot = Some(candidate);
            }
        }
        drop(statement);
        if require_local_snapshot && local_snapshot.is_none() {
            return Err("governed-local-standing-snapshot-required".to_owned());
        }
        if let Some((
            revision,
            status,
            issued_at,
            expires_at,
            revision_identity,
            _operator,
            _changed_at,
        )) = &local_snapshot
        {
            if status != "current"
                || *issued_at > standing.resolved_at_unix_ms
                || *expires_at != standing.expires_at_unix_ms
            {
                return Err("governed-local-standing-snapshot-mismatch".to_owned());
            }
            let expected_currentness = hash_domain(
                "docket.governed-loop.local-standing-currentness/v1",
                format!(
                    "{}\0{}\0{}\0{}\0{}\0{}",
                    standing.execution_standing,
                    revision,
                    revision_identity,
                    status,
                    standing.resolved_at_unix_ms,
                    expires_at
                )
                .as_bytes(),
            );
            if expected_currentness != standing.currentness {
                return Err("governed-local-standing-currentness-mismatch".to_owned());
            }
            let expected = hash_domain(
                "docket.governed-loop.local-standing-resolution/v1",
                format!(
                    "{}\0{}\0{}\0{}\0{}",
                    standing.execution_standing,
                    revision,
                    standing.currentness,
                    issuance.issuance,
                    standing.resolved_at_unix_ms
                )
                .as_bytes(),
            );
            if expected != standing.resolution {
                return Err("governed-local-standing-resolution-mismatch".to_owned());
            }
        }
        transaction
            .execute(
                "INSERT INTO governed_execution_standing_use
                 (execution_standing,issuance,standing_resolution,standing_currentness,consumed_at)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    standing.execution_standing,
                    issuance.issuance,
                    standing.resolution,
                    standing.currentness,
                    u64_to_i64(custody.accepted_at_unix_ms)?
                ],
            )
            .map_err(|error| format!("governed-execution-standing-consume:{error}"))?;
        transaction
            .execute(
                "INSERT INTO governed_loop_attempt
                 (issuance,signed_body_b64,issuer_principal,signer_key_id,signer_public_key,
                  signature,campaign,occurrence,program,proposal,work_schema,work,subject,scope,
                  observation,ag_standing_resolution,mandate,ag_spend,execution_standing,
                  standing_currentness,attempt,executor_marker,executor_binding,
                  executor_program_digest,executor_plan,accepted_at,status,local_standing_mode)
                 VALUES
                 (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,
                  ?19,?20,?21,?22,?23,?24,?25,?26,'accepted',?27)",
                params![
                    issuance.issuance,
                    envelope.body_b64,
                    envelope.authentication.issuer_principal,
                    envelope.authentication.signer_key_id,
                    envelope.authentication.signer_public_key,
                    envelope.authentication.signature,
                    issuance.key.campaign,
                    issuance.key.occurrence,
                    issuance.program,
                    issuance.proposal,
                    issuance.work_schema,
                    issuance.work,
                    issuance.subject,
                    issuance.scope,
                    issuance.observation,
                    issuance.standing_resolution,
                    issuance.mandate,
                    issuance.spend,
                    custody.execution_standing,
                    custody.standing_currentness,
                    custody.attempt,
                    custody.executor_marker,
                    executor_binding.identity,
                    executor_binding.program_digest,
                    executor_binding.plan,
                    u64_to_i64(custody.accepted_at_unix_ms)?,
                    if require_local_snapshot { 1 } else { 0 }
                ],
            )
            .map_err(|error| format!("governed-attempt-insert:{error}"))?;
        if let Some((
            revision,
            status,
            _issued_at,
            expires_at,
            _revision_identity,
            _operator,
            _changed_at,
        )) = local_snapshot
        {
            transaction.execute(
                "INSERT INTO governed_local_standing_snapshot
                 (issuance,execution_standing,revision,status,resolved_at,expires_at,currentness,resolution)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![issuance.issuance,standing.execution_standing,revision,status,
                    u64_to_i64(standing.resolved_at_unix_ms)?,expires_at,
                    standing.currentness,standing.resolution],
            ).map_err(|error|format!("governed-local-standing-snapshot-insert:{error}"))?;
        }
        transaction
            .commit()
            .map_err(|error| format!("governed-custody-commit:{error}"))
    }

    fn get(&mut self, issuance: &str) -> Result<Option<CustodyRecordV1>, String> {
        let record = self
            .connection
            .query_row(
                "SELECT signed_body_b64,issuer_principal,signer_key_id,signer_public_key,signature,
                        campaign,occurrence,program,proposal,work_schema,work,subject,scope,
                        observation,ag_standing_resolution,mandate,ag_spend,execution_standing,
                        standing_currentness,attempt,executor_marker,executor_binding,
                        executor_program_digest,executor_plan,accepted_at,status,
                        settlement,receipt,outcome,settled_at,reconciliation,indeterminate_evidence
                 FROM governed_loop_attempt WHERE issuance=?1",
                [issuance],
                |row| {
                    let accepted_at = read_u64(row.get::<_, i64>(24)?, 24)?;
                    let status: String = row.get(25)?;
                    let settlement_ref: Option<String> = row.get(26)?;
                    let receipt: Option<String> = row.get(27)?;
                    let outcome: Option<String> = row.get(28)?;
                    let settled_at: Option<i64> = row.get(29)?;
                    let reconciliation: Option<String> = row.get(30)?;
                    let evidence: Option<String> = row.get(31)?;
                    let issuance_record = AgIssuanceWireV1 {
                        schema: AG_ISSUANCE_SCHEMA_V1.to_owned(),
                        issuance: issuance.to_owned(),
                        key: OccurrenceKeyWireV1 {
                            campaign: row.get(5)?,
                            occurrence: row.get(6)?,
                        },
                        program: row.get(7)?,
                        proposal: row.get(8)?,
                        work_schema: row.get(9)?,
                        work: row.get(10)?,
                        subject: row.get(11)?,
                        scope: row.get(12)?,
                        observation: row.get(13)?,
                        standing_resolution: row.get(14)?,
                        mandate: row.get(15)?,
                        spend: row.get(16)?,
                    };
                    let custody = DocketCustodyWireV1 {
                        schema: CUSTODY_SCHEMA_V1.to_owned(),
                        issuance: issuance.to_owned(),
                        ag_spend: issuance_record.spend.clone(),
                        execution_standing: row.get(17)?,
                        standing_currentness: row.get(18)?,
                        attempt: row.get(19)?,
                        executor_marker: row.get(20)?,
                        accepted_at_unix_ms: accepted_at,
                    };
                    let known = match (&settlement_ref, &receipt, &outcome, settled_at) {
                        (Some(settlement), Some(receipt), Some(outcome), Some(at)) => {
                            Some(DocketSettlementWireV1 {
                                schema: SETTLEMENT_SCHEMA_V1.to_owned(),
                                settlement: settlement.clone(),
                                issuance: issuance.to_owned(),
                                attempt: custody.attempt.clone(),
                                executor_marker: custody.executor_marker.clone(),
                                receipt: receipt.clone(),
                                outcome: match outcome.as_str() {
                                    "success" => KnownOutcomeWireV1::Success,
                                    "failure" => KnownOutcomeWireV1::Failure,
                                    _ => return Err(sql_decode("governed outcome")),
                                },
                                settled_at_unix_ms: read_u64(at, 29)?,
                            })
                        }
                        (None, None, None, None) => None,
                        _ => return Err(sql_decode("partial governed settlement")),
                    };
                    let indeterminate = match (reconciliation, evidence) {
                        (Some(reconciliation), Some(evidence)) => {
                            Some(IndeterminateOutcomeWireV1 {
                                issuance: issuance.to_owned(),
                                attempt: custody.attempt.clone(),
                                reconciliation,
                                evidence,
                            })
                        }
                        (None, None) => None,
                        _ => return Err(sql_decode("partial governed indeterminate")),
                    };
                    Ok(CustodyRecordV1 {
                        issuance: issuance_record,
                        custody,
                        signed_body_b64: row.get(0)?,
                        authentication: IssuanceAuthenticationWireV1 {
                            issuer_principal: row.get(1)?,
                            signer_key_id: row.get(2)?,
                            signer_public_key: row.get(3)?,
                            signature: row.get(4)?,
                        },
                        executor_binding: row.get(21)?,
                        executor_program_digest: row.get(22)?,
                        executor_plan: row.get(23)?,
                        status,
                        settlement: known,
                        indeterminate,
                    })
                },
            )
            .optional()
            .map_err(|error| format!("governed-custody-read:{error}"))?;
        record
            .map(|record| {
                validate_stored_record(&record)?;
                validate_local_snapshot(&self.connection, &record)?;
                Ok(record)
            })
            .transpose()
    }

    fn record_known_outcome(
        &mut self,
        issuance: &str,
        custody: &DocketCustodyWireV1,
        receipt: &str,
        outcome: KnownOutcomeWireV1,
        at: u64,
    ) -> Result<(), String> {
        require_digest(receipt, "executor receipt")?;
        let known = match outcome {
            KnownOutcomeWireV1::Success => "success",
            KnownOutcomeWireV1::Failure => "failure",
        };
        let settlement = hash_domain(
            "docket.governed-loop.settlement/v1",
            format!("{issuance}:{}:{receipt}:{known}", custody.attempt).as_bytes(),
        );
        let changed = self
            .connection
            .execute(
                "UPDATE governed_loop_attempt
                         SET status='settled',settlement=?1,receipt=?2,outcome=?3,settled_at=?4
                         WHERE issuance=?5 AND attempt=?6 AND executor_marker=?7
                           AND status IN ('accepted','indeterminate')",
                params![
                    settlement,
                    receipt,
                    known,
                    u64_to_i64(at)?,
                    issuance,
                    custody.attempt,
                    custody.executor_marker
                ],
            )
            .map_err(|error| format!("governed-settlement-write:{error}"))?;
        if changed == 0 {
            let existing = self
                .get(issuance)?
                .ok_or_else(|| "governed-settlement-attempt-missing".to_owned())?;
            if existing
                .settlement
                .as_ref()
                .is_some_and(|value| value.receipt == receipt && value.outcome == outcome)
            {
                return Ok(());
            }
            return Err("governed-settlement-substitution".to_owned());
        }
        Ok(())
    }

    fn record_indeterminate(
        &mut self,
        issuance: &str,
        custody: &DocketCustodyWireV1,
        evidence: &str,
    ) -> Result<(), String> {
        require_digest(evidence, "indeterminate evidence")?;
        let reconciliation = hash_domain(
            "docket.governed-loop.reconciliation/v1",
            format!("{issuance}:{}:{evidence}", custody.attempt).as_bytes(),
        );
        let changed = self
            .connection
            .execute(
                "UPDATE governed_loop_attempt
                 SET status='indeterminate',reconciliation=?1,indeterminate_evidence=?2
                 WHERE issuance=?3 AND attempt=?4 AND executor_marker=?5
                   AND status='accepted'",
                params![
                    reconciliation,
                    evidence,
                    issuance,
                    custody.attempt,
                    custody.executor_marker
                ],
            )
            .map_err(|error| format!("governed-indeterminate-write:{error}"))?;
        if changed == 0 {
            let existing = self
                .get(issuance)?
                .ok_or_else(|| "governed-indeterminate-attempt-missing".to_owned())?;
            if existing.status == "settled" || existing.status == "indeterminate" {
                return Ok(());
            }
            return Err("governed-indeterminate-substitution".to_owned());
        }
        Ok(())
    }
}

fn validate_stored_record(record: &CustodyRecordV1) -> Result<(), String> {
    validate_issuance(&record.issuance)?;
    let body = b64_decode(&record.signed_body_b64)?;
    let public_key = b64_decode(&record.authentication.signer_public_key)?;
    let signature = b64_decode(&record.authentication.signature)?;
    let mut signed = Vec::with_capacity(SIGNATURE_PREFIX_V1.len() + body.len());
    signed.extend_from_slice(SIGNATURE_PREFIX_V1);
    signed.extend_from_slice(&body);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signed, &signature)
        .map_err(|_| "governed-stored-issuance-signature-invalid".to_owned())?;
    let parsed: AgIssuanceWireV1 = strict_json(&body, "stored-issuance-body")?;
    let canonical = serde_json::to_vec(
        &serde_json::to_value(&parsed)
            .map_err(|error| format!("stored-issuance-canonical-value:{error}"))?,
    )
    .map_err(|error| format!("stored-issuance-canonical:{error}"))?;
    if parsed != record.issuance || canonical != body {
        return Err("governed-stored-issuance-substitution".to_owned());
    }
    if record.custody.schema != CUSTODY_SCHEMA_V1
        || record.custody.issuance != record.issuance.issuance
        || record.custody.ag_spend != record.issuance.spend
        || record.custody.attempt
            != digest_json_string(
                "ag.governed-loop.docket-attempt/v1",
                &record.issuance.issuance,
            )?
        || record.custody.executor_marker
            != hash_domain(
                "docket.governed-loop.executor-marker/v1",
                record.custody.attempt.as_bytes(),
            )
    {
        return Err("governed-stored-custody-substitution".to_owned());
    }
    for (value, label) in [
        (
            &record.custody.execution_standing,
            "stored execution standing",
        ),
        (
            &record.custody.standing_currentness,
            "stored standing currentness",
        ),
        (&record.executor_program_digest, "stored executor program"),
        (&record.executor_plan, "stored executor plan"),
        (&record.executor_binding, "stored executor binding"),
    ] {
        require_digest(value, label)?;
    }
    let binding = serde_json::to_vec(&serde_json::json!({
        "plan": record.executor_plan,
        "program_digest": record.executor_program_digest,
    }))
    .map_err(|error| format!("stored-executor-binding-canonical:{error}"))?;
    if record.executor_binding != hash_domain("docket.governed-loop.executor-binding/v1", &binding)
    {
        return Err("governed-stored-executor-binding-substitution".to_owned());
    }
    match record.status.as_str() {
        "accepted" if record.settlement.is_none() && record.indeterminate.is_none() => Ok(()),
        "settled" => {
            let settlement = record
                .settlement
                .as_ref()
                .ok_or_else(|| "governed-stored-settlement-missing".to_owned())?;
            if settlement.schema != SETTLEMENT_SCHEMA_V1
                || settlement.issuance != record.issuance.issuance
                || settlement.attempt != record.custody.attempt
                || settlement.executor_marker != record.custody.executor_marker
            {
                return Err("governed-stored-settlement-substitution".to_owned());
            }
            require_digest(&settlement.receipt, "stored settlement receipt")?;
            let outcome = match settlement.outcome {
                KnownOutcomeWireV1::Success => "success",
                KnownOutcomeWireV1::Failure => "failure",
            };
            let expected = hash_domain(
                "docket.governed-loop.settlement/v1",
                format!(
                    "{}:{}:{}:{outcome}",
                    record.issuance.issuance, record.custody.attempt, settlement.receipt
                )
                .as_bytes(),
            );
            if settlement.settlement != expected {
                return Err("governed-stored-settlement-identity".to_owned());
            }
            if let Some(indeterminate) = &record.indeterminate {
                validate_stored_indeterminate(record, indeterminate)?;
            }
            Ok(())
        }
        "indeterminate" => {
            let indeterminate = record
                .indeterminate
                .as_ref()
                .ok_or_else(|| "governed-stored-indeterminate-missing".to_owned())?;
            if record.settlement.is_some() {
                return Err("governed-stored-indeterminate-substitution".to_owned());
            }
            validate_stored_indeterminate(record, indeterminate)
        }
        _ => Err("governed-stored-status-shape".to_owned()),
    }
}

fn validate_local_snapshot(
    connection: &Connection,
    record: &CustodyRecordV1,
) -> Result<(), String> {
    let has_mode:i64=connection.query_row("SELECT COUNT(*) FROM pragma_table_info('governed_loop_attempt') WHERE name='local_standing_mode'",[],|r|r.get(0)).map_err(|e|format!("governed-local-standing-mode-schema:{e}"))?;
    if has_mode == 0 {
        return Ok(());
    }
    let mode: i64 = connection
        .query_row(
            "SELECT local_standing_mode FROM governed_loop_attempt WHERE issuance=?1",
            [&record.issuance.issuance],
            |r| r.get(0),
        )
        .map_err(|e| format!("governed-local-standing-mode-read:{e}"))?;
    let snapshot:Option<(String,u64,String,u64,u64,String,String)>=connection.query_row("SELECT execution_standing,revision,status,resolved_at,expires_at,currentness,resolution FROM governed_local_standing_snapshot WHERE issuance=?1",[&record.issuance.issuance],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional().map_err(|e|format!("governed-local-standing-snapshot-read:{e}"))?;
    if mode == 0 {
        if snapshot.is_some() {
            return Err("governed-historical-standing-has-local-snapshot".to_owned());
        }
        return Ok(());
    }
    if mode != 1 {
        return Err("governed-local-standing-mode-corrupt".to_owned());
    }
    let (id, revision, status, resolved, expires, currentness, resolution) =
        snapshot.ok_or_else(|| "governed-local-standing-snapshot-missing".to_owned())?;
    if id != record.custody.execution_standing
        || currentness != record.custody.standing_currentness
        || status != "current"
    {
        return Err("governed-local-standing-snapshot-custody-mismatch".to_owned());
    }
    let grant:(String,String,String,String,String,String,String,String,u64,u64)=connection.query_row("SELECT operator,campaign,occurrence,program,work_schema,work,subject,scope,issued_at,expires_at FROM local_execution_standing_grant WHERE execution_standing=?1",[&id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?))).map_err(|e|format!("governed-local-standing-grant-read:{e}"))?;
    if (
        grant.1.as_str(),
        grant.2.as_str(),
        grant.3.as_str(),
        grant.4.as_str(),
        grant.5.as_str(),
        grant.6.as_str(),
        grant.7.as_str(),
        grant.9,
    ) != (
        record.issuance.key.campaign.as_str(),
        record.issuance.key.occurrence.as_str(),
        record.issuance.program.as_str(),
        record.issuance.work_schema.as_str(),
        record.issuance.work.as_str(),
        record.issuance.subject.as_str(),
        record.issuance.scope.as_str(),
        expires,
    ) || grant.8 > resolved
    {
        return Err("governed-local-standing-grant-binding-mismatch".to_owned());
    }
    let input = crate::local_execution_standing::GrantInput {
        operator: &grant.0,
        campaign: &grant.1,
        occurrence: &grant.2,
        program: &grant.3,
        work_schema: &grant.4,
        work: &grant.5,
        subject: &grant.6,
        scope: &grant.7,
        issued_at_unix_ms: grant.8,
        expires_at_unix_ms: grant.9,
    };
    if crate::local_execution_standing::grant_identity(&input)? != id {
        return Err("governed-local-standing-grant-identity".to_owned());
    }
    let (revision_status,changed_at,revision_identity):(String,u64,String)=connection.query_row("SELECT status,changed_at,revision_identity FROM local_execution_standing_revision WHERE execution_standing=?1 AND revision=?2",params![id,revision],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|e|format!("governed-local-standing-revision-read:{e}"))?;
    let expected_revision = hash_domain(
        "docket.governed-loop.local-standing-revision/v1",
        format!("{id}\0{revision}\0{revision_status}\0{changed_at}").as_bytes(),
    );
    if revision_status != "current" || revision_identity != expected_revision {
        return Err("governed-local-standing-revision-mismatch".to_owned());
    }
    let expected_currentness = hash_domain(
        "docket.governed-loop.local-standing-currentness/v1",
        format!("{id}\0{revision}\0{revision_identity}\0{revision_status}\0{resolved}\0{expires}")
            .as_bytes(),
    );
    let expected_resolution = hash_domain(
        "docket.governed-loop.local-standing-resolution/v1",
        format!(
            "{id}\0{revision}\0{currentness}\0{}\0{resolved}",
            record.issuance.issuance
        )
        .as_bytes(),
    );
    if currentness != expected_currentness || resolution != expected_resolution {
        return Err("governed-local-standing-snapshot-identity".to_owned());
    }
    Ok(())
}

fn validate_stored_indeterminate(
    record: &CustodyRecordV1,
    indeterminate: &IndeterminateOutcomeWireV1,
) -> Result<(), String> {
    if indeterminate.issuance != record.issuance.issuance
        || indeterminate.attempt != record.custody.attempt
    {
        return Err("governed-stored-indeterminate-substitution".to_owned());
    }
    require_digest(&indeterminate.evidence, "stored indeterminate evidence")?;
    let expected = hash_domain(
        "docket.governed-loop.reconciliation/v1",
        format!(
            "{}:{}:{}",
            record.issuance.issuance, record.custody.attempt, indeterminate.evidence
        )
        .as_bytes(),
    );
    if indeterminate.reconciliation != expected {
        return Err("governed-stored-reconciliation-identity".to_owned());
    }
    Ok(())
}

fn strict_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("{label}-json:{error}"))
}

fn resolve_executor_binding(
    program: &Path,
    config: &Path,
    expected_plan: &str,
) -> Result<ExecutorBindingV1, String> {
    require_digest(expected_plan, "executor plan")?;
    if !program.is_absolute() || !config.is_absolute() {
        return Err("governed-executor-path-not-absolute".to_owned());
    }
    let metadata = std::fs::symlink_metadata(program)
        .map_err(|error| format!("governed-executor-metadata:{}:{error}", program.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("governed-executor-not-regular-nonsymlink".to_owned());
    }
    if metadata.len() > MAX_EXECUTOR_PROGRAM_BYTES {
        return Err("governed-executor-program-too-large".to_owned());
    }
    let mut executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(program)
        .map_err(|error| format!("governed-executor-open:{}:{error}", program.display()))?;
    let opened_metadata = executable
        .metadata()
        .map_err(|error| format!("governed-executor-opened-metadata:{error}"))?;
    if !opened_metadata.is_file() || opened_metadata.len() != metadata.len() {
        return Err("governed-executor-file-raced".to_owned());
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened_metadata.len())
            .map_err(|_| "governed-executor-program-size-overflow".to_owned())?,
    );
    executable
        .read_to_end(&mut bytes)
        .map_err(|error| format!("governed-executor-read:{error}"))?;
    if bytes.len() as u64 != opened_metadata.len() {
        return Err("governed-executor-file-raced".to_owned());
    }
    let program_digest = hash_domain("docket.governed-loop.executor-program/v1", &bytes);
    let plan = invoke_plan_id(program, config)?;
    if plan != expected_plan {
        return Err("governed-executor-plan-substitution".to_owned());
    }
    let canonical = serde_json::to_vec(&serde_json::json!({
        "plan": plan,
        "program_digest": program_digest,
    }))
    .map_err(|error| format!("governed-executor-binding-canonical:{error}"))?;
    Ok(ExecutorBindingV1 {
        identity: hash_domain("docket.governed-loop.executor-binding/v1", &canonical),
        program_digest,
        plan,
    })
}

fn require_executor_binding(
    program: &Path,
    config: &Path,
    expected: &ExecutorBindingV1,
) -> Result<(), String> {
    let current = resolve_executor_binding(program, config, &expected.plan)?;
    if current != *expected {
        return Err("governed-executor-binding-substitution".to_owned());
    }
    Ok(())
}

fn invoke_plan_id(program: &Path, config: &Path) -> Result<String, String> {
    let output = Command::new(program)
        .arg("plan-id")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("executor-plan-id-spawn:{}:{error}", program.display()))?;
    if !output.status.success() {
        return Err(format!(
            "executor-plan-id-refused:{}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(512)
                .collect::<String>()
        ));
    }
    let body = output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout);
    if body.is_empty() || body.contains(&b'\n') || body.contains(&b'\r') {
        return Err("executor-plan-id-not-exact".to_owned());
    }
    let plan = std::str::from_utf8(body)
        .map_err(|_| "executor-plan-id-not-utf8".to_owned())?
        .to_owned();
    require_digest(&plan, "executor plan")?;
    Ok(plan)
}

fn invoke_json<I: Serialize + ?Sized, O: DeserializeOwned>(
    program: &Path,
    arguments: &[&str],
    input: &I,
    stdout_limit: usize,
) -> Result<O, String> {
    invoke_json_with_deadline(program, arguments, input, stdout_limit, None)
}

fn invoke_json_with_deadline<I: Serialize + ?Sized, O: DeserializeOwned>(
    program: &Path,
    arguments: &[&str],
    input: &I,
    stdout_limit: usize,
    deadline: Option<std::time::Duration>,
) -> Result<O, String> {
    let bytes = serde_json::to_vec(input).map_err(|error| format!("process-request:{error}"))?;
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("process-spawn:{}:{error}", program.display()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "process-stdin-unavailable".to_owned())?
        .write_all(&bytes)
        .map_err(|error| format!("process-stdin:{error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "process-stdout-unavailable".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "process-stderr-unavailable".to_owned())?;
    let stdout_reader = std::thread::spawn(move || read_bounded_draining(stdout, stdout_limit));
    let stderr_reader = std::thread::spawn(move || read_bounded_draining(stderr, 2048));
    let mut timed_out = false;
    let status = if let Some(limit) = deadline {
        let end = std::time::Instant::now() + limit;
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("process-wait:{error}"))?
            {
                break status;
            }
            if std::time::Instant::now() >= end {
                let _ = child.kill();
                timed_out = true;
                break child
                    .wait()
                    .map_err(|error| format!("process-reap:{error}"))?;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    } else {
        child
            .wait()
            .map_err(|error| format!("process-wait:{error}"))?
    };
    let (stdout, stdout_overflow) = stdout_reader
        .join()
        .map_err(|_| "process-stdout-reader-panicked".to_owned())?
        .map_err(|error| format!("process-stdout:{error}"))?;
    let (stderr, _) = stderr_reader
        .join()
        .map_err(|_| "process-stderr-reader-panicked".to_owned())?
        .map_err(|error| format!("process-stderr:{error}"))?;
    if timed_out {
        return Err("process-deadline".to_owned());
    }
    if !status.success() {
        return Err(format!(
            "process-refused:{}",
            String::from_utf8_lossy(&stderr)
                .chars()
                .take(512)
                .collect::<String>()
        ));
    }
    if stdout_overflow {
        return Err("process-response-exceeds-1-mib".to_owned());
    }
    strict_json(&stdout, "process-response")
}

fn read_bounded_draining<R: std::io::Read>(
    mut reader: R,
    limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::with_capacity(limit.min(8192));
    let mut overflow = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(retained.len());
        let keep = remaining.min(count);
        retained.extend_from_slice(&buffer[..keep]);
        overflow |= keep != count;
    }
    Ok((retained, overflow))
}

fn b64_decode(value: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    for byte in value.bytes() {
        let index = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or_else(|| "noncanonical-base64url".to_owned())? as u32;
        accumulator = (accumulator << 6) | index;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    if bits >= 6 || (accumulator & ((1 << bits) - 1)) != 0 {
        return Err("noncanonical-base64url".to_owned());
    }
    Ok(output)
}

fn now_unix_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system-clock-before-epoch".to_owned())?;
    u64::try_from(duration.as_millis()).map_err(|_| "system-clock-overflow".to_owned())
}

fn u64_to_i64(value: u64) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| "governed-clock-out-of-range".to_owned())
}

fn read_u64(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| sql_decode(&format!("negative u64 column {column}")))
}

fn sql_decode(detail: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        std::io::Error::new(std::io::ErrorKind::InvalidData, detail.to_owned()).into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SqliteStore;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use sha2::Digest as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: std::path::PathBuf,
        database: std::path::PathBuf,
        trust: Vec<u8>,
        envelope: Vec<u8>,
        issuance: AgIssuanceWireV1,
        custody: DocketCustodyWireV1,
        standing_program: std::path::PathBuf,
        executor_program: std::path::PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn fixture(executor_outcome: ExecutorOutcomeClassWireV1) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "docket-governed-loop-test-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let database = root.join("state.sqlite");
        drop(SqliteStore::open(&database).unwrap());

        let mut issuance = AgIssuanceWireV1 {
            schema: AG_ISSUANCE_SCHEMA_V1.to_owned(),
            issuance: digest("placeholder"),
            key: OccurrenceKeyWireV1 {
                campaign: digest("campaign"),
                occurrence: "00000000-0000-0000-0000-000000000001".to_owned(),
            },
            program: digest("program"),
            proposal: digest("proposal"),
            work_schema: "test.executor/v1".to_owned(),
            work: digest("work"),
            subject: digest("subject"),
            scope: digest("scope"),
            observation: digest("observation"),
            standing_resolution: digest("ag-standing-resolution"),
            mandate: digest("mandate"),
            spend: digest("ag-spend"),
        };
        let basis = serde_json::json!({
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
        issuance.issuance = hash_domain(
            "ag.governed-loop.issuance/v1",
            &serde_json::to_vec(&basis).unwrap(),
        );
        let body = serde_json::to_vec(&serde_json::to_value(&issuance).unwrap()).unwrap();
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let mut signed = SIGNATURE_PREFIX_V1.to_vec();
        signed.extend_from_slice(&body);
        let public_key = b64_encode(key.public_key().as_ref());
        let envelope = SignedIssuanceEnvelopeWireV1 {
            schema: SIGNED_ISSUANCE_SCHEMA_V1.to_owned(),
            body_b64: b64_encode(&body),
            authentication: IssuanceAuthenticationWireV1 {
                issuer_principal: "ag.test".to_owned(),
                signer_key_id: "ag-test-key".to_owned(),
                signer_public_key: public_key.clone(),
                signature: b64_encode(key.sign(&signed).as_ref()),
            },
        };
        let trust = serde_json::to_vec(&AgIssuerTrustConfigV1 {
            issuers: vec![TrustedAgIssuerV1 {
                issuer_principal: "ag.test".to_owned(),
                key_id: "ag-test-key".to_owned(),
                public_key,
            }],
        })
        .unwrap();

        let attempt =
            digest_json_string("ag.governed-loop.docket-attempt/v1", &issuance.issuance).unwrap();
        let custody = DocketCustodyWireV1 {
            schema: CUSTODY_SCHEMA_V1.to_owned(),
            issuance: issuance.issuance.clone(),
            ag_spend: issuance.spend.clone(),
            execution_standing: digest("execution-standing"),
            standing_currentness: digest("execution-standing-currentness"),
            attempt: attempt.clone(),
            executor_marker: hash_domain(
                "docket.governed-loop.executor-marker/v1",
                attempt.as_bytes(),
            ),
            accepted_at_unix_ms: 0,
        };
        let standing = ExecutionStandingResolutionV1 {
            schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
            resolution: digest("execution-standing-resolution"),
            currentness: custody.standing_currentness.clone(),
            execution_standing: custody.execution_standing.clone(),
            issuance: issuance.issuance.clone(),
            campaign: issuance.key.campaign.clone(),
            occurrence: issuance.key.occurrence.clone(),
            subject: issuance.subject.clone(),
            scope: issuance.scope.clone(),
            status: ExecutionStandingStatusV1::Current,
            resolved_at_unix_ms: 0,
            expires_at_unix_ms: i64::MAX as u64,
        };
        let standing_program = root.join("standing-resolver");
        write_static_program(
            &standing_program,
            &serde_json::to_string(&standing).unwrap(),
        );
        let executor_program = root.join("executor");
        std::fs::write(root.join("executor-config"), issuance.work.as_bytes()).unwrap();
        write_executor(
            &executor_program,
            &custody,
            executor_outcome,
            &digest("executor-receipt"),
        );
        Fixture {
            root,
            database,
            trust,
            envelope: serde_json::to_vec(&envelope).unwrap(),
            issuance,
            custody,
            standing_program,
            executor_program,
        }
    }

    #[test]
    fn authenticated_issuance_consumes_one_distinct_standing_and_settles_once() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let first = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert_eq!(first.attempt, fixture.custody.attempt);
        assert_ne!(first.ag_spend, first.execution_standing);
        assert_ne!(first.execution_standing, first.executor_marker);

        // An identical delivery is custody replay, not another executor call.
        write_refusing_program(&fixture.executor_program);
        let duplicate = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert_eq!(duplicate, first);
        let result = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(result, DocketReconciliationWireV1::Settled { .. }));

        let connection = Connection::open(&fixture.database).unwrap();
        let attempts: i64 = connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        let standing_uses: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM governed_execution_standing_use",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((attempts, standing_uses), (1, 1));
    }

    #[test]
    fn read_only_inspection_retains_issuer_custody_and_outcome_without_mutation() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let accepted = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();

        let before = std::fs::metadata(&fixture.database).unwrap().len();
        let inspection = inspect(&fixture.database, &fixture.issuance.issuance).unwrap();
        let record = inspection.record.expect("accepted issuance is visible");
        assert_eq!(inspection.schema, INSPECTION_SCHEMA_V1);
        assert_eq!(inspection.requested_issuance, fixture.issuance.issuance);
        assert_eq!(record.issuance, fixture.issuance);
        assert_eq!(record.authentication.issuer_principal, "ag.test");
        assert_eq!(record.authentication.signer_key_id, "ag-test-key");
        assert_eq!(record.custody, accepted);
        assert_eq!(record.status, GovernedRecordStatusV1::Settled);
        assert!(record.settlement.is_some());
        assert!(record.indeterminate.is_none());
        assert_eq!(std::fs::metadata(&fixture.database).unwrap().len(), before);
    }

    #[test]
    fn read_only_inspection_refuses_a_missing_store_instead_of_creating_it() {
        let root = std::env::temp_dir().join(format!(
            "docket-governed-inspect-missing-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let database = root.join("missing.sqlite");
        let result = inspect(&database, &digest("missing-issuance"));
        assert!(result.is_err());
        assert!(!database.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restart_before_custody_reservation_is_not_accepted_and_invokes_nothing() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let result = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            None,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert_eq!(result, DocketReconciliationWireV1::NotAccepted);
        assert!(!fixture
            .executor_program
            .with_extension("invocations")
            .exists());
    }

    #[test]
    fn transport_refusal_after_custody_reconciles_without_a_second_execute() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        std::fs::write(
            fixture.executor_program.with_extension("response"),
            b"not-json",
        )
        .unwrap();
        let custody = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let inspection = inspect(&fixture.database, &fixture.issuance.issuance).unwrap();
        assert_eq!(
            inspection.record.unwrap().status,
            GovernedRecordStatusV1::Indeterminate
        );

        write_executor(
            &fixture.executor_program,
            &custody,
            ExecutorOutcomeClassWireV1::Success,
            &digest("reconciled-after-transport-refusal"),
        );
        let reconciled = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            reconciled,
            DocketReconciliationWireV1::Settled { .. }
        ));
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("invocations")).unwrap(),
            b"x"
        );
    }

    #[test]
    fn executable_change_after_reservation_refuses_before_executor_invocation() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let standing: ExecutionStandingResolutionV1 = strict_json(
            &std::fs::read(fixture.standing_program.with_extension("response")).unwrap_or_else(
                |_| {
                    let output = Command::new(&fixture.standing_program).output().unwrap();
                    output.stdout
                },
            ),
            "test-standing",
        )
        .unwrap();
        write_mutating_static_program(
            &fixture.standing_program,
            &serde_json::to_string(&standing).unwrap(),
            &fixture.executor_program,
        );

        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let record = inspect(&fixture.database, &fixture.issuance.issuance)
            .unwrap()
            .record
            .unwrap();
        assert_eq!(record.status, GovernedRecordStatusV1::Indeterminate);
        assert!(!fixture
            .executor_program
            .with_extension("invocations")
            .exists());
    }

    #[test]
    fn terminal_failure_and_settlement_replay_are_exact_and_nonexecuting() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Failure);
        let custody = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let first = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        write_refusing_program(&fixture.executor_program);
        let replay = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert_eq!(replay, first);
        assert!(matches!(
            first,
            DocketReconciliationWireV1::Settled {
                settlement: DocketSettlementWireV1 {
                    outcome: KnownOutcomeWireV1::Failure,
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            std::fs::read(fixture.executor_program.with_extension("invocations")).unwrap(),
            b"x"
        );
    }

    #[test]
    fn local_mode_requires_and_atomically_retains_exact_observed_snapshot() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let missing = accept_local(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap_err();
        assert_eq!(missing, "governed-local-standing-snapshot-required");

        let input = crate::local_execution_standing::GrantInput {
            operator: "operator-1",
            campaign: &fixture.issuance.key.campaign,
            occurrence: &fixture.issuance.key.occurrence,
            program: &fixture.issuance.program,
            work_schema: &fixture.issuance.work_schema,
            work: &fixture.issuance.work,
            subject: &fixture.issuance.subject,
            scope: &fixture.issuance.scope,
            issued_at_unix_ms: 1000,
            expires_at_unix_ms: 1300,
        };
        crate::local_execution_standing::grant(&fixture.database, &input).unwrap();
        let standing = crate::local_execution_standing::resolve(
            &fixture.database,
            "operator-1",
            &ExecutionStandingRequestV1 {
                schema: STANDING_REQUEST_SCHEMA_V1.to_owned(),
                issuance: fixture.issuance.clone(),
                now_unix_ms: 1100,
            },
        )
        .unwrap();
        let custody =
            gwr_runtime::governed_loop::make_custody(&fixture.issuance, &standing, 1100).unwrap();
        let (envelope, issuance) =
            verify_signed_issuance(&fixture.envelope, &fixture.trust).unwrap();
        // The grant permanently enrolled local mode. Ordinary accept/open can
        // no longer downgrade it by omitting the assertion flag.
        let mut store = SqliteGovernedCustodyStoreV1::open(&fixture.database, false).unwrap();
        assert!(store.require_local_snapshot);
        let program_digest = digest("program-digest");
        let binding_bytes=serde_json::to_vec(&serde_json::json!({"plan":issuance.work.clone(),"program_digest":program_digest.clone()})).unwrap();
        store
            .insert_custody(
                &envelope,
                &issuance,
                &standing,
                &custody,
                &ExecutorBindingV1 {
                    identity: hash_domain(
                        "docket.governed-loop.executor-binding/v1",
                        &binding_bytes,
                    ),
                    program_digest,
                    plan: issuance.work.clone(),
                },
            )
            .unwrap();
        crate::local_execution_standing::transition(
            &fixture.database,
            &standing.execution_standing,
            "revoked",
            1150,
        )
        .unwrap();
        let snapshot = inspect_local_snapshot(&fixture.database, &issuance.issuance)
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.revision, 1);
        assert_eq!(snapshot.status, "current");
        assert_eq!(snapshot.resolved_at_unix_ms, 1100);
        assert_eq!(snapshot.expires_at_unix_ms, 1300);
        assert_eq!(snapshot.currentness, standing.currentness);
        let changed = Connection::open(&fixture.database).unwrap();
        changed.execute("UPDATE local_execution_standing_grant SET operator='operator-2' WHERE execution_standing=?1",[&standing.execution_standing]).unwrap();
        assert_eq!(
            inspect(&fixture.database, &issuance.issuance).unwrap_err(),
            "governed-local-standing-grant-identity"
        );
    }

    #[test]
    fn mutated_grant_identity_refuses_before_custody() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let input = crate::local_execution_standing::GrantInput {
            operator: "operator-1",
            campaign: &fixture.issuance.key.campaign,
            occurrence: &fixture.issuance.key.occurrence,
            program: &fixture.issuance.program,
            work_schema: &fixture.issuance.work_schema,
            work: &fixture.issuance.work,
            subject: &fixture.issuance.subject,
            scope: &fixture.issuance.scope,
            issued_at_unix_ms: 1000,
            expires_at_unix_ms: 1300,
        };
        crate::local_execution_standing::grant(&fixture.database, &input).unwrap();
        let standing = crate::local_execution_standing::resolve(
            &fixture.database,
            "operator-1",
            &ExecutionStandingRequestV1 {
                schema: STANDING_REQUEST_SCHEMA_V1.to_owned(),
                issuance: fixture.issuance.clone(),
                now_unix_ms: 1100,
            },
        )
        .unwrap();
        Connection::open(&fixture.database).unwrap().execute("UPDATE local_execution_standing_grant SET expires_at=1299 WHERE execution_standing=?1",[&standing.execution_standing]).unwrap();
        let custody =
            gwr_runtime::governed_loop::make_custody(&fixture.issuance, &standing, 1100).unwrap();
        let (envelope, issuance) =
            verify_signed_issuance(&fixture.envelope, &fixture.trust).unwrap();
        let mut store = SqliteGovernedCustodyStoreV1::open(&fixture.database, false).unwrap();
        let error = store
            .insert_custody(
                &envelope,
                &issuance,
                &standing,
                &custody,
                &ExecutorBindingV1 {
                    identity: digest("binding"),
                    program_digest: digest("program"),
                    plan: issuance.work.clone(),
                },
            )
            .unwrap_err();
        assert_eq!(error, "governed-local-standing-grant-identity");
        let count: i64 = Connection::open(&fixture.database)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM governed_execution_standing_use",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn changed_outcome_binding_and_stored_dispatch_inputs_refuse() {
        for field in ["attempt", "marker"] {
            let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
            let mut changed = fixture.custody.clone();
            match field {
                "attempt" => changed.attempt = digest("changed-attempt"),
                "marker" => changed.executor_marker = digest("changed-marker"),
                _ => unreachable!(),
            }
            write_executor(
                &fixture.executor_program,
                &changed,
                ExecutorOutcomeClassWireV1::Success,
                &digest("binding-refusal"),
            );
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap();
            assert_eq!(
                inspect(&fixture.database, &fixture.issuance.issuance)
                    .unwrap()
                    .record
                    .unwrap()
                    .status,
                GovernedRecordStatusV1::Indeterminate,
                "field={field}"
            );
        }

        for column in ["work", "subject", "scope"] {
            let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap();
            let connection = Connection::open(&fixture.database).unwrap();
            connection
                .execute(
                    &format!("UPDATE governed_loop_attempt SET {column}=?1"),
                    [digest("stored-dispatch-substitution")],
                )
                .unwrap();
            drop(connection);
            assert!(
                inspect(&fixture.database, &fixture.issuance.issuance).is_err(),
                "column={column}"
            );
        }
    }

    #[test]
    fn sqlite_schema_and_exact_semantic_rows_remain_c1_compatible() {
        let actual: [u8; 32] = sha2::Sha256::digest(include_bytes!(
            "../migrations/0006_governed_loop_custody.sql"
        ))
        .into();
        let expected: [u8; 32] =
            hex_bytes("eefe9b084d1515086d3de3621c8b52a95a1603622f23482d2e700242bb7caeeb")
                .try_into()
                .unwrap();
        assert_eq!(actual, expected);
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let custody = accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let connection = Connection::open(&fixture.database).unwrap();
        let row: (String, String, String, String, String, String, String) = connection
            .query_row(
                "SELECT issuance,ag_spend,execution_standing,attempt,executor_marker,status,outcome
                 FROM governed_loop_attempt",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            row,
            (
                fixture.issuance.issuance.clone(),
                fixture.issuance.spend.clone(),
                custody.execution_standing.clone(),
                custody.attempt.clone(),
                custody.executor_marker.clone(),
                "settled".to_owned(),
                "success".to_owned(),
            )
        );
        let standing: (String, String, String) = connection
            .query_row(
                "SELECT execution_standing,issuance,standing_currentness
                 FROM governed_execution_standing_use",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            standing,
            (
                custody.execution_standing,
                fixture.issuance.issuance.clone(),
                custody.standing_currentness,
            )
        );
    }

    #[test]
    fn unknown_outcome_reconciles_read_only_and_never_executes_again() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        let unknown = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            None,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            &unknown,
            DocketReconciliationWireV1::Indeterminate { .. }
        ));

        write_executor(
            &fixture.executor_program,
            &fixture.custody,
            ExecutorOutcomeClassWireV1::Indeterminate,
            &digest("different-unknown-evidence"),
        );
        let repeated_unknown = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert_eq!(repeated_unknown, unknown);

        write_executor(
            &fixture.executor_program,
            &fixture.custody,
            ExecutorOutcomeClassWireV1::Failure,
            &digest("reconciled-receipt"),
        );
        let settled = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(matches!(
            settled,
            DocketReconciliationWireV1::Settled { .. }
        ));
    }

    #[test]
    fn signature_attempt_and_instrument_substitutions_refuse() {
        let first_fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let mut changed: serde_json::Value =
            serde_json::from_slice(&first_fixture.envelope).unwrap();
        changed["authentication"]["signature"] = serde_json::Value::String(b64_encode(&[0; 64]));
        assert!(verify_signed_issuance(
            &serde_json::to_vec(&changed).unwrap(),
            &first_fixture.trust,
        )
        .is_err());

        accept(
            &first_fixture.database,
            &first_fixture.envelope,
            &first_fixture.trust,
            &first_fixture.standing_program,
            &first_fixture.executor_program,
            &first_fixture.root.join("executor-config"),
        )
        .unwrap();
        assert!(reconcile(
            &first_fixture.database,
            &first_fixture.issuance.issuance,
            Some(&digest("wrong-attempt")),
            &first_fixture.executor_program,
            &first_fixture.root.join("executor-config"),
        )
        .is_err());

        let substituted = fixture(ExecutorOutcomeClassWireV1::Success);
        let standing = ExecutionStandingResolutionV1 {
            schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
            resolution: digest("substituted-standing-resolution"),
            currentness: digest("substituted-standing-currentness"),
            execution_standing: substituted.issuance.spend.clone(),
            issuance: substituted.issuance.issuance.clone(),
            campaign: substituted.issuance.key.campaign.clone(),
            occurrence: substituted.issuance.key.occurrence.clone(),
            subject: substituted.issuance.subject.clone(),
            scope: substituted.issuance.scope.clone(),
            status: ExecutionStandingStatusV1::Current,
            resolved_at_unix_ms: 0,
            expires_at_unix_ms: i64::MAX as u64,
        };
        write_static_program(
            &substituted.standing_program,
            &serde_json::to_string(&standing).unwrap(),
        );
        assert_eq!(
            accept(
                &substituted.database,
                &substituted.envelope,
                &substituted.trust,
                &substituted.standing_program,
                &substituted.executor_program,
                &substituted.root.join("executor-config"),
            )
            .unwrap_err(),
            "governed-instrument-substitution"
        );
        let connection = Connection::open(&substituted.database).unwrap();
        let attempts: i64 = connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(attempts, 0);
    }

    #[test]
    fn executor_and_plan_substitution_refuse_during_reconciliation() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Indeterminate);
        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();

        std::fs::write(fixture.root.join("executor-config"), digest("wrong-plan")).unwrap();
        let plan_error = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap_err();
        assert!(plan_error.contains("executor-plan-substitution"));

        std::fs::write(
            fixture.root.join("executor-config"),
            fixture.issuance.work.as_bytes(),
        )
        .unwrap();
        let mut executable = OpenOptions::new()
            .append(true)
            .open(&fixture.executor_program)
            .unwrap();
        writeln!(executable, "# substituted executable").unwrap();
        drop(executable);
        let executable_error = reconcile(
            &fixture.database,
            &fixture.issuance.issuance,
            Some(&fixture.custody.attempt),
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap_err();
        assert_eq!(executable_error, "governed-executor-binding-substitution");
    }

    #[test]
    fn concurrent_duplicate_custody_creates_one_attempt_and_one_delivery() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        let (left, right) = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                accept(
                    &fixture.database,
                    &fixture.envelope,
                    &fixture.trust,
                    &fixture.standing_program,
                    &fixture.executor_program,
                    &fixture.root.join("executor-config"),
                )
            });
            let right = scope.spawn(|| {
                accept(
                    &fixture.database,
                    &fixture.envelope,
                    &fixture.trust,
                    &fixture.standing_program,
                    &fixture.executor_program,
                    &fixture.root.join("executor-config"),
                )
            });
            (left.join().unwrap(), right.join().unwrap())
        });
        assert_eq!(left.unwrap(), right.unwrap());

        let delivered = std::fs::read(fixture.executor_program.with_extension("invocations"))
            .unwrap_or_default();
        assert_eq!(delivered, b"x");
        let connection = Connection::open(&fixture.database).unwrap();
        let attempts: i64 = connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(attempts, 1);
    }

    #[test]
    fn restart_read_refuses_tampered_custody_and_settlement_rows() {
        for (label, statement) in [
            (
                "custody",
                "UPDATE governed_loop_attempt SET executor_binding='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
            ),
            (
                "settlement",
                "UPDATE governed_loop_attempt SET receipt='sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
            ),
        ] {
            let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
            accept(
                &fixture.database,
                &fixture.envelope,
                &fixture.trust,
                &fixture.standing_program,
                &fixture.executor_program,
                &fixture.root.join("executor-config"),
            )
            .unwrap();
            let connection = Connection::open(&fixture.database).unwrap();
            connection.execute(statement, []).unwrap();
            drop(connection);
            assert!(
                reconcile(
                    &fixture.database,
                    &fixture.issuance.issuance,
                    Some(&fixture.custody.attempt),
                    &fixture.executor_program,
                    &fixture.root.join("executor-config"),
                )
                .is_err(),
                "{label} substitution must fail closed"
            );
        }
    }

    #[test]
    fn docket_owned_executor_transport_corpus_matches_the_v1_wire_projection() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/executor-transport-v1/corpus.json"
        ))
        .unwrap();
        assert_eq!(
            corpus["transport"],
            serde_json::Value::String(EXECUTOR_TRANSPORT_SCHEMA_V1.to_owned())
        );
        assert_eq!(
            corpus["dispatch_schema"],
            serde_json::Value::String(EXECUTOR_DISPATCH_SCHEMA_V1.to_owned())
        );
        assert_eq!(
            corpus["outcome_schema"],
            serde_json::Value::String(EXECUTOR_OUTCOME_SCHEMA_V1.to_owned())
        );
        assert_eq!(
            corpus["max_document_bytes"],
            serde_json::Value::from(MAX_EXECUTOR_DOCUMENT_BYTES)
        );

        for case in corpus["decode_cases"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap().as_bytes();
            let canonical = match case["kind"].as_str().unwrap() {
                "dispatch" => strict_json::<ExecutorDispatchWireV1>(input, "corpus-dispatch")
                    .and_then(|dispatch| {
                        for value in [
                            &dispatch.attempt,
                            &dispatch.marker,
                            &dispatch.work,
                            &dispatch.subject,
                            &dispatch.scope,
                        ] {
                            require_digest(value, "corpus dispatch digest")?;
                        }
                        if dispatch.work_schema.is_empty() {
                            return Err("corpus dispatch work schema empty".to_owned());
                        }
                        serde_json::to_vec(&serde_json::to_value(dispatch).unwrap())
                            .map_err(|error| error.to_string())
                    }),
                "outcome" => strict_json::<ExecutorOutcomeWireV1>(input, "corpus-outcome")
                    .and_then(|outcome| {
                        for value in [&outcome.attempt, &outcome.marker, &outcome.receipt] {
                            require_digest(value, "corpus outcome digest")?;
                        }
                        serde_json::to_vec(&serde_json::to_value(outcome).unwrap())
                            .map_err(|error| error.to_string())
                    }),
                other => panic!("unknown corpus document kind {other}"),
            };
            assert_eq!(
                canonical.is_ok(),
                case["expect"] == "accept",
                "corpus case {}",
                case["id"].as_str().unwrap()
            );
            if let (Ok(actual), Some(expected)) = (canonical, case["canonical_output"].as_str()) {
                assert_eq!(actual, expected.as_bytes(), "corpus case {}", case["id"]);
            }
        }
    }

    #[test]
    fn oversized_executor_stdout_is_transport_refusal_and_docket_indeterminate() {
        let fixture = fixture(ExecutorOutcomeClassWireV1::Success);
        std::fs::write(
            fixture.executor_program.with_extension("response"),
            vec![b'x'; MAX_EXECUTOR_DOCUMENT_BYTES + 1],
        )
        .unwrap();

        accept(
            &fixture.database,
            &fixture.envelope,
            &fixture.trust,
            &fixture.standing_program,
            &fixture.executor_program,
            &fixture.root.join("executor-config"),
        )
        .unwrap();

        let inspection = inspect(&fixture.database, &fixture.issuance.issuance).unwrap();
        let record = inspection.record.unwrap();
        assert_eq!(record.status, GovernedRecordStatusV1::Indeterminate);
        assert!(record.settlement.is_none());
        assert!(record.indeterminate.is_some());
    }

    #[test]
    fn bounded_reader_drains_but_retains_no_more_than_the_contract_limit() {
        let input = vec![b'x'; 32];
        let (retained, overflow) = read_bounded_draining(input.as_slice(), 16).unwrap();
        assert_eq!(retained, vec![b'x'; 16]);
        assert!(overflow);
    }

    fn digest(label: &str) -> String {
        hash_domain("docket-governed-loop-test/v1", label.as_bytes())
    }

    fn write_executor(
        path: &Path,
        custody: &DocketCustodyWireV1,
        outcome: ExecutorOutcomeClassWireV1,
        receipt: &str,
    ) {
        let output = serde_json::to_string(&ExecutorOutcomeWireV1 {
            attempt: custody.attempt.clone(),
            marker: custody.executor_marker.clone(),
            receipt: receipt.to_owned(),
            outcome,
        })
        .unwrap();
        let response = path.with_extension("response");
        let invocations = path.with_extension("invocations");
        std::fs::write(&response, output).unwrap();
        if path.exists() {
            return;
        }
        let response = response.display().to_string().replace('\'', "'\\''");
        let invocations = invocations.display().to_string().replace('\'', "'\\''");
        std::fs::write(
            path,
            format!(
                "#!/bin/sh\nif [ \"$1\" = plan-id ]; then cat \"$2\"; exit $?; fi\nif [ \"$1\" = execute ]; then cat >/dev/null; printf x >> '{invocations}'; cat '{response}'; exit $?; fi\nif [ \"$1\" = reconcile ]; then cat >/dev/null; cat '{response}'; exit $?; fi\nexit 64\n"
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn write_static_program(path: &Path, output: &str) {
        let escaped = output.replace('\'', "'\\''");
        std::fs::write(
            path,
            format!("#!/bin/sh\ncat >/dev/null\nprintf '%s' '{escaped}'\n"),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn write_mutating_static_program(path: &Path, output: &str, mutated: &Path) {
        let escaped = output.replace('\'', "'\\''");
        let mutated = mutated.display().to_string().replace('\'', "'\\''");
        std::fs::write(
            path,
            format!(
                "#!/bin/sh\ncat >/dev/null\nprintf '\\n# changed-after-reservation\\n' >> '{mutated}'\nprintf '%s' '{escaped}'\n"
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn write_refusing_program(path: &Path) {
        std::fs::write(path, "#!/bin/sh\nexit 77\n").unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn b64_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let value = (u32::from(chunk[0]) << 16)
                | (chunk.get(1).copied().map_or(0, u32::from) << 8)
                | chunk.get(2).copied().map_or(0, u32::from);
            output.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
            output.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
            if chunk.len() > 1 {
                output.push(ALPHABET[((value >> 6) & 0x3f) as usize] as char);
            }
            if chunk.len() > 2 {
                output.push(ALPHABET[(value & 0x3f) as usize] as char);
            }
        }
        output
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}
