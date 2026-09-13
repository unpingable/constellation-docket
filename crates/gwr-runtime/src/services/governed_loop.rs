//! Coordination of Docket governed-loop custody through narrow adapter ports.

use crate::governed_loop::{
    executor_dispatch, hash_domain, make_custody, require_digest, require_same_envelope,
    AgIssuanceWireV1, CustodyRecordV1, DocketCustodyWireV1, DocketReconciliationWireV1,
    ExecutorOutcomeClassWireV1, ExecutorOutcomeWireV1, GovernedLoopInspectionV1,
    GovernedRecordInspectionV1, GovernedRecordStatusV1, KnownOutcomeWireV1,
    SignedIssuanceEnvelopeWireV1, INSPECTION_SCHEMA_V1, STANDING_REQUEST_SCHEMA_V1,
};
use crate::ports::governed_loop::{
    ExecutionStandingResolverV1, GovernedClockV1, GovernedCustodyStoreV1, GovernedExecutorV1,
};

pub fn accept<S, R, E, C>(
    store: &mut S,
    envelope: &SignedIssuanceEnvelopeWireV1,
    issuance: &AgIssuanceWireV1,
    standing_resolver: &mut R,
    executor: &mut E,
    clock: &mut C,
) -> Result<DocketCustodyWireV1, String>
where
    S: GovernedCustodyStoreV1,
    R: ExecutionStandingResolverV1,
    E: GovernedExecutorV1,
    C: GovernedClockV1,
{
    if let Some(existing) = store.get(&issuance.issuance)? {
        require_same_envelope(&existing, envelope, issuance)?;
        return Ok(existing.custody);
    }

    let executor_binding = executor.resolve_binding(&issuance.work)?;
    let now = clock.now_unix_ms()?;
    let standing =
        standing_resolver.resolve(&crate::governed_loop::ExecutionStandingRequestV1 {
            schema: STANDING_REQUEST_SCHEMA_V1.to_owned(),
            issuance: issuance.clone(),
            now_unix_ms: now,
        })?;
    let custody = make_custody(issuance, &standing, now)?;
    match store.insert_custody(envelope, issuance, &standing, &custody, &executor_binding) {
        Ok(()) => {}
        Err(error) => {
            if let Some(existing) = store.get(&issuance.issuance)? {
                require_same_envelope(&existing, envelope, issuance)?;
                return Ok(existing.custody);
            }
            return Err(error);
        }
    }

    if let Err(error) = executor.require_binding(&executor_binding) {
        store.record_indeterminate(
            &issuance.issuance,
            &custody,
            &hash_domain(
                "docket.governed-loop.executor-binding-changed/v1",
                error.as_bytes(),
            ),
        )?;
        return Ok(custody);
    }
    let dispatch = executor_dispatch(issuance, &custody);
    match executor.execute(&dispatch) {
        Ok(outcome) => record_executor_outcome(
            store,
            &issuance.issuance,
            &custody,
            outcome,
            clock.now_unix_ms()?,
        )?,
        Err(error) => store.record_indeterminate(
            &issuance.issuance,
            &custody,
            &hash_domain(
                "docket.governed-loop.executor-unavailable/v1",
                error.as_bytes(),
            ),
        )?,
    }
    Ok(custody)
}

pub fn reconcile<S, E, C>(
    store: &mut S,
    issuance: &str,
    expected_attempt: Option<&str>,
    executor: &mut E,
    clock: &mut C,
) -> Result<DocketReconciliationWireV1, String>
where
    S: GovernedCustodyStoreV1,
    E: GovernedExecutorV1,
    C: GovernedClockV1,
{
    require_digest(issuance, "issuance")?;
    let Some(mut record) = store.get(issuance)? else {
        return Ok(DocketReconciliationWireV1::NotAccepted);
    };
    if expected_attempt.is_some_and(|expected| expected != record.custody.attempt) {
        return Err("governed-reconciliation-attempt-substitution".to_owned());
    }
    if record.status == "settled" {
        return response(record);
    }

    executor.require_binding(&crate::governed_loop::ExecutorBindingV1 {
        identity: record.executor_binding.clone(),
        program_digest: record.executor_program_digest.clone(),
        plan: record.executor_plan.clone(),
    })?;
    let dispatch = executor_dispatch(&record.issuance, &record.custody);
    match executor.reconcile(&dispatch) {
        Ok(outcome) => record_executor_outcome(
            store,
            issuance,
            &record.custody,
            outcome,
            clock.now_unix_ms()?,
        )?,
        Err(error) if record.status == "accepted" => store.record_indeterminate(
            issuance,
            &record.custody,
            &hash_domain(
                "docket.governed-loop.reconciliation-unavailable/v1",
                error.as_bytes(),
            ),
        )?,
        Err(_) => {}
    }
    record = store
        .get(issuance)?
        .ok_or_else(|| "governed-custody-disappeared".to_owned())?;
    response(record)
}

pub fn inspect<S: GovernedCustodyStoreV1>(
    store: &mut S,
    issuance: &str,
) -> Result<GovernedLoopInspectionV1, String> {
    require_digest(issuance, "issuance")?;
    let Some(record) = store.get(issuance)? else {
        return Ok(GovernedLoopInspectionV1 {
            schema: INSPECTION_SCHEMA_V1.to_owned(),
            requested_issuance: issuance.to_owned(),
            record: None,
        });
    };
    let status = match record.status.as_str() {
        "accepted" => GovernedRecordStatusV1::Accepted,
        "settled" => GovernedRecordStatusV1::Settled,
        "indeterminate" => GovernedRecordStatusV1::Indeterminate,
        _ => return Err("governed-custody-status-corrupt".to_owned()),
    };
    Ok(GovernedLoopInspectionV1 {
        schema: INSPECTION_SCHEMA_V1.to_owned(),
        requested_issuance: issuance.to_owned(),
        record: Some(GovernedRecordInspectionV1 {
            issuance: record.issuance,
            authentication: record.authentication,
            custody: record.custody,
            status,
            settlement: record.settlement,
            indeterminate: record.indeterminate,
            executor_binding: record.executor_binding,
            executor_program_digest: record.executor_program_digest,
            executor_plan: record.executor_plan,
        }),
    })
}

fn record_executor_outcome<S: GovernedCustodyStoreV1>(
    store: &mut S,
    issuance: &str,
    custody: &DocketCustodyWireV1,
    outcome: ExecutorOutcomeWireV1,
    at: u64,
) -> Result<(), String> {
    if outcome.attempt != custody.attempt || outcome.marker != custody.executor_marker {
        return store.record_indeterminate(
            issuance,
            custody,
            &hash_domain(
                "docket.governed-loop.executor-binding-refusal/v1",
                format!("{}:{}", outcome.attempt, outcome.marker).as_bytes(),
            ),
        );
    }
    require_digest(&outcome.receipt, "executor receipt")?;
    match outcome.outcome {
        ExecutorOutcomeClassWireV1::Success => store.record_known_outcome(
            issuance,
            custody,
            &outcome.receipt,
            KnownOutcomeWireV1::Success,
            at,
        ),
        ExecutorOutcomeClassWireV1::Failure => store.record_known_outcome(
            issuance,
            custody,
            &outcome.receipt,
            KnownOutcomeWireV1::Failure,
            at,
        ),
        ExecutorOutcomeClassWireV1::Indeterminate => {
            store.record_indeterminate(issuance, custody, &outcome.receipt)
        }
    }
}

fn response(record: CustodyRecordV1) -> Result<DocketReconciliationWireV1, String> {
    match record.status.as_str() {
        "accepted" => Ok(DocketReconciliationWireV1::Accepted(record.custody)),
        "settled" => Ok(DocketReconciliationWireV1::Settled {
            custody: record.custody,
            settlement: record
                .settlement
                .ok_or_else(|| "governed-settlement-columns-missing".to_owned())?,
        }),
        "indeterminate" => Ok(DocketReconciliationWireV1::Indeterminate {
            custody: record.custody,
            indeterminate: record
                .indeterminate
                .ok_or_else(|| "governed-indeterminate-columns-missing".to_owned())?,
        }),
        _ => Err("governed-custody-status-corrupt".to_owned()),
    }
}
