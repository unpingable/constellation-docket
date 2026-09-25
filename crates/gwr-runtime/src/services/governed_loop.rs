//! Coordination of Docket governed-loop custody through narrow adapter ports.

use crate::governed_loop::{
    executor_dispatch, hash_domain, issuance_expired_before_execute_evidence, make_custody,
    require_digest, require_issuance_current, require_same_envelope,
    require_standing_snapshot_within_bound, standing_snapshot_exceeded_before_execute_evidence,
    AgIssuanceWireV1, CustodyRecordV1, DocketCustodyWireV1, DocketReconciliationWireV1,
    ExecutorOutcomeClassWireV1, ExecutorOutcomeWireV1, GovernedLoopInspectionV1,
    GovernedRecordInspectionV1, GovernedRecordStatusV1, KnownOutcomeWireV1,
    SignedIssuanceEnvelopeWireV1, INSPECTION_SCHEMA_V1, STANDING_REQUEST_SCHEMA_V1,
};
use crate::ports::governed_loop::{
    ExecutionStandingResolverV1, GovernedClockV1, GovernedCustodyStoreV1, GovernedExecutorV1,
};

/// Accepts one authenticated AG issuance and performs at most one executor
/// delivery.
///
/// Effect-boundary rule (declared, enforced with the injected clock):
/// - AG warrant: the signed issuance `not_after` must lie strictly after the
///   clock reading taken (1) before standing resolution, (2) immediately
///   before the custody transaction and (3) immediately before `execute`.
///   A historical issuance without not-after is refused.
/// - Docket warrant: the execution-standing resolution is a snapshot bounded
///   by `MAX_STANDING_SNAPSHOT_AGE_MS` and its own expiry, checked at (2)
///   and (3).
///
/// Before custody a failed check refuses and persists nothing. After custody
/// it records a typed indeterminate outcome and never invokes the executor.
/// Re-delivery of an already custodied issuance returns that custody and
/// never executes; reconciliation never executes.
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

    let now = clock.now_unix_ms()?;
    require_issuance_current(issuance, now)?;
    let executor_binding = executor.resolve_binding(&issuance.work)?;
    let standing =
        standing_resolver.resolve(&crate::governed_loop::ExecutionStandingRequestV1 {
            schema: STANDING_REQUEST_SCHEMA_V1.to_owned(),
            issuance: issuance.clone(),
            now_unix_ms: now,
        })?;
    let custody = make_custody(issuance, &standing, now)?;
    let custody_now = clock.now_unix_ms()?;
    require_issuance_current(issuance, custody_now)?;
    require_standing_snapshot_within_bound(&standing, custody_now)?;
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
    let execute_now = clock.now_unix_ms()?;
    if require_issuance_current(issuance, execute_now).is_err() {
        store.record_indeterminate(
            &issuance.issuance,
            &custody,
            &issuance_expired_before_execute_evidence(issuance),
        )?;
        return Ok(custody);
    }
    if require_standing_snapshot_within_bound(&standing, execute_now).is_err() {
        store.record_indeterminate(
            &issuance.issuance,
            &custody,
            &standing_snapshot_exceeded_before_execute_evidence(issuance, &custody),
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

#[cfg(test)]
mod tests {
    //! Synthetic-clock tests of the effect-boundary rule. Every port is an
    //! in-memory fake; the clock returns a scripted reading per call.
    use super::*;
    use crate::governed_loop::{
        issuance_identity, ExecutionStandingResolutionV1, ExecutionStandingStatusV1,
        ExecutorBindingV1, ExecutorDispatchWireV1, IssuanceAuthenticationWireV1,
        OccurrenceKeyWireV1, AG_ISSUANCE_SCHEMA_V1, AG_ISSUANCE_SCHEMA_V2,
        MAX_STANDING_SNAPSHOT_AGE_MS, SIGNED_ISSUANCE_SCHEMA_V1, STANDING_RESOLUTION_SCHEMA_V1,
    };
    use std::collections::{BTreeMap, VecDeque};

    const T: u64 = 1_790_000_000_000;
    const NOT_AFTER: u64 = T + 60_000;

    fn digest(label: &str) -> String {
        hash_domain("docket-ewv-service-test/v1", label.as_bytes())
    }

    fn issuance(schema: &str, not_after: Option<u64>) -> AgIssuanceWireV1 {
        let mut issuance = AgIssuanceWireV1 {
            schema: schema.to_owned(),
            issuance: String::new(),
            key: OccurrenceKeyWireV1 {
                campaign: digest("campaign"),
                occurrence: "00000000-0000-4000-8000-0000000000e2".to_owned(),
            },
            program: digest("program"),
            proposal: digest("proposal"),
            work_schema: "test.executor/v1".to_owned(),
            work: digest("work"),
            subject: digest("subject"),
            scope: digest("scope"),
            observation: digest("observation"),
            standing_resolution: digest("ag-standing"),
            mandate: digest("mandate"),
            spend: digest("spend"),
            not_after_unix_ms: not_after,
        };
        issuance.issuance = issuance_identity(&issuance).unwrap();
        issuance
    }

    fn envelope() -> SignedIssuanceEnvelopeWireV1 {
        SignedIssuanceEnvelopeWireV1 {
            schema: SIGNED_ISSUANCE_SCHEMA_V1.to_owned(),
            body_b64: "body".to_owned(),
            authentication: IssuanceAuthenticationWireV1 {
                issuer_principal: "ag.test".to_owned(),
                signer_key_id: "key".to_owned(),
                signer_public_key: "public".to_owned(),
                signature: "signature".to_owned(),
            },
        }
    }

    #[derive(Default)]
    struct Store {
        records: BTreeMap<String, CustodyRecordV1>,
    }

    impl GovernedCustodyStoreV1 for Store {
        fn get(&mut self, issuance: &str) -> Result<Option<CustodyRecordV1>, String> {
            Ok(self.records.get(issuance).cloned())
        }

        fn insert_custody(
            &mut self,
            envelope: &SignedIssuanceEnvelopeWireV1,
            issuance: &AgIssuanceWireV1,
            _standing: &ExecutionStandingResolutionV1,
            custody: &DocketCustodyWireV1,
            binding: &ExecutorBindingV1,
        ) -> Result<(), String> {
            let record = CustodyRecordV1 {
                issuance: issuance.clone(),
                custody: custody.clone(),
                signed_body_b64: envelope.body_b64.clone(),
                authentication: envelope.authentication.clone(),
                executor_binding: binding.identity.clone(),
                executor_program_digest: binding.program_digest.clone(),
                executor_plan: binding.plan.clone(),
                status: "accepted".to_owned(),
                settlement: None,
                indeterminate: None,
            };
            if self
                .records
                .insert(issuance.issuance.clone(), record)
                .is_some()
            {
                return Err("duplicate".to_owned());
            }
            Ok(())
        }

        fn record_known_outcome(
            &mut self,
            issuance: &str,
            _custody: &DocketCustodyWireV1,
            _receipt: &str,
            _outcome: KnownOutcomeWireV1,
            _at: u64,
        ) -> Result<(), String> {
            self.records.get_mut(issuance).unwrap().status = "settled".to_owned();
            Ok(())
        }

        fn record_indeterminate(
            &mut self,
            issuance: &str,
            custody: &DocketCustodyWireV1,
            evidence: &str,
        ) -> Result<(), String> {
            let record = self.records.get_mut(issuance).unwrap();
            if record.status == "accepted" {
                record.status = "indeterminate".to_owned();
                record.indeterminate = Some(crate::governed_loop::IndeterminateOutcomeWireV1 {
                    issuance: issuance.to_owned(),
                    attempt: custody.attempt.clone(),
                    reconciliation: digest("reconciliation"),
                    evidence: evidence.to_owned(),
                });
            }
            Ok(())
        }
    }

    struct Resolver {
        status: ExecutionStandingStatusV1,
        age_ms: u64,
        lifetime_ms: u64,
        calls: usize,
    }

    impl Resolver {
        fn current() -> Self {
            Self {
                status: ExecutionStandingStatusV1::Current,
                age_ms: 0,
                lifetime_ms: 300_000,
                calls: 0,
            }
        }
    }

    impl ExecutionStandingResolverV1 for Resolver {
        fn resolve(
            &mut self,
            request: &crate::governed_loop::ExecutionStandingRequestV1,
        ) -> Result<ExecutionStandingResolutionV1, String> {
            self.calls += 1;
            let issuance = &request.issuance;
            let resolved_at = request.now_unix_ms - self.age_ms;
            Ok(ExecutionStandingResolutionV1 {
                schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
                resolution: digest("resolution"),
                currentness: digest("currentness"),
                execution_standing: digest("execution-standing"),
                issuance: issuance.issuance.clone(),
                campaign: issuance.key.campaign.clone(),
                occurrence: issuance.key.occurrence.clone(),
                subject: issuance.subject.clone(),
                scope: issuance.scope.clone(),
                status: self.status.clone(),
                resolved_at_unix_ms: resolved_at,
                expires_at_unix_ms: resolved_at + self.lifetime_ms,
            })
        }
    }

    #[derive(Default)]
    struct Executor {
        executes: usize,
        reconciles: usize,
    }

    impl GovernedExecutorV1 for Executor {
        fn resolve_binding(&mut self, _plan: &str) -> Result<ExecutorBindingV1, String> {
            Ok(ExecutorBindingV1 {
                identity: digest("binding"),
                program_digest: digest("program-bytes"),
                plan: digest("plan"),
            })
        }

        fn require_binding(&mut self, _expected: &ExecutorBindingV1) -> Result<(), String> {
            Ok(())
        }

        fn execute(
            &mut self,
            dispatch: &ExecutorDispatchWireV1,
        ) -> Result<ExecutorOutcomeWireV1, String> {
            self.executes += 1;
            Ok(ExecutorOutcomeWireV1 {
                attempt: dispatch.attempt.clone(),
                marker: dispatch.marker.clone(),
                receipt: digest("receipt"),
                outcome: ExecutorOutcomeClassWireV1::Success,
            })
        }

        fn reconcile(
            &mut self,
            _dispatch: &ExecutorDispatchWireV1,
        ) -> Result<ExecutorOutcomeWireV1, String> {
            self.reconciles += 1;
            Err("attempt-absent".to_owned())
        }
    }

    /// Returns one scripted reading per call; repeats the last one.
    struct Clock(VecDeque<u64>, u64);

    impl Clock {
        fn new(readings: &[u64]) -> Self {
            Self(readings.iter().copied().collect(), 0)
        }
    }

    impl GovernedClockV1 for Clock {
        fn now_unix_ms(&mut self) -> Result<u64, String> {
            if let Some(next) = self.0.pop_front() {
                self.1 = next;
            }
            Ok(self.1)
        }
    }

    struct Run {
        store: Store,
        resolver: Resolver,
        executor: Executor,
        issuance: AgIssuanceWireV1,
    }

    impl Run {
        fn new(issuance: AgIssuanceWireV1) -> Self {
            Self {
                store: Store::default(),
                resolver: Resolver::current(),
                executor: Executor::default(),
                issuance,
            }
        }

        /// Clock readings: pre-resolution, pre-custody, pre-execute, settle.
        fn accept(&mut self, readings: &[u64]) -> Result<DocketCustodyWireV1, String> {
            accept(
                &mut self.store,
                &envelope(),
                &self.issuance,
                &mut self.resolver,
                &mut self.executor,
                &mut Clock::new(readings),
            )
        }

        fn status(&self) -> Option<&str> {
            self.store
                .records
                .get(&self.issuance.issuance)
                .map(|record| record.status.as_str())
        }

        fn evidence(&self) -> Option<&str> {
            self.store.records[&self.issuance.issuance]
                .indeterminate
                .as_ref()
                .map(|value| value.evidence.as_str())
        }
    }

    fn v2() -> AgIssuanceWireV1 {
        issuance(AG_ISSUANCE_SCHEMA_V2, Some(NOT_AFTER))
    }

    #[test]
    fn before_not_after_at_every_reading_executes_once() {
        let mut run = Run::new(v2());
        let n = NOT_AFTER - 1;
        run.accept(&[n, n, n, n]).unwrap();
        assert_eq!(run.executor.executes, 1);
        assert_eq!(run.status(), Some("settled"));
    }

    #[test]
    fn at_or_after_not_after_at_accept_refuses_before_any_owner_is_asked() {
        for now in [NOT_AFTER, NOT_AFTER + 1, NOT_AFTER + 86_400_000] {
            let mut run = Run::new(v2());
            assert_eq!(run.accept(&[now]).unwrap_err(), "governed-issuance-expired");
            assert_eq!(run.resolver.calls, 0);
            assert_eq!(run.executor.executes, 0);
            assert!(run.store.records.is_empty());
        }
    }

    #[test]
    fn expiry_between_resolution_and_custody_refuses_and_persists_nothing() {
        let mut run = Run::new(v2());
        assert_eq!(
            run.accept(&[NOT_AFTER - 10, NOT_AFTER]).unwrap_err(),
            "governed-issuance-expired"
        );
        assert_eq!(run.resolver.calls, 1);
        assert_eq!(run.executor.executes, 0);
        assert!(run.store.records.is_empty(), "no standing use consumed");
    }

    #[test]
    fn expiry_between_custody_and_execute_never_invokes_the_executor() {
        let mut run = Run::new(v2());
        let custody = run
            .accept(&[NOT_AFTER - 10, NOT_AFTER - 5, NOT_AFTER])
            .unwrap();
        assert_eq!(run.executor.executes, 0);
        assert_eq!(run.status(), Some("indeterminate"));
        assert_eq!(
            run.evidence(),
            Some(issuance_expired_before_execute_evidence(&run.issuance).as_str())
        );

        // Re-delivery (AG retry) returns the same custody and never executes.
        assert_eq!(run.accept(&[NOT_AFTER + 1]).unwrap(), custody);
        // Reconciliation after expiry is read-only and never executes.
        let reconciled = reconcile(
            &mut run.store,
            &run.issuance.issuance.clone(),
            Some(&custody.attempt),
            &mut run.executor,
            &mut Clock::new(&[NOT_AFTER + 2]),
        )
        .unwrap();
        assert!(matches!(
            reconciled,
            DocketReconciliationWireV1::Indeterminate { .. }
        ));
        assert_eq!(run.executor.reconciles, 1);
        assert_eq!(run.executor.executes, 0);
    }

    #[test]
    fn retry_after_expiry_is_not_refreshed() {
        let mut run = Run::new(v2());
        for now in [NOT_AFTER, NOT_AFTER + 1_000, NOT_AFTER + 3_600_000] {
            assert_eq!(run.accept(&[now]).unwrap_err(), "governed-issuance-expired");
        }
        assert_eq!(run.executor.executes, 0);
        assert!(run.store.records.is_empty());
    }

    #[test]
    fn historical_issuance_without_not_after_is_never_dispatched() {
        let mut run = Run::new(issuance(AG_ISSUANCE_SCHEMA_V1, None));
        assert_eq!(
            run.accept(&[T]).unwrap_err(),
            "governed-issuance-not-after-absent"
        );
        assert_eq!(run.resolver.calls, 0);
        assert!(run.store.records.is_empty());
    }

    #[test]
    fn standing_snapshot_bound_is_enforced_at_custody_and_at_execute() {
        // Inclusive at the declared bound, both at custody and at execute.
        let mut run = Run::new(v2());
        run.resolver.age_ms = MAX_STANDING_SNAPSHOT_AGE_MS;
        run.accept(&[T, T, T]).unwrap();
        assert_eq!(run.executor.executes, 1);

        // An older resolution (characterization e1') refuses before custody.
        let mut run = Run::new(v2());
        run.resolver.age_ms = MAX_STANDING_SNAPSHOT_AGE_MS + 1;
        assert_eq!(
            run.accept(&[T]).unwrap_err(),
            "governed-execution-standing-snapshot-stale"
        );
        assert!(run.store.records.is_empty());

        // Aging past the bound between resolution and custody refuses.
        let mut run = Run::new(v2());
        assert_eq!(
            run.accept(&[T, T + MAX_STANDING_SNAPSHOT_AGE_MS + 1])
                .unwrap_err(),
            "governed-execution-standing-snapshot-stale"
        );
        assert!(run.store.records.is_empty());

        // Aging past the bound between custody and execute never executes.
        let mut run = Run::new(v2());
        let custody = run
            .accept(&[T, T + 1, T + MAX_STANDING_SNAPSHOT_AGE_MS + 1])
            .unwrap();
        assert_eq!(run.executor.executes, 0);
        assert_eq!(
            run.evidence(),
            Some(
                standing_snapshot_exceeded_before_execute_evidence(&run.issuance, &custody)
                    .as_str()
            )
        );
    }

    #[test]
    fn grant_expiry_between_resolution_and_execute_is_enforced() {
        // Characterization c1: expiry after resolution, before custody.
        let mut run = Run::new(v2());
        run.resolver.lifetime_ms = 1_000;
        assert_eq!(
            run.accept(&[T, T + 1_000]).unwrap_err(),
            "governed-execution-standing-expired"
        );
        assert!(run.store.records.is_empty());
        // Characterization c2: expiry after custody, before execute.
        let mut run = Run::new(v2());
        run.resolver.lifetime_ms = 1_000;
        run.accept(&[T, T + 999, T + 1_000]).unwrap();
        assert_eq!(run.executor.executes, 0);
        assert_eq!(run.status(), Some("indeterminate"));
    }

    #[test]
    fn standing_refusals_stay_distinct_at_accept() {
        for (status, expected) in [
            (
                ExecutionStandingStatusV1::Revoked,
                "governed-execution-standing-revoked",
            ),
            (
                ExecutionStandingStatusV1::Superseded,
                "governed-execution-standing-superseded",
            ),
            (
                ExecutionStandingStatusV1::Expired,
                "governed-execution-standing-expired",
            ),
            (
                ExecutionStandingStatusV1::Absent,
                "governed-execution-standing-absent",
            ),
        ] {
            let mut run = Run::new(v2());
            run.resolver.status = status;
            assert_eq!(run.accept(&[T]).unwrap_err(), expected);
            assert!(run.store.records.is_empty());
        }
    }
}
