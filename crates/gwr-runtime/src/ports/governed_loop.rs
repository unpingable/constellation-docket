//! Narrow ports required by governed-loop coordination.

use crate::governed_loop::{
    AgIssuanceWireV1, CustodyRecordV1, DocketCustodyWireV1, ExecutionStandingRequestV1,
    ExecutionStandingResolutionV1, ExecutorBindingV1, ExecutorDispatchWireV1,
    ExecutorOutcomeWireV1, KnownOutcomeWireV1, SignedIssuanceEnvelopeWireV1,
};

pub trait GovernedCustodyStoreV1 {
    fn get(&mut self, issuance: &str) -> Result<Option<CustodyRecordV1>, String>;

    fn insert_custody(
        &mut self,
        envelope: &SignedIssuanceEnvelopeWireV1,
        issuance: &AgIssuanceWireV1,
        standing: &ExecutionStandingResolutionV1,
        custody: &DocketCustodyWireV1,
        executor_binding: &ExecutorBindingV1,
    ) -> Result<(), String>;

    fn record_known_outcome(
        &mut self,
        issuance: &str,
        custody: &DocketCustodyWireV1,
        receipt: &str,
        outcome: KnownOutcomeWireV1,
        at: u64,
    ) -> Result<(), String>;

    fn record_indeterminate(
        &mut self,
        issuance: &str,
        custody: &DocketCustodyWireV1,
        evidence: &str,
    ) -> Result<(), String>;
}

pub trait ExecutionStandingResolverV1 {
    fn resolve(
        &mut self,
        request: &ExecutionStandingRequestV1,
    ) -> Result<ExecutionStandingResolutionV1, String>;
}

pub trait GovernedExecutorV1 {
    fn resolve_binding(&mut self, expected_plan: &str) -> Result<ExecutorBindingV1, String>;

    fn require_binding(&mut self, expected: &ExecutorBindingV1) -> Result<(), String>;

    fn execute(
        &mut self,
        dispatch: &ExecutorDispatchWireV1,
    ) -> Result<ExecutorOutcomeWireV1, String>;

    fn reconcile(
        &mut self,
        dispatch: &ExecutorDispatchWireV1,
    ) -> Result<ExecutorOutcomeWireV1, String>;
}

pub trait GovernedClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, String>;
}
