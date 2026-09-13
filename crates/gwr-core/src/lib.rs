//! Pure deterministic types and transition rules for the governed work runtime.
//!
//! This crate owns typed identities, digest transcripts, immutable value objects,
//! lifecycle validation, reservation and standing-use rules, bridge admission,
//! receipt construction from established facts, recovery-resolution validation,
//! and reconciliation rules. It performs no I/O.

#![forbid(unsafe_code)]

pub mod authorization;
pub mod bridge;
pub mod campaign;
pub mod digest;
pub mod domain;
pub mod effect_spec;
pub mod ids;
pub mod lifecycle;
pub mod observation_plan;
pub mod outcome;
pub mod preparation;
pub mod prepared_attempt;
pub mod receipt;
pub mod reconciliation;
pub mod recovery;
pub mod ref_continuity;
pub mod refusal;
pub mod repository;
pub mod work_request;
