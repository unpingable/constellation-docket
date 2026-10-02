//! Local adapters: SQLite, filesystem artifacts, provider adapters, Git broker,
//! observations, CLI, clocks, and identity generation.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod authz_intake;
pub mod broker;
pub mod campaign_export;
pub mod capabilities;
pub mod governed_loop;
pub mod execution_standing;
pub mod observe;
pub mod providers;
pub mod recover;
pub mod stage0_guest;
pub mod stage1a_vm;
pub mod stage1b_vm;
pub mod stage1d_session;
pub mod store;

pub use gwr_runtime::services::preparation::REPORTED_DIGEST_LABEL;
