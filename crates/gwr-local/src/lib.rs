//! Local adapters: SQLite, filesystem artifacts, provider adapters, Git broker,
//! observations, CLI, clocks, and identity generation.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod authz_intake;
pub mod broker;
pub mod build_info;
pub mod campaign_export;
pub mod capabilities;
pub mod governed_loop;
pub mod local_execution_standing;
pub mod observe;
pub mod providers;
pub mod recover;
mod source_commit;
pub mod store;
#[cfg(test)]
mod test_support;

pub use gwr_runtime::services::preparation::REPORTED_DIGEST_LABEL;
