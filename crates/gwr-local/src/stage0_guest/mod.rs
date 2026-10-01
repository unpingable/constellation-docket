//! Experimental VM-guest Stage-0 seam.
//!
//! This module is deliberately local and fixed-function. It is not a generic
//! guest framework and owns no authorization or Docket custody semantics.

pub mod protocol;
pub mod proxy;
pub mod state;

pub use protocol::{
    GuestOutcomeV1, GuestRequestV1, GuestResponseV1, WorkBindingV1, GUEST_PROTOCOL_V1,
    STAGE0_WORK_SCHEMA_V1,
};
