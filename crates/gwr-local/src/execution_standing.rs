//! Owner-installed execution-standing projection. This adapter has no grant authority.
use gwr_runtime::governed_loop::{
    validate_issuance, validate_standing, ExecutionStandingRequestV1,
    ExecutionStandingResolutionV1, STANDING_REQUEST_SCHEMA_V1,
};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

const LIMIT: u64 = 1_048_576;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingEnrollmentV1 {
    pub schema: String,
    pub principal: String,
    pub projection: std::path::PathBuf,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerStandingProjectionV1 {
    pub schema: String,
    pub principal: String,
    /// Owner-assigned snapshot identity, never interpreted as authority by Docket.
    pub generation: String,
    pub resolution: ExecutionStandingResolutionV1,
}

/// Preserve an exactly bound, current owner response. No fallback or grant synthesis.
pub fn project(
    enrollment: &StandingEnrollmentV1,
    owner: &OwnerStandingProjectionV1,
    request: &ExecutionStandingRequestV1,
) -> Result<ExecutionStandingResolutionV1, String> {
    if enrollment.schema != "docket.execution-standing-enrollment/v1"
        || enrollment.principal.trim().is_empty()
        || owner.schema != "docket.owner-execution-standing-projection/v1"
        || owner.principal != enrollment.principal
        || owner.generation.trim().is_empty()
        || request.schema != STANDING_REQUEST_SCHEMA_V1
    {
        return Err("execution-standing-enrollment-or-principal".into());
    }
    validate_issuance(&request.issuance)?;
    validate_standing(&request.issuance, &owner.resolution, request.now_unix_ms)?;
    // Also retain the runtime's distinct-instrument check before returning bytes.
    gwr_runtime::governed_loop::make_custody(
        &request.issuance,
        &owner.resolution,
        request.now_unix_ms,
    )?;
    Ok(owner.resolution.clone())
}

/// Read a bounded root-controlled regular file, excluding caller-selected paths,
/// symlinks, writable ancestors and writable files. Root is the enrolled authority.
pub fn read_owner_file(path: &Path) -> Result<Vec<u8>, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("execution-standing-owner-path".into());
    }
    for ancestor in path.ancestors().skip(1) {
        let m = std::fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("execution-standing-owner-directory".into());
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    let m = file.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.len() > LIMIT {
        return Err("execution-standing-owner-file".into());
    }
    read_bounded(file)
}

pub fn read_bounded(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() as u64 > LIMIT {
        return Err("execution-standing-document-bound".into());
    }
    Ok(bytes)
}
