//! Owner-installed execution-standing projection. This adapter has no grant authority.
use gwr_runtime::governed_loop::{
    validate_issuance, validate_standing, ExecutionStandingRequestV1,
    ExecutionStandingResolutionV1, STANDING_REQUEST_SCHEMA_V1,
};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

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
    read_trusted_file(path, &OwnerTrust::root())
}

/// Who may own enrolled owner files and their ancestors. Installed resolvers use
/// only [`OwnerTrust::root`]; the anchored form exists for unprivileged tests.
#[derive(Clone, Debug)]
pub struct OwnerTrust {
    uid: u32,
    anchor: PathBuf,
}

impl OwnerTrust {
    /// uid 0 owns the file and every ancestor up to `/`.
    pub fn root() -> Self {
        Self {
            uid: 0,
            anchor: PathBuf::from("/"),
        }
    }

    /// Unprivileged test trust: `uid` owns the file and its ancestors up to and
    /// including `anchor`; ancestors above `anchor` are not examined.
    pub fn anchored_for_tests(uid: u32, anchor: impl Into<PathBuf>) -> Self {
        Self {
            uid,
            anchor: anchor.into(),
        }
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Absolute, `..`-free path below the anchor whose ancestors are trusted
    /// directories (owned by the trusted uid, no group/other write, no symlink).
    pub fn require_trusted_ancestors(&self, path: &Path) -> Result<(), String> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || !path.starts_with(&self.anchor)
        {
            return Err("execution-standing-owner-path".into());
        }
        for ancestor in path.ancestors().skip(1) {
            self.require_trusted_directory(ancestor)?;
            if ancestor == self.anchor {
                break;
            }
        }
        Ok(())
    }

    pub fn require_trusted_directory(&self, path: &Path) -> Result<(), String> {
        let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !m.is_dir() || m.uid() != self.uid || m.mode() & 0o022 != 0 {
            return Err("execution-standing-owner-directory".into());
        }
        Ok(())
    }

    /// Opened-file check: a regular file owned by the trusted uid,
    /// without group/other write, within the document bound.
    pub fn require_trusted_opened(&self, file: &File) -> Result<(), String> {
        let m = file.metadata().map_err(|e| e.to_string())?;
        if !m.is_file() || m.uid() != self.uid || m.mode() & 0o022 != 0 || m.len() > LIMIT {
            return Err("execution-standing-owner-file".into());
        }
        Ok(())
    }
}

/// [`read_owner_file`] under an explicit owner trust.
pub fn read_trusted_file(path: &Path, trust: &OwnerTrust) -> Result<Vec<u8>, String> {
    trust.require_trusted_ancestors(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    trust.require_trusted_opened(&file)?;
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
