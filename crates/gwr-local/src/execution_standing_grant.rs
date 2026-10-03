//! Owner-enrolled bounded execution-standing grant (DK-02 amendment, 2026-10-03).
//!
//! The owner installs one root-owned grant document and pins its exact bytes by
//! digest in the resolver's root-owned enrollment. For a presented AG issuance
//! this adapter derives exactly one standing, `H(grant ‖ issuance)`, bound to
//! that issuance, campaign, occurrence, subject and scope, and only while every
//! grant constraint holds. Uses are counted in a root-owned journal of
//! `O_EXCL`-created entries. The adapter never opens the grant for writing and
//! has no path by which a caller can enlarge it. Docket's binding, currentness
//! and one-custody law (`validate_standing`, `make_custody`, the custody store)
//! is unchanged and still applies to the derived answer.
use crate::execution_standing::{read_bounded, read_trusted_file, OwnerTrust};
use gwr_runtime::governed_loop::{
    hash_domain, make_custody, require_digest, validate_issuance, validate_standing,
    AgIssuanceWireV1, ExecutionStandingRequestV1, ExecutionStandingResolutionV1,
    ExecutionStandingStatusV1, STANDING_REQUEST_SCHEMA_V1, STANDING_RESOLUTION_SCHEMA_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

pub const GRANT_ENROLLMENT_SCHEMA_V1: &str = "docket.execution-standing-grant-enrollment/v1";
pub const GRANT_SCHEMA_V1: &str = "docket.owner-execution-standing-grant/v1";
pub const GRANT_USE_SCHEMA_V1: &str = "docket.execution-standing-grant-use/v1";
/// Upper bound on `max_uses`; journal entry names carry six decimal digits.
pub const MAX_GRANT_USES: u32 = 10_000;
/// Upper bound on the lifetime of one derived standing answer.
pub const MAX_GRANT_STANDING_TTL_MS: u64 = 600_000;

/// Root-owned file beside the installed resolver. It names the one enrolled
/// grant and pins its exact bytes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantEnrollmentV1 {
    pub schema: String,
    pub principal: String,
    pub grant: PathBuf,
    /// `sha256:` + lowercase hex of the exact grant file bytes (`sha256sum`).
    pub grant_sha256: String,
}

/// The owner's bounded grant. Docket reads it; it never writes it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerStandingGrantV1 {
    pub schema: String,
    pub grant_id: String,
    pub principal: String,
    pub subject: String,
    pub scope: String,
    pub work_schema: String,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_uses: u32,
    pub standing_ttl_ms: u64,
    /// Owner revocation reference: the grant is revoked while anything exists here.
    pub revocation_marker: PathBuf,
    /// Root-owned directory dedicated to this grant's use journal.
    pub use_journal: PathBuf,
}

/// One durable, `O_EXCL`-created use of the grant by exactly one AG issuance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantUseV1 {
    pub schema: String,
    pub grant: String,
    pub grant_id: String,
    pub use_index: u32,
    /// `sha256:` of the previous entry's exact bytes; `None` for the first use.
    pub previous: Option<String>,
    pub issuance: String,
    pub campaign: String,
    pub occurrence: String,
    pub subject: String,
    pub scope: String,
    pub work_schema: String,
    pub derived_at_unix_ms: u64,
}

#[derive(Serialize)]
struct StandingBasis<'a> {
    grant: &'a str,
    issuance: &'a str,
}

#[derive(Serialize)]
struct CurrentnessBasis<'a> {
    grant: &'a str,
    grant_id: &'a str,
    use_index: u32,
    use_entry: &'a str,
    resolved_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

/// `sha256:` + lowercase hex of exact bytes, as printed by `sha256sum`.
pub fn sha256_digest(bytes: &[u8]) -> String {
    let mut out = String::from("sha256:");
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Derive one exactly bound standing for the presented issuance from the
/// enrolled grant, consuming at most one use for a new issuance and none for
/// an issuance already journaled. Every refusal returns no standing.
pub fn derive_standing(
    enrollment: &GrantEnrollmentV1,
    trust: &OwnerTrust,
    request: &ExecutionStandingRequestV1,
) -> Result<ExecutionStandingResolutionV1, String> {
    if enrollment.schema != GRANT_ENROLLMENT_SCHEMA_V1 || enrollment.principal.trim().is_empty() {
        return Err("execution-standing-grant-enrollment".into());
    }
    require_digest(&enrollment.grant_sha256, "grant pin")
        .map_err(|_| "execution-standing-grant-enrollment".to_owned())?;
    let bytes = read_trusted_file(&enrollment.grant, trust)?;
    let grant_digest = sha256_digest(&bytes);
    if grant_digest != enrollment.grant_sha256 {
        return Err("execution-standing-grant-digest-mismatch".into());
    }
    let grant: OwnerStandingGrantV1 = serde_json::from_slice(&bytes)
        .map_err(|_| "execution-standing-grant-document".to_owned())?;
    validate_grant(&grant, &enrollment.principal)?;
    if request.schema != STANDING_REQUEST_SCHEMA_V1 {
        return Err("execution-standing-request-schema".into());
    }
    validate_issuance(&request.issuance)?;
    let issuance = &request.issuance;
    let now = request.now_unix_ms;
    require_not_revoked(&grant.revocation_marker, trust)?;
    if now < grant.not_before_unix_ms {
        return Err("execution-standing-grant-not-yet-valid".into());
    }
    if now >= grant.expires_at_unix_ms {
        return Err("execution-standing-grant-expired".into());
    }
    if issuance.subject != grant.subject {
        return Err("execution-standing-grant-subject-mismatch".into());
    }
    if issuance.scope != grant.scope {
        return Err("execution-standing-grant-scope-mismatch".into());
    }
    if issuance.work_schema != grant.work_schema {
        return Err("execution-standing-grant-work-schema-mismatch".into());
    }
    let (entry, entry_digest) = claim_use(&grant, &grant_digest, trust, issuance, now)?;
    let resolution = resolution_for(&grant, &grant_digest, &entry, &entry_digest)?;
    // The derived answer must satisfy the unchanged runtime law before it leaves.
    validate_standing(issuance, &resolution, now)?;
    make_custody(issuance, &resolution, now)?;
    Ok(resolution)
}

fn validate_grant(grant: &OwnerStandingGrantV1, principal: &str) -> Result<(), String> {
    let bad = grant.schema != GRANT_SCHEMA_V1
        || grant.principal != principal
        || !token(&grant.grant_id)
        || require_digest(&grant.subject, "grant subject").is_err()
        || require_digest(&grant.scope, "grant scope").is_err()
        || !token(&grant.work_schema)
        || grant.not_before_unix_ms >= grant.expires_at_unix_ms
        || grant.max_uses == 0
        || grant.max_uses > MAX_GRANT_USES
        || grant.standing_ttl_ms == 0
        || grant.standing_ttl_ms > MAX_GRANT_STANDING_TTL_MS
        || !grant.revocation_marker.is_absolute()
        || !grant.use_journal.is_absolute();
    if bad {
        return Err("execution-standing-grant-document".into());
    }
    Ok(())
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
}

/// Revoked while anything exists at the marker. The marker's directory must be
/// owner-trusted so that a caller cannot hide a revocation by replacing it.
fn require_not_revoked(marker: &Path, trust: &OwnerTrust) -> Result<(), String> {
    trust
        .require_trusted_ancestors(marker)
        .map_err(|_| "execution-standing-grant-revocation-reference".to_owned())?;
    match std::fs::symlink_metadata(marker) {
        Ok(_) => Err("execution-standing-grant-revoked".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("execution-standing-grant-revocation-reference".into()),
    }
}

fn entry_name(index: u32) -> String {
    format!("use-{index:06}.json")
}

fn parse_entry_name(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("use-")?.strip_suffix(".json")?;
    if digits.len() != 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn claim_use(
    grant: &OwnerStandingGrantV1,
    grant_digest: &str,
    trust: &OwnerTrust,
    issuance: &AgIssuanceWireV1,
    now: u64,
) -> Result<(GrantUseV1, String), String> {
    let dir = grant.use_journal.as_path();
    let journal_error = |_| "execution-standing-grant-journal-directory".to_owned();
    trust
        .require_trusted_ancestors(dir)
        .map_err(journal_error)?;
    trust
        .require_trusted_directory(dir)
        .map_err(journal_error)?;
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(dir)
        .map_err(|_| "execution-standing-grant-journal-directory".to_owned())?;
    // Serialize derivations; the lock is released when `handle` drops.
    handle
        .lock()
        .map_err(|_| "execution-standing-grant-journal-lock".to_owned())?;
    let entries = read_journal(dir, grant, grant_digest, trust)?;
    if let Some((entry, digest)) = entries
        .iter()
        .find(|(e, _)| e.issuance == issuance.issuance)
    {
        if entry.campaign != issuance.key.campaign || entry.occurrence != issuance.key.occurrence {
            return Err("execution-standing-grant-journal-binding".into());
        }
        return Ok((entry.clone(), digest.clone()));
    }
    let used = u32::try_from(entries.len())
        .map_err(|_| "execution-standing-grant-journal-bound".to_owned())?;
    if used >= grant.max_uses {
        return Err("execution-standing-grant-exhausted".into());
    }
    let previous = entries.last();
    if previous.is_some_and(|(e, _)| now < e.derived_at_unix_ms) {
        return Err("execution-standing-grant-clock-regression".into());
    }
    let entry = GrantUseV1 {
        schema: GRANT_USE_SCHEMA_V1.into(),
        grant: grant_digest.into(),
        grant_id: grant.grant_id.clone(),
        use_index: used + 1,
        previous: previous.map(|(_, digest)| digest.clone()),
        issuance: issuance.issuance.clone(),
        campaign: issuance.key.campaign.clone(),
        occurrence: issuance.key.occurrence.clone(),
        subject: issuance.subject.clone(),
        scope: issuance.scope.clone(),
        work_schema: issuance.work_schema.clone(),
        derived_at_unix_ms: now,
    };
    let bytes = serde_json::to_vec(&entry).map_err(|e| e.to_string())?;
    let write_error = |_| "execution-standing-grant-journal-write".to_owned();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(entry_name(entry.use_index)))
        .map_err(write_error)?;
    file.write_all(&bytes).map_err(write_error)?;
    file.sync_all().map_err(write_error)?;
    handle.sync_all().map_err(write_error)?;
    Ok((entry, sha256_digest(&bytes)))
}

/// Read and verify the whole journal: only contiguous `use-NNNNNN.json` entries
/// for this exact grant, owner-trusted, canonical, hash-chained, distinct
/// issuances and nondecreasing derivation times. Anything else fails closed.
fn read_journal(
    dir: &Path,
    grant: &OwnerStandingGrantV1,
    grant_digest: &str,
    trust: &OwnerTrust,
) -> Result<Vec<(GrantUseV1, String)>, String> {
    let tamper = |what: &str| format!("execution-standing-grant-journal-{what}");
    let mut indices = Vec::new();
    for item in std::fs::read_dir(dir).map_err(|_| tamper("directory"))? {
        let item = item.map_err(|_| tamper("directory"))?;
        let index = item
            .file_name()
            .to_str()
            .and_then(parse_entry_name)
            .filter(|i| (1..=grant.max_uses).contains(i))
            .ok_or_else(|| tamper("unexpected-entry"))?;
        indices.push(index);
    }
    indices.sort_unstable();
    if indices.iter().zip(1..).any(|(&have, want)| have != want) {
        return Err(tamper("gap"));
    }
    let mut entries: Vec<(GrantUseV1, String)> = Vec::with_capacity(indices.len());
    for index in indices {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir.join(entry_name(index)))
            .map_err(|_| tamper("entry-owner"))?;
        trust
            .require_trusted_opened(&file)
            .map_err(|_| tamper("entry-owner"))?;
        let bytes = read_bounded(file).map_err(|_| tamper("entry-document"))?;
        let entry: GrantUseV1 =
            serde_json::from_slice(&bytes).map_err(|_| tamper("entry-document"))?;
        if serde_json::to_vec(&entry).map_err(|_| tamper("entry-document"))? != bytes {
            return Err(tamper("entry-noncanonical"));
        }
        if entry.grant != grant_digest || entry.grant_id != grant.grant_id {
            return Err(tamper("foreign-grant"));
        }
        let previous = entries.last();
        let bound = entry.schema == GRANT_USE_SCHEMA_V1
            && entry.use_index == index
            && entry.previous.as_deref() == previous.map(|(_, digest)| digest.as_str())
            && require_digest(&entry.issuance, "journal issuance").is_ok()
            && require_digest(&entry.campaign, "journal campaign").is_ok()
            && entry.subject == grant.subject
            && entry.scope == grant.scope
            && entry.work_schema == grant.work_schema
            && entry.derived_at_unix_ms >= grant.not_before_unix_ms
            && entry.derived_at_unix_ms < grant.expires_at_unix_ms
            && previous.is_none_or(|(p, _)| p.derived_at_unix_ms <= entry.derived_at_unix_ms)
            && entries.iter().all(|(e, _)| e.issuance != entry.issuance);
        if !bound {
            return Err(tamper("entry-binding"));
        }
        entries.push((entry, sha256_digest(&bytes)));
    }
    Ok(entries)
}

fn resolution_for(
    grant: &OwnerStandingGrantV1,
    grant_digest: &str,
    entry: &GrantUseV1,
    entry_digest: &str,
) -> Result<ExecutionStandingResolutionV1, String> {
    let execution_standing = hash_domain(
        "docket.grant-execution-standing/v1",
        &encode(&StandingBasis {
            grant: grant_digest,
            issuance: &entry.issuance,
        })?,
    );
    let resolved_at = entry.derived_at_unix_ms;
    let expires_at = resolved_at
        .saturating_add(grant.standing_ttl_ms)
        .min(grant.expires_at_unix_ms);
    let currentness = hash_domain(
        "docket.grant-execution-standing-currentness/v1",
        &encode(&CurrentnessBasis {
            grant: grant_digest,
            grant_id: &grant.grant_id,
            use_index: entry.use_index,
            use_entry: entry_digest,
            resolved_at_unix_ms: resolved_at,
            expires_at_unix_ms: expires_at,
        })?,
    );
    let mut resolution = ExecutionStandingResolutionV1 {
        schema: STANDING_RESOLUTION_SCHEMA_V1.into(),
        resolution: String::new(),
        currentness,
        execution_standing,
        issuance: entry.issuance.clone(),
        campaign: entry.campaign.clone(),
        occurrence: entry.occurrence.clone(),
        subject: entry.subject.clone(),
        scope: entry.scope.clone(),
        status: ExecutionStandingStatusV1::Current,
        resolved_at_unix_ms: resolved_at,
        expires_at_unix_ms: expires_at,
    };
    let mut basis = serde_json::to_value(&resolution).map_err(|e| e.to_string())?;
    if let Some(object) = basis.as_object_mut() {
        object.remove("resolution");
    }
    resolution.resolution = hash_domain(
        "docket.grant-execution-standing-resolution/v1",
        &serde_json::to_vec(&basis).map_err(|e| e.to_string())?,
    );
    Ok(resolution)
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}

/// Open the enrollment beside an installed resolver executable.
pub fn enrollment_beside(
    executable: &Path,
    trust: &OwnerTrust,
) -> Result<GrantEnrollmentV1, String> {
    let path = executable.with_file_name("docket-standing-grant-resolver.enrollment.json");
    serde_json::from_slice(&read_trusted_file(&path, trust)?)
        .map_err(|_| "execution-standing-grant-enrollment".to_owned())
}
