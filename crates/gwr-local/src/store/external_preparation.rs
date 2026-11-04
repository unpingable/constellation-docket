//! External preparation is content custody plus bounded submitted testimony.
//! This local adapter adds no operations to the authority-neutral provider port.
//! JSON is ingress/inspection only; persistence uses explicit scalar columns.

use super::{codec::*, SqliteStore};
use crate::adapters::FsArtifactStore;
use gwr_core::digest::{Sha256Digest, Transcript};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::{PreparationRunId, WorkRequestId};
use gwr_core::preparation::{PreparationEnd, PreparationRun, PreparationStatus};
use gwr_core::work_request::{ClockReading, CommitHash};
use gwr_runtime::ports::adapters::{Clock, IdSource, ProvenanceSink};
use gwr_runtime::ports::labor_provider::{
    BoundedAssignment, LaborProvider, PreparationOutcome, PreparationReport, ProvenanceEntry,
    ProviderError,
};
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::preparation::{run_preparation, PreparationResult};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::process::Command;

pub const SCHEMA: &str = "gwr:external-candidate:v1";
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024;
pub const MAX_CANDIDATE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOrigin {
    pub kind: String,
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
}

/// The caller's origin and tool statements remain unverified testimony.
/// Request/basis equality checks prove consistency with operator-selected
/// coordinates, never independent origin, preparation history or useful output.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalManifest {
    pub schema: String,
    pub submission_id: String,
    pub request: String,
    pub repository_id: String,
    pub basis: String,
    pub content_sha256: String,
    pub content_length: u64,
    pub deadline_unix_ms: u64,
    pub origin: ExternalOrigin,
}

fn bounded_text(value: &str, limit: usize, field: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        return Err(format!("invalid or unbounded {field}"));
    }
    Ok(())
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl ExternalManifest {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err("external manifest exceeds byte bound".into());
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEMA {
            return Err("unsupported external schema".into());
        }
        bounded_text(&self.submission_id, 256, "submission identity")?;
        if !hex(&self.request, 32) {
            return Err("invalid external request identity".into());
        }
        if !self
            .repository_id
            .strip_prefix("repo-")
            .is_some_and(|v| hex(v, 32))
        {
            return Err("invalid external repository identity".into());
        }
        if !hex(&self.basis, 40) && !hex(&self.basis, 64) {
            return Err("external basis must be an exact commit object ID".into());
        }
        if !hex(&self.content_sha256, 64) {
            return Err("invalid content digest".into());
        }
        if self.content_length > MAX_CANDIDATE_BYTES {
            return Err("content length exceeds bound".into());
        }
        if self.deadline_unix_ms > i64::MAX as u64 {
            return Err("deadline exceeds native clock domain".into());
        }
        if !matches!(self.origin.kind.as_str(), "external-session" | "human") {
            return Err("unsupported origin kind".into());
        }
        bounded_text(&self.origin.identity, 4096, "origin identity")?;
        if let Some(tool) = &self.origin.tool {
            bounded_text(tool, 256, "origin tool")?;
        }
        Ok(())
    }

    /// Explicit versioned semantic transcript, independent of JSON layout.
    /// Optional-tool presence is a separate field; absence is never invented.
    pub fn binding_digest(&self, locator: &str, target_ref: &str) -> Sha256Digest {
        Transcript::new("gwr:external-preparation-binding:v1")
            .text_field("schema", &self.schema)
            .text_field("repository_id", &self.repository_id)
            .text_field("submission_id", &self.submission_id)
            .text_field("request", &self.request)
            .text_field("basis", &self.basis)
            .text_field("content_sha256", &self.content_sha256)
            .field("content_length", &self.content_length.to_be_bytes())
            .field("deadline_unix_ms", &self.deadline_unix_ms.to_be_bytes())
            .text_field("origin_kind", &self.origin.kind)
            .text_field("origin_identity", &self.origin.identity)
            .field(
                "origin_tool_present",
                &[u8::from(self.origin.tool.is_some())],
            )
            .text_field("origin_tool", self.origin.tool.as_deref().unwrap_or(""))
            .text_field("repository_locator", locator)
            .text_field("target_ref", target_ref)
            .finalize()
    }
}

/// Read at most bound+1 bytes even when a file grows after metadata inspection.
pub fn read_bounded(path: &Path, bound: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(bound + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > bound {
        return Err("external input exceeds byte bound".into());
    }
    Ok(bytes)
}

struct ExternalCandidate(Vec<u8>);
impl LaborProvider for ExternalCandidate {
    fn prepare(
        &mut self,
        _assignment: &BoundedAssignment,
    ) -> Result<PreparationReport, ProviderError> {
        Ok(PreparationReport {
            events: Vec::new(),
            outcome: PreparationOutcome::Candidate {
                patch: std::mem::take(&mut self.0),
            },
            provenance: Vec::new(),
        })
    }
}

// External origin is retained in its typed local binding, not disguised as
// provider testimony. This adapter deliberately emits no provider events.
struct NoProviderTestimony;
impl ProvenanceSink for NoProviderTestimony {
    fn record(
        &mut self,
        _run: PreparationRunId,
        entries: &[ProvenanceEntry],
    ) -> Result<(), String> {
        if entries.is_empty() {
            Ok(())
        } else {
            Err("unexpected provider testimony".into())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExternalPreparationView {
    pub schema: &'static str,
    pub preparation_run: String,
    pub candidate: String,
    pub status: &'static str,
    pub binding: ExternalManifest,
    pub repository_locator: String,
    pub target_ref: String,
    pub binding_digest: String,
    pub provenance_trust: &'static str,
}

impl SqliteStore {
    /// A writer transaction serializes repeated submissions. Native rows commit
    /// together. Process loss before commit rolls them back; content-addressed
    /// file bytes may remain, and are reverified before any future acceptance.
    #[allow(clippy::too_many_arguments)]
    pub fn import_external_candidate(
        &mut self,
        state: &Path,
        expected_request: WorkRequestId,
        expected_basis: &str,
        manifest: &ExternalManifest,
        patch: &[u8],
        clock: &dyn Clock,
        ids: &mut dyn IdSource,
    ) -> Result<ExternalPreparationView, String> {
        manifest.validate()?;
        if manifest.request != id16(expected_request.as_bytes()) {
            return Err("request mismatch".into());
        }
        if manifest.basis != expected_basis {
            return Err("basis mismatch".into());
        }
        if patch.len() as u64 != manifest.content_length {
            return Err("content length mismatch".into());
        }
        if Sha256Digest::of_bytes(patch).to_hex() != manifest.content_sha256 {
            return Err("content digest mismatch".into());
        }
        self.conn
            .execute_batch("BEGIN IMMEDIATE TRANSACTION")
            .map_err(|e| e.to_string())?;
        let result = self.import_external_in_transaction(
            state,
            expected_request,
            manifest,
            patch,
            clock,
            ids,
        );
        match result {
            Ok(view) => {
                if let Err(error) = self.conn.execute_batch("COMMIT") {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    return Err(error.to_string());
                }
                Ok(view)
            }
            Err(error) => {
                self.conn
                    .execute_batch("ROLLBACK")
                    .map_err(|rollback| format!("{error}; rollback failed: {rollback}"))?;
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn import_external_in_transaction(
        &mut self,
        state: &Path,
        request: WorkRequestId,
        manifest: &ExternalManifest,
        patch: &[u8],
        clock: &dyn Clock,
        ids: &mut dyn IdSource,
    ) -> Result<ExternalPreparationView, String> {
        let wr = self
            .get_work_request(request)
            .map_err(|e| format!("external request: {e:?}"))?;
        let repository_id = wr
            .repository_id
            .ok_or("request has no registered repository identity")?;
        if manifest.repository_id != repository_id.to_string() {
            return Err("repository mismatch".into());
        }
        GitRefEffect::validate_target_ref(wr.target_ref.as_str()).map_err(|e| format!("{e:?}"))?;
        let existing: Option<String> = self.conn.query_row(
            "SELECT preparation_run FROM external_preparation WHERE repository_id=?1 AND submission_id=?2",
            params![manifest.repository_id, manifest.submission_id], |r| r.get(0),
        ).optional().map_err(|e| e.to_string())?;
        // An exact committed repeat reads original custody even after its
        // ingestion deadline. It creates no new run and renews nothing.
        if let Some(run) = existing {
            let view = self.inspect_external_candidate(
                state,
                parse_id16(&run).map_err(|e| format!("{e:?}"))?,
            )?;
            if &view.binding != manifest {
                return Err("submission identity conflict".into());
            }
            return Ok(view);
        }
        let registration = self
            .get_repository(repository_id)
            .map_err(|e| format!("repository: {e:?}"))?;
        if registration.current_path() != Some(&wr.repository) {
            return Err("request repository locator is not current".into());
        }
        let now = clock.now();
        if now.0 > i64::MAX as u64 || now.0 > manifest.deadline_unix_ms {
            return Err("external import expired".into());
        }
        // Existence is a Git-owned fact; matching caller assertions alone are
        // insufficient. This does not prove that the worker used this basis.
        // `-C` alone does not select a repository when the calling session
        // carries Git-local selectors such as GIT_DIR or alternate object
        // directories. Ask Git for its own local variable vocabulary, then
        // let the registered path discover its normal .git/worktree metadata.
        let local_environment = Command::new("git")
            .args(["rev-parse", "--local-env-vars"])
            .output()
            .map_err(|e| format!("basis commit environment check: {e}"))?;
        if !local_environment.status.success() {
            return Err("basis commit environment check refused".into());
        }
        let variables = std::str::from_utf8(&local_environment.stdout)
            .map_err(|_| "basis commit environment vocabulary is not UTF-8")?;
        let mut lookup = Command::new("git");
        for variable in variables.lines() {
            lookup.env_remove(variable);
        }
        let check = lookup
            .arg("--no-replace-objects")
            .arg("-C")
            .arg(wr.repository.as_str())
            .args(["cat-file", "-t", &manifest.basis])
            .output()
            .map_err(|e| format!("basis commit check: {e}"))?;
        if !check.status.success() || check.stdout != b"commit\n" {
            return Err("basis commit absent from registered repository".into());
        }
        let run = PreparationRun {
            id: PreparationRunId::from_bytes(ids.fresh16()),
            work_request: request,
            started_at: now,
            deadline: ClockReading(manifest.deadline_unix_ms),
            status: PreparationStatus::Running,
        };
        self.create_preparation_run(&run)
            .map_err(|e| format!("{e:?}"))?;
        let assignment = BoundedAssignment {
            preparation_run: run.id,
            goal: wr.goal,
            basis: CommitHash::new(&manifest.basis),
            workspace: state.join("external-content-no-provider-workspace"),
            deadline: run.deadline,
        };
        let mut artifacts = FsArtifactStore::new(state.join("artifacts"))?;
        let result = run_preparation(
            self,
            &mut ExternalCandidate(patch.to_vec()),
            &run,
            &assignment,
            &mut artifacts,
            &mut NoProviderTestimony,
            clock,
            ids,
        )
        .map_err(|e| format!("{e:?}"))?;
        let artifact = match result {
            PreparationResult::CandidateIngested { artifact, .. } => artifact,
            other => {
                return Err(format!(
                    "external import did not ingest candidate: {other:?}"
                ))
            }
        };
        // Verify actual retained bytes before accepting a native binding. This
        // also refuses a truncated pre-existing content-addressed file.
        if read_bounded(
            &state
                .join("artifacts")
                .join(artifact.content_digest.to_hex()),
            MAX_CANDIDATE_BYTES,
        )? != patch
        {
            return Err("retained content mismatch".into());
        }
        let digest = manifest
            .binding_digest(wr.repository.as_str(), wr.target_ref.as_str())
            .to_hex();
        self.conn.execute(
            "INSERT INTO external_preparation (repository_id,submission_id,schema_version,work_request,basis,content_digest,content_len,deadline,origin_kind,origin_identity,origin_tool,repository_locator,target_ref,binding_digest,preparation_run,candidate) VALUES (?1,?2,1,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![manifest.repository_id,manifest.submission_id,manifest.request,manifest.basis,manifest.content_sha256,manifest.content_length as i64,manifest.deadline_unix_ms as i64,manifest.origin.kind,manifest.origin.identity,manifest.origin.tool,wr.repository.as_str(),wr.target_ref.as_str(),digest,id16(run.id.as_bytes()),id16(artifact.id.as_bytes())]
        ).map_err(|e| e.to_string())?;
        self.inspect_external_candidate(state, run.id)
    }

    /// Caller opens an existing query-only store. No migration, inferred
    /// origin, provider invocation, authority operation or sidecar write.
    pub fn inspect_external_candidate(
        &mut self,
        state: &Path,
        run: PreparationRunId,
    ) -> Result<ExternalPreparationView, String> {
        let (version, binding, locator, target, digest, candidate): (i64,ExternalManifest,String,String,String,String) = self.conn.query_row(
            "SELECT schema_version,submission_id,work_request,repository_id,basis,content_digest,content_len,deadline,origin_kind,origin_identity,origin_tool,repository_locator,target_ref,binding_digest,candidate FROM external_preparation WHERE preparation_run=?1",
            [id16(run.as_bytes())], |r| Ok((r.get(0)?, ExternalManifest {
                schema: SCHEMA.into(), submission_id:r.get(1)?,request:r.get(2)?,repository_id:r.get(3)?,basis:r.get(4)?,content_sha256:r.get(5)?,content_length:r.get::<_,u64>(6)?,deadline_unix_ms:r.get::<_,u64>(7)?,origin:ExternalOrigin{kind:r.get(8)?,identity:r.get(9)?,tool:r.get(10)?}
            },r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?))
        ).map_err(|e| format!("external binding unavailable or corrupt: {e}"))?;
        binding
            .validate()
            .map_err(|e| format!("corrupt external binding: {e}"))?;
        if version != 1 || binding.binding_digest(&locator, &target).to_hex() != digest {
            return Err("corrupt external binding digest".into());
        }
        let native_run = self
            .get_preparation_run(run)
            .map_err(|e| format!("corrupt external run: {e:?}"))?;
        let artifact = self
            .get_candidate(
                parse_id16(&candidate).map_err(|e| format!("corrupt external candidate: {e:?}"))?,
            )
            .map_err(|e| format!("corrupt external candidate: {e:?}"))?;
        let wr = self
            .get_work_request(native_run.work_request)
            .map_err(|e| format!("corrupt external request: {e:?}"))?;
        if native_run.status != PreparationStatus::Ended(PreparationEnd::CandidateProduced)
            || id16(native_run.work_request.as_bytes()) != binding.request
            || native_run.deadline.0 != binding.deadline_unix_ms
            || artifact.preparation_run != run
            || artifact.content_digest.to_hex() != binding.content_sha256
            || artifact.content_len != binding.content_length
            || wr.repository_id.map(|id| id.to_string()).as_deref() != Some(&binding.repository_id)
            || wr.repository.as_str() != locator
            || wr.target_ref.as_str() != target
        {
            return Err("corrupt external native binding".into());
        }
        // Do not create artifacts/ on this query path. A missing file is a
        // refusal; verify bounded actual bytes rather than trusting SQL alone.
        let bytes = read_bounded(
            &state.join("artifacts").join(&binding.content_sha256),
            MAX_CANDIDATE_BYTES,
        )?;
        if bytes.len() as u64 != binding.content_length
            || Sha256Digest::of_bytes(&bytes).to_hex() != binding.content_sha256
        {
            return Err("corrupt external artifact".into());
        }
        Ok(ExternalPreparationView {
            schema: "gwr:external-preparation:v1",
            preparation_run: id16(run.as_bytes()),
            candidate,
            status: "candidate_produced",
            binding,
            repository_locator: locator,
            target_ref: target,
            binding_digest: digest,
            provenance_trust: "submitted_testimony",
        })
    }
}
