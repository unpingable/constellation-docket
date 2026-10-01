//! Fault-directed private state for the fixed Stage-0 result cell.

use super::protocol::{transcript_digest, GuestOutcomeV1, WorkBindingV1};
use gwr_runtime::governed_loop::require_digest;
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const JOURNAL_MAGIC: &[u8; 8] = b"DGST0J01";
const CELL_MAGIC: &[u8; 8] = b"DGST0C01";
const MAX_STATE_BYTES: u64 = 16 * 1024;
const CHECKSUM_BYTES: usize = 71;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultCutV1 {
    None,
    BeforeReservation,
    AfterReservation,
    AfterEffect,
    AfterCommit,
}

impl FaultCutV1 {
    pub fn from_environment() -> Result<Self, String> {
        match std::env::var("DOCKET_STAGE0_FAULT").as_deref() {
            Err(std::env::VarError::NotPresent) | Ok("") | Ok("none") => Ok(Self::None),
            Ok("before_reservation") => Ok(Self::BeforeReservation),
            Ok("after_reservation") => Ok(Self::AfterReservation),
            Ok("after_effect") => Ok(Self::AfterEffect),
            Ok("after_commit") => Ok(Self::AfterCommit),
            Ok(_) => Err("stage0-unknown-fault-cut".to_owned()),
            Err(error) => Err(format!("stage0-fault-environment:{error}")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectResultV1 {
    pub outcome: GuestOutcomeV1,
    pub receipt: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalStateV1 {
    Reserved = 1,
    Effected = 2,
    Committed = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JournalV1 {
    state: JournalStateV1,
    pre_generation: u64,
    post_generation: u64,
    pre_cell_identity: String,
    binding: WorkBindingV1,
    receipt: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CellV1 {
    generation: u64,
    binding: WorkBindingV1,
}

enum StoredV1<T> {
    Missing,
    Valid(T, String),
    Corrupt(String),
}

impl<T> StoredV1<T> {
    fn evidence_identity(&self) -> &str {
        match self {
            Self::Missing => "missing",
            Self::Valid(_, identity) | Self::Corrupt(identity) => identity,
        }
    }
}

pub fn execute(
    state_directory: &Path,
    binding: &WorkBindingV1,
    fault: FaultCutV1,
) -> Result<EffectResultV1, String> {
    binding.validate()?;
    validate_state_directory(state_directory)?;
    let journals = state_directory.join("attempts");
    ensure_private_directory(&journals)?;

    let lock_path = state_directory.join("effect.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|error| format!("stage0-lock-open:{error}"))?;
    lock.try_lock()
        .map_err(|error| format!("stage0-concurrent-execute-refusal:{error}"))?;

    let journal_path = journal_path(&journals, &binding.attempt)?;
    let existing = read_journal(&journal_path)?;
    match existing {
        StoredV1::Valid(journal, _) => {
            if journal.binding != *binding {
                return Err("stage0-conflicting-replay".to_owned());
            }
            let cell = read_cell(&state_directory.join("result.cell"))?;
            return classify(&journal, &cell);
        }
        StoredV1::Corrupt(identity) => {
            return Ok(indeterminate(binding, &identity, "journal-corrupt"));
        }
        StoredV1::Missing => {}
    }

    if fault == FaultCutV1::BeforeReservation {
        return Err("stage0-injected-process-death:before-reservation".to_owned());
    }

    let cell_path = state_directory.join("result.cell");
    let cell = read_cell(&cell_path)?;
    let (pre_generation, pre_cell_identity) = match &cell {
        StoredV1::Missing => (0, "missing".to_owned()),
        StoredV1::Valid(cell, identity) => (cell.generation, identity.clone()),
        StoredV1::Corrupt(_) => return Err("stage0-cell-corrupt-before-reservation".to_owned()),
    };
    let mut journal = JournalV1 {
        state: JournalStateV1::Reserved,
        pre_generation,
        post_generation: 0,
        pre_cell_identity,
        binding: binding.clone(),
        receipt: String::new(),
    };
    persist_journal(&journal_path, &journal)?;
    if fault == FaultCutV1::AfterReservation {
        return Err("stage0-injected-process-death:after-reservation".to_owned());
    }

    let post_generation = pre_generation
        .checked_add(1)
        .ok_or_else(|| "stage0-cell-generation-exhausted".to_owned())?;
    persist_cell(
        &cell_path,
        &CellV1 {
            generation: post_generation,
            binding: binding.clone(),
        },
    )?;
    if fault == FaultCutV1::AfterEffect {
        return Err("stage0-injected-process-death:after-effect".to_owned());
    }

    journal.state = JournalStateV1::Effected;
    journal.post_generation = post_generation;
    persist_journal(&journal_path, &journal)?;

    journal.state = JournalStateV1::Committed;
    journal.receipt = success_receipt(binding, post_generation);
    persist_journal(&journal_path, &journal)?;
    if fault == FaultCutV1::AfterCommit {
        return Err("stage0-injected-process-death:after-commit".to_owned());
    }

    Ok(EffectResultV1 {
        outcome: GuestOutcomeV1::Success,
        receipt: journal.receipt,
    })
}

pub fn reconcile(
    state_directory: &Path,
    binding: &WorkBindingV1,
) -> Result<EffectResultV1, String> {
    binding.validate()?;
    validate_state_directory(state_directory)?;
    let attempts = state_directory.join("attempts");
    if !validate_attempt_directory(&attempts)? {
        return Err("stage0-reconcile-missing-attempt".to_owned());
    }
    let journal_path = journal_path(&attempts, &binding.attempt)?;
    let journal = read_journal(&journal_path)?;
    match journal {
        StoredV1::Missing => Err("stage0-reconcile-missing-attempt".to_owned()),
        StoredV1::Corrupt(identity) => Ok(indeterminate(binding, &identity, "journal-corrupt")),
        StoredV1::Valid(journal, _) => {
            if journal.binding != *binding {
                return Err("stage0-conflicting-replay".to_owned());
            }
            let cell = read_cell(&state_directory.join("result.cell"))?;
            classify(&journal, &cell)
        }
    }
}

fn classify(journal: &JournalV1, cell: &StoredV1<CellV1>) -> Result<EffectResultV1, String> {
    if matches!(cell, StoredV1::Corrupt(_)) {
        return Ok(indeterminate(
            &journal.binding,
            cell.evidence_identity(),
            "cell-corrupt",
        ));
    }
    match journal.state {
        JournalStateV1::Committed => {
            require_digest(&journal.receipt, "stage0 committed receipt")?;
            Ok(EffectResultV1 {
                outcome: GuestOutcomeV1::Success,
                receipt: journal.receipt.clone(),
            })
        }
        JournalStateV1::Effected => Ok(EffectResultV1 {
            outcome: GuestOutcomeV1::Success,
            receipt: success_receipt(&journal.binding, journal.post_generation),
        }),
        JournalStateV1::Reserved => match cell {
            StoredV1::Missing if journal.pre_cell_identity == "missing" => Ok(EffectResultV1 {
                outcome: GuestOutcomeV1::Failure,
                receipt: failure_receipt(journal),
            }),
            StoredV1::Valid(_, identity) if *identity == journal.pre_cell_identity => {
                Ok(EffectResultV1 {
                    outcome: GuestOutcomeV1::Failure,
                    receipt: failure_receipt(journal),
                })
            }
            StoredV1::Valid(cell, _)
                if cell.generation == journal.pre_generation.saturating_add(1)
                    && cell.binding == journal.binding =>
            {
                Ok(EffectResultV1 {
                    outcome: GuestOutcomeV1::Success,
                    receipt: success_receipt(&journal.binding, cell.generation),
                })
            }
            _ => Ok(indeterminate(
                &journal.binding,
                cell.evidence_identity(),
                "reserved-evidence-disagrees",
            )),
        },
    }
}

fn success_receipt(binding: &WorkBindingV1, generation: u64) -> String {
    transcript_digest(
        "simulated-guest-success-receipt/v1",
        &[
            binding.attempt.as_bytes(),
            binding.marker.as_bytes(),
            binding.work_schema.as_bytes(),
            binding.work.as_bytes(),
            binding.subject.as_bytes(),
            binding.scope.as_bytes(),
            &generation.to_be_bytes(),
            b"success",
        ],
    )
}

fn failure_receipt(journal: &JournalV1) -> String {
    transcript_digest(
        "simulated-guest-failure-receipt/v1",
        &[
            journal.binding.attempt.as_bytes(),
            journal.binding.marker.as_bytes(),
            journal.binding.work_schema.as_bytes(),
            journal.binding.work.as_bytes(),
            journal.binding.subject.as_bytes(),
            journal.binding.scope.as_bytes(),
            &journal.pre_generation.to_be_bytes(),
            journal.pre_cell_identity.as_bytes(),
            b"failure",
        ],
    )
}

fn indeterminate(binding: &WorkBindingV1, evidence: &str, reason: &str) -> EffectResultV1 {
    EffectResultV1 {
        outcome: GuestOutcomeV1::Indeterminate,
        receipt: transcript_digest(
            "simulated-guest-indeterminate-evidence/v1",
            &[
                binding.attempt.as_bytes(),
                binding.marker.as_bytes(),
                binding.work_schema.as_bytes(),
                binding.work.as_bytes(),
                binding.subject.as_bytes(),
                binding.scope.as_bytes(),
                evidence.as_bytes(),
                reason.as_bytes(),
            ],
        ),
    }
}

fn validate_state_directory(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("stage0-state-directory-not-exact-absolute".to_owned());
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("stage0-state-directory-metadata:{error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("stage0-state-directory-not-nonsymlink-directory".to_owned());
    }
    if metadata.mode() & 0o077 != 0 {
        return Err("stage0-state-directory-not-private".to_owned());
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            let parent = File::open(
                path.parent()
                    .ok_or_else(|| "stage0-state-parent".to_owned())?,
            )
            .map_err(|error| format!("stage0-state-parent-open:{error}"))?;
            parent
                .sync_all()
                .map_err(|error| format!("stage0-state-parent-sync:{error}"))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("stage0-attempt-directory-create:{error}")),
    }
    if !validate_attempt_directory(path)? {
        return Err("stage0-attempt-directory-disappeared".to_owned());
    }
    Ok(())
}

fn validate_attempt_directory(path: &Path) -> Result<bool, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("stage0-attempt-directory-metadata:{error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err("stage0-attempt-directory-not-private".to_owned());
    }
    Ok(true)
}

fn journal_path(directory: &Path, attempt: &str) -> Result<PathBuf, String> {
    require_digest(attempt, "stage0 journal attempt")?;
    Ok(directory.join(format!("{}.journal", &attempt[7..])))
}

fn read_journal(path: &Path) -> Result<StoredV1<JournalV1>, String> {
    read_record(path, decode_journal)
}

fn read_cell(path: &Path) -> Result<StoredV1<CellV1>, String> {
    read_record(path, decode_cell)
}

fn read_record<T>(
    path: &Path,
    decode: fn(&[u8]) -> Result<T, String>,
) -> Result<StoredV1<T>, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(StoredV1::Missing),
        Err(error) => return Err(format!("stage0-state-metadata:{error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_STATE_BYTES
    {
        return Ok(StoredV1::Corrupt(transcript_digest(
            "persistent-evidence-metadata/v1",
            &[
                path.as_os_str().as_encoded_bytes(),
                &metadata.len().to_be_bytes(),
            ],
        )));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("stage0-state-open:{error}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("stage0-state-read:{error}"))?;
    let identity = transcript_digest("persistent-evidence-bytes/v1", &[&bytes]);
    match decode(&bytes) {
        Ok(value) => Ok(StoredV1::Valid(value, identity)),
        Err(_) => Ok(StoredV1::Corrupt(identity)),
    }
}

fn persist_journal(path: &Path, journal: &JournalV1) -> Result<(), String> {
    persist_record(path, &encode_journal(journal)?)
}

fn persist_cell(path: &Path, cell: &CellV1) -> Result<(), String> {
    persist_record(path, &encode_cell(cell)?)
}

fn persist_record(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "stage0-state-parent".to_owned())?;
    let name = path
        .file_name()
        .ok_or_else(|| "stage0-state-name".to_owned())?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("stage0-state-temp-open:{error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("stage0-state-write:{error}"))?;
    file.sync_all()
        .map_err(|error| format!("stage0-state-sync:{error}"))?;
    drop(file);
    std::fs::rename(&temporary, path).map_err(|error| format!("stage0-state-rename:{error}"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("stage0-state-directory-sync:{error}"))
}

fn encode_journal(journal: &JournalV1) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(JOURNAL_MAGIC);
    bytes.push(journal.state as u8);
    bytes.extend_from_slice(&journal.pre_generation.to_be_bytes());
    bytes.extend_from_slice(&journal.post_generation.to_be_bytes());
    put_text(&mut bytes, &journal.pre_cell_identity)?;
    put_binding(&mut bytes, &journal.binding)?;
    put_text(&mut bytes, &journal.receipt)?;
    append_checksum("journal-checksum/v1", bytes)
}

fn decode_journal(bytes: &[u8]) -> Result<JournalV1, String> {
    let payload = verified_payload("journal-checksum/v1", bytes)?;
    let mut cursor = Cursor::new(payload);
    require_magic(&mut cursor, JOURNAL_MAGIC)?;
    let state = match take_u8(&mut cursor)? {
        1 => JournalStateV1::Reserved,
        2 => JournalStateV1::Effected,
        3 => JournalStateV1::Committed,
        _ => return Err("stage0-journal-state".to_owned()),
    };
    let pre_generation = take_u64(&mut cursor)?;
    let post_generation = take_u64(&mut cursor)?;
    let pre_cell_identity = take_text(&mut cursor)?;
    let binding = take_binding(&mut cursor)?;
    let receipt = take_text(&mut cursor)?;
    require_consumed(&cursor)?;
    binding.validate()?;
    if pre_cell_identity != "missing" {
        require_digest(&pre_cell_identity, "stage0 pre-cell identity")?;
    }
    match state {
        JournalStateV1::Reserved if post_generation != 0 || !receipt.is_empty() => {
            return Err("stage0-reserved-shape".to_owned())
        }
        JournalStateV1::Effected
            if post_generation != pre_generation.saturating_add(1) || !receipt.is_empty() =>
        {
            return Err("stage0-effected-shape".to_owned())
        }
        JournalStateV1::Committed if post_generation != pre_generation.saturating_add(1) => {
            return Err("stage0-committed-shape".to_owned())
        }
        _ => {}
    }
    if state == JournalStateV1::Committed {
        require_digest(&receipt, "stage0 journal receipt")?;
    }
    Ok(JournalV1 {
        state,
        pre_generation,
        post_generation,
        pre_cell_identity,
        binding,
        receipt,
    })
}

fn encode_cell(cell: &CellV1) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CELL_MAGIC);
    bytes.extend_from_slice(&cell.generation.to_be_bytes());
    put_binding(&mut bytes, &cell.binding)?;
    append_checksum("result-cell-checksum/v1", bytes)
}

fn decode_cell(bytes: &[u8]) -> Result<CellV1, String> {
    let payload = verified_payload("result-cell-checksum/v1", bytes)?;
    let mut cursor = Cursor::new(payload);
    require_magic(&mut cursor, CELL_MAGIC)?;
    let generation = take_u64(&mut cursor)?;
    if generation == 0 {
        return Err("stage0-cell-zero-generation".to_owned());
    }
    let binding = take_binding(&mut cursor)?;
    require_consumed(&cursor)?;
    binding.validate()?;
    Ok(CellV1 {
        generation,
        binding,
    })
}

fn append_checksum(domain: &str, mut bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    let checksum = transcript_digest(domain, &[&bytes]);
    bytes.extend_from_slice(checksum.as_bytes());
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err("stage0-state-encoding-oversized".to_owned());
    }
    Ok(bytes)
}

fn verified_payload<'a>(domain: &str, bytes: &'a [u8]) -> Result<&'a [u8], String> {
    if bytes.len() <= CHECKSUM_BYTES {
        return Err("stage0-state-truncated".to_owned());
    }
    let split = bytes.len() - CHECKSUM_BYTES;
    let (payload, checksum) = bytes.split_at(split);
    if checksum != transcript_digest(domain, &[payload]).as_bytes() {
        return Err("stage0-state-checksum".to_owned());
    }
    Ok(payload)
}

fn put_binding(bytes: &mut Vec<u8>, binding: &WorkBindingV1) -> Result<(), String> {
    binding.validate()?;
    for value in [
        &binding.attempt,
        &binding.marker,
        &binding.work_schema,
        &binding.work,
        &binding.subject,
        &binding.scope,
    ] {
        put_text(bytes, value)?;
    }
    Ok(())
}

fn take_binding(cursor: &mut Cursor<&[u8]>) -> Result<WorkBindingV1, String> {
    Ok(WorkBindingV1 {
        attempt: take_text(cursor)?,
        marker: take_text(cursor)?,
        work_schema: take_text(cursor)?,
        work: take_text(cursor)?,
        subject: take_text(cursor)?,
        scope: take_text(cursor)?,
    })
}

fn put_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let length =
        u16::try_from(value.len()).map_err(|_| "stage0-state-field-oversized".to_owned())?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn take_text(cursor: &mut Cursor<&[u8]>) -> Result<String, String> {
    let mut length = [0_u8; 2];
    cursor
        .read_exact(&mut length)
        .map_err(|_| "stage0-state-truncated".to_owned())?;
    let mut bytes = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| "stage0-state-truncated".to_owned())?;
    String::from_utf8(bytes).map_err(|_| "stage0-state-text".to_owned())
}

fn require_magic(cursor: &mut Cursor<&[u8]>, expected: &[u8; 8]) -> Result<(), String> {
    let mut actual = [0_u8; 8];
    cursor
        .read_exact(&mut actual)
        .map_err(|_| "stage0-state-truncated".to_owned())?;
    if &actual != expected {
        return Err("stage0-state-magic".to_owned());
    }
    Ok(())
}

fn take_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, String> {
    let mut value = [0_u8; 1];
    cursor
        .read_exact(&mut value)
        .map_err(|_| "stage0-state-truncated".to_owned())?;
    Ok(value[0])
}

fn take_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, String> {
    let mut value = [0_u8; 8];
    cursor
        .read_exact(&mut value)
        .map_err(|_| "stage0-state-truncated".to_owned())?;
    Ok(u64::from_be_bytes(value))
}

fn require_consumed(cursor: &Cursor<&[u8]>) -> Result<(), String> {
    if cursor.position() as usize != cursor.get_ref().len() {
        return Err("stage0-state-trailing-bytes".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn digest(label: &str) -> String {
        transcript_digest("state-test/v1", &[label.as_bytes()])
    }

    fn binding(label: &str) -> WorkBindingV1 {
        WorkBindingV1 {
            attempt: digest(&format!("{label}-attempt")),
            marker: digest(&format!("{label}-marker")),
            work_schema: super::super::protocol::STAGE0_WORK_SCHEMA_V1.to_owned(),
            work: digest("plan"),
            subject: digest("subject"),
            scope: digest("scope"),
        }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.starts_with("/tmp/docket-stage0-state-test-") {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn root() -> TestRoot {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = PathBuf::from(format!(
            "/tmp/docket-stage0-state-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        TestRoot(path)
    }

    #[test]
    fn normal_effect_and_exact_terminal_replay_advance_once() {
        let root = root();
        let binding = binding("normal");
        let first = execute(root.path(), &binding, FaultCutV1::None).unwrap();
        assert_eq!(first.outcome, GuestOutcomeV1::Success);
        let cell = std::fs::read(root.path().join("result.cell")).unwrap();
        let replay = execute(root.path(), &binding, FaultCutV1::None).unwrap();
        assert_eq!(replay, first);
        assert_eq!(
            std::fs::read(root.path().join("result.cell")).unwrap(),
            cell
        );
        assert_eq!(reconcile(root.path(), &binding).unwrap(), first);
    }

    #[test]
    fn conflicting_replay_refuses_without_effect() {
        let root = root();
        let binding = binding("conflict");
        execute(root.path(), &binding, FaultCutV1::None).unwrap();
        let cell = std::fs::read(root.path().join("result.cell")).unwrap();
        let mut changed = binding.clone();
        changed.marker = digest("changed-marker");
        assert_eq!(
            execute(root.path(), &changed, FaultCutV1::None).unwrap_err(),
            "stage0-conflicting-replay"
        );
        assert_eq!(
            std::fs::read(root.path().join("result.cell")).unwrap(),
            cell
        );
    }

    #[test]
    fn death_before_reservation_leaves_no_attempt_evidence() {
        let root = root();
        let binding = binding("before");
        assert!(
            execute(root.path(), &binding, FaultCutV1::BeforeReservation)
                .unwrap_err()
                .contains("before-reservation")
        );
        assert_eq!(
            reconcile(root.path(), &binding).unwrap_err(),
            "stage0-reconcile-missing-attempt"
        );
        assert!(!root.path().join("result.cell").exists());
    }

    #[test]
    fn death_after_reservation_proves_failure_and_never_retries() {
        let root = root();
        let binding = binding("reserved");
        assert!(execute(root.path(), &binding, FaultCutV1::AfterReservation)
            .unwrap_err()
            .contains("after-reservation"));
        let result = reconcile(root.path(), &binding).unwrap();
        assert_eq!(result.outcome, GuestOutcomeV1::Failure);
        assert_eq!(
            execute(root.path(), &binding, FaultCutV1::None).unwrap(),
            result
        );
        assert!(!root.path().join("result.cell").exists());
    }

    #[test]
    fn death_after_effect_proves_success_and_never_retries() {
        let root = root();
        let binding = binding("effected");
        assert!(execute(root.path(), &binding, FaultCutV1::AfterEffect)
            .unwrap_err()
            .contains("after-effect"));
        let cell = std::fs::read(root.path().join("result.cell")).unwrap();
        let result = reconcile(root.path(), &binding).unwrap();
        assert_eq!(result.outcome, GuestOutcomeV1::Success);
        assert_eq!(
            execute(root.path(), &binding, FaultCutV1::None).unwrap(),
            result
        );
        assert_eq!(
            std::fs::read(root.path().join("result.cell")).unwrap(),
            cell
        );
    }

    #[test]
    fn death_after_commit_replays_the_exact_terminal_receipt() {
        let root = root();
        let binding = binding("committed");
        assert!(execute(root.path(), &binding, FaultCutV1::AfterCommit)
            .unwrap_err()
            .contains("after-commit"));
        let cell = std::fs::read(root.path().join("result.cell")).unwrap();
        let reconciled = reconcile(root.path(), &binding).unwrap();
        let replayed = execute(root.path(), &binding, FaultCutV1::None).unwrap();
        assert_eq!(reconciled, replayed);
        assert_eq!(reconciled.outcome, GuestOutcomeV1::Success);
        assert_eq!(
            std::fs::read(root.path().join("result.cell")).unwrap(),
            cell
        );
    }

    #[test]
    fn disagreement_and_corruption_never_become_definite() {
        let ambiguous_root = root();
        let first_binding = binding("ambiguous");
        assert!(execute(
            ambiguous_root.path(),
            &first_binding,
            FaultCutV1::AfterReservation
        )
        .is_err());
        let other = binding("other");
        persist_cell(
            &ambiguous_root.path().join("result.cell"),
            &CellV1 {
                generation: 1,
                binding: other,
            },
        )
        .unwrap();
        assert_eq!(
            reconcile(ambiguous_root.path(), &first_binding)
                .unwrap()
                .outcome,
            GuestOutcomeV1::Indeterminate
        );

        let corrupt_root = root();
        let corrupt_binding = binding("corrupt-journal");
        assert!(execute(
            corrupt_root.path(),
            &corrupt_binding,
            FaultCutV1::AfterReservation,
        )
        .is_err());
        std::fs::write(
            journal_path(
                &corrupt_root.path().join("attempts"),
                &corrupt_binding.attempt,
            )
            .unwrap(),
            b"corrupt",
        )
        .unwrap();
        assert_eq!(
            reconcile(corrupt_root.path(), &corrupt_binding)
                .unwrap()
                .outcome,
            GuestOutcomeV1::Indeterminate
        );

        let cell_root = root();
        let cell_binding = binding("corrupt-cell");
        execute(cell_root.path(), &cell_binding, FaultCutV1::None).unwrap();
        std::fs::write(cell_root.path().join("result.cell"), b"corrupt").unwrap();
        assert_eq!(
            reconcile(cell_root.path(), &cell_binding).unwrap().outcome,
            GuestOutcomeV1::Indeterminate
        );
    }

    #[test]
    fn reconcile_is_byte_read_only_for_all_private_state() {
        let root = root();
        let binding = binding("read-only");
        execute(root.path(), &binding, FaultCutV1::None).unwrap();
        let before = snapshot(root.path());
        reconcile(root.path(), &binding).unwrap();
        let after = snapshot(root.path());
        assert_eq!(after, before);
    }

    fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut result = Vec::new();
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                for nested in std::fs::read_dir(path).unwrap() {
                    let nested = nested.unwrap().path();
                    result.push((
                        nested.strip_prefix(root).unwrap().to_owned(),
                        std::fs::read(&nested).unwrap(),
                    ));
                }
            } else {
                result.push((
                    path.strip_prefix(root).unwrap().to_owned(),
                    std::fs::read(&path).unwrap(),
                ));
            }
        }
        result.sort_by(|left, right| left.0.cmp(&right.0));
        result
    }
}
