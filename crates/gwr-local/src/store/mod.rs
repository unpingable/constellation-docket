//! SQLite implementation of the store port: transactional current-state
//! projections plus immutable typed ledger records.

pub(crate) mod codec;

use codec::*;
use gwr_core::authorization::{
    AcceptedIssuance, AuthorizationSource, UpstreamPremise, UpstreamResidual,
    UpstreamResidualStatus,
};
use gwr_core::campaign::adjudication::AdjudicationReceipt;
use gwr_core::campaign::proposal::CampaignStageProposal;
use gwr_core::campaign::standing::{
    CampaignStageConsumption, CampaignStageStanding, CampaignStandingState,
};
use gwr_core::digest::Sha256Digest;
use gwr_core::domain::reservation::{ClaimState, ReservationClaim};
use gwr_core::domain::standing::{GrantState, StandingGrant, StandingScope, StandingUse};
use gwr_core::ids::*;
use gwr_core::lifecycle::AttemptState;
use gwr_core::observation_plan::{ObservationPlan, ObservationRecord};
use gwr_core::outcome::{Commitment, DispatchRefusalRecord, IndeterminateRecord};
use gwr_core::preparation::{CandidateArtifact, PreparationEnd, PreparationRun, PreparationStatus};
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::receipt::{DispatchEnvelope, RatificationReceipt, ReviewQueueAdmission};
use gwr_core::reconciliation::{Reconciliation, ResidualObligation};
use gwr_core::recovery::{RecoveryFact, RecoveryResolution};
use gwr_core::refusal::RelianceRefusal;
use gwr_core::repository::{RepositoryAlias, RepositoryAliasKind, RepositoryRegistration};
use gwr_core::work_request::{ClockReading, RepositoryLocator, WorkRequest};
use gwr_runtime::ports::store::{
    CampaignBurn, ProjectedAttempt, RelianceRefusalRecord, RelianceSubject, Store, StoreError,
    TimelineEntry,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::path::Path;

const MIGRATION: &str = include_str!("../../migrations/0001_init.sql");
const MIGRATION_0002: &str = include_str!("../../migrations/0002_reliance_subject.sql");
const MIGRATION_0003: &str = include_str!("../../migrations/0003_authz_issuance.sql");
const MIGRATION_0004: &str = include_str!("../../migrations/0004_repository_registry.sql");
const MIGRATION_0005: &str = include_str!("../../migrations/0005_campaign_stage_standing.sql");
const MIGRATION_0006: &str = include_str!("../../migrations/0006_governed_loop_custody.sql");
const MIGRATION_0007: &str = include_str!("../../migrations/0007_local_execution_standing.sql");

pub struct SqliteStore {
    conn: Connection,
}

fn backend(e: rusqlite::Error) -> StoreError {
    // A decode failure raised inside a row-mapping closure travels through
    // rusqlite's conversion-error channel; surface it as the typed corruption
    // error rather than a generic backend failure.
    if let rusqlite::Error::FromSqlConversionFailure(_, _, source) = &e {
        if let Some(corrupt) = source.downcast_ref::<CorruptColumn>() {
            return StoreError::Corrupt(corrupt.to_string());
        }
    }
    StoreError::Backend(e.to_string())
}

/// Bounded writer-contention window (P4). When another connection holds the
/// write lock, SQLite sleeps and retries inside this budget before returning
/// `SQLITE_BUSY`. This never changes outcomes: a waiting consumer that
/// acquires the lock observes the committed burn and receives the exact
/// typed replay classification; a consumer that outlasts the budget receives
/// a bounded store error, never a success. It is not a guarantee of eventual
/// success — only ordinary short contention gets a bounded chance to
/// resolve. Five seconds covers process-level CLI overlap without turning a
/// stuck writer into an unbounded hang.
pub const SQLITE_BUSY_TIMEOUT_MS: u32 = 5_000;

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(backend)?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(backend)?;
        conn.pragma_update(None, "busy_timeout", SQLITE_BUSY_TIMEOUT_MS)
            .map_err(backend)?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(backend)?;
        conn.pragma_update(None, "busy_timeout", SQLITE_BUSY_TIMEOUT_MS)
            .map_err(backend)?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    /// Apply migrations. 0001 is idempotent (`IF NOT EXISTS`); 0002 adds the
    /// reliance-refusal subject columns and is applied only when a database
    /// predates them, so a pre-0002 store (including the pilot's) opens
    /// unchanged except for the added nullable columns.
    fn migrate(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(MIGRATION).map_err(backend)?;
        let has_subject: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('reliance_refusal')
                 WHERE name='observation'",
                [],
                |r| r.get(0),
            )
            .map_err(backend)?;
        if has_subject == 0 {
            conn.execute_batch(MIGRATION_0002).map_err(backend)?;
        }
        // 0003 adds the upstream-authorization issuance table and the grant's
        // authorization source. Pre-0003 grants keep a NULL source, which reads
        // as "unrecorded" — never as either authorization source.
        let has_source: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('standing_grant')
                 WHERE name='source'",
                [],
                |r| r.get(0),
            )
            .map_err(backend)?;
        if has_source == 0 {
            conn.execute_batch(MIGRATION_0003).map_err(backend)?;
        }
        // 0004 introduces Docket's explicit logical repository registry.
        // It intentionally does not backfill from stored paths: a path is a
        // locator, never identity. Existing stores remain readable for
        // operations that do not require logical identity. The nullable
        // work-request binding remains NULL until a new request supplies an ID
        // or an operator explicitly migrates one selected attempt.
        let has_repository_id: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('work_request')
                 WHERE name='repository_id'",
                [],
                |r| r.get(0),
            )
            .map_err(backend)?;
        if has_repository_id == 0 {
            conn.execute("ALTER TABLE work_request ADD COLUMN repository_id TEXT", [])
                .map_err(backend)?;
        }
        conn.execute_batch(MIGRATION_0004).map_err(backend)?;
        // 0005 adds the campaign-stage standing ledger (S-2). Idempotent
        // (`IF NOT EXISTS`); it shares no table with the effect-standing
        // domain and alters none.
        conn.execute_batch(MIGRATION_0005).map_err(backend)?;
        // 0006 is the canonical AG-issuance-bound execution-custody ledger.
        // It shares neither authority nor storage with campaign-stage
        // standing, AG's spend journal, or executor-local idempotency state.
        conn.execute_batch(MIGRATION_0006).map_err(backend)?;
        conn.execute_batch(MIGRATION_0007).map_err(backend)?;
        Ok(())
    }

    /// Raw SQL escape hatch for boundary tests that need to corrupt persisted
    /// records. Test support only.
    pub fn execute_raw_for_test(&mut self, sql: &str) -> Result<usize, StoreError> {
        self.conn.execute(sql, []).map_err(backend)
    }

    /// Raw single-string query for tests asserting deployment properties
    /// (for example the journal mode the durability law rides on). Test
    /// support only.
    pub fn query_string_for_test(&mut self, sql: &str) -> Result<String, StoreError> {
        self.conn.query_row(sql, [], |r| r.get(0)).map_err(backend)
    }

    fn tx(&mut self) -> Result<Transaction<'_>, StoreError> {
        self.conn.transaction().map_err(backend)
    }

    /// Insert a commitment row directly. Test support only: it exists so a
    /// suite can stage another attempt's committed effect without driving that
    /// attempt's whole lifecycle. It writes no projection.
    pub fn record_commitment_for_test(
        &mut self,
        c: &gwr_core::outcome::Commitment,
    ) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO commitment
                 (attempt, dispatch, target_ref, previous_value, result_commit, journal_digest, at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id16(c.attempt.as_bytes()),
                    id16(c.dispatch.as_bytes()),
                    c.target_ref.as_str(),
                    c.previous_value.as_str(),
                    c.result_commit.as_str(),
                    c.journal_digest.to_hex(),
                    c.committed_at.0 as i64
                ],
            )
            .map_err(backend)?;
        Ok(())
    }

    /// Column names across every table, for boundary tests.
    pub fn all_column_names(&mut self) -> Result<Vec<String>, StoreError> {
        let mut names = Vec::new();
        let tables: Vec<String> = self
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .map_err(backend)?
            .query_map([], |r| r.get(0))
            .map_err(backend)?
            .collect::<Result<_, _>>()
            .map_err(backend)?;
        for t in tables {
            let mut stmt = self
                .conn
                .prepare(&format!("PRAGMA table_info({t})"))
                .map_err(backend)?;
            let cols: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))
                .map_err(backend)?
                .collect::<Result<_, _>>()
                .map_err(backend)?;
            for c in cols {
                names.push(format!("{t}.{c}"));
            }
        }
        Ok(names)
    }
}

/// Serialize the projection columns for an attempt state.
#[allow(clippy::type_complexity)]
fn projection_columns(
    state: &AttemptState,
) -> (
    &'static str,
    Option<String>, // rat_id
    Option<String>, // rat_standing_use
    Option<String>, // rsv_id
    Option<String>, // rsv_use
    Option<String>, // dispatch_id
    Option<String>, // refusal_ground
    Option<String>, // resolution_id
) {
    use AttemptState as S;
    let rat = |r: &gwr_core::lifecycle::RatificationRef| {
        (
            Some(id16(r.ratification.as_bytes())),
            Some(id16(r.standing_use.as_bytes())),
        )
    };
    let rsv = |r: &gwr_core::lifecycle::ReservationRef| {
        (
            Some(id16(r.reservation.as_bytes())),
            Some(id16(r.reservation_use.as_bytes())),
        )
    };
    match state {
        S::Prepared => ("prepared", None, None, None, None, None, None, None),
        S::Ratified { ratification } => {
            let (a, b) = rat(ratification);
            ("ratified", a, b, None, None, None, None, None)
        }
        S::Reserved {
            ratification,
            reservation,
        } => {
            let (a, b) = rat(ratification);
            (
                "reserved",
                a,
                b,
                Some(id16(reservation.as_bytes())),
                None,
                None,
                None,
                None,
            )
        }
        S::Dispatching {
            ratification,
            reservation,
            dispatch,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "dispatching",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                None,
                None,
            )
        }
        S::Committed {
            ratification,
            reservation,
            dispatch,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "committed",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                None,
                None,
            )
        }
        S::DispatchRefused {
            ratification,
            reservation,
            dispatch,
            ground,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "dispatch_refused",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                Some(ground_tag(*ground).to_string()),
                None,
            )
        }
        S::Indeterminate {
            ratification,
            reservation,
            dispatch,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "indeterminate",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                None,
                None,
            )
        }
        S::CommittedViaRecovery {
            ratification,
            reservation,
            dispatch,
            resolution,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "committed_via_recovery",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                None,
                Some(id16(resolution.resolution.as_bytes())),
            )
        }
        S::ProvenNotCommitted {
            ratification,
            reservation,
            dispatch,
            resolution,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "proven_not_committed",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                None,
                Some(id16(resolution.resolution.as_bytes())),
            )
        }
    }
}

/// The successor relation of the lifecycle, in projection-tag form. It mirrors
/// `AttemptState`'s transition methods exactly; the type system enforces this
/// for in-process callers, and this enforces it for anything reaching the store
/// directly.
fn transition_permitted(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("prepared", "ratified")
            | ("ratified", "reserved")
            | ("reserved", "dispatching")
            | ("dispatching", "committed")
            | ("dispatching", "dispatch_refused")
            | ("dispatching", "indeterminate")
            | ("indeterminate", "committed_via_recovery")
            | ("indeterminate", "proven_not_committed")
    )
}

/// Atomically advance the attempt projection from `expected_version` and append
/// the timeline row. The single writer for the projection.
fn advance_projection(
    tx: &Transaction<'_>,
    attempt: AttemptId,
    expected_version: u64,
    state: &AttemptState,
    at: ClockReading,
) -> Result<(), StoreError> {
    let (tag, rat_id, rat_use, rsv_id, rsv_use, dsp, ground, res) = projection_columns(state);

    // The store validates the transition it is asked to persist. A persistence
    // port that accepts any caller-supplied next state is not a neutral port —
    // it is a second authority path around the lifecycle, and it was one: a
    // caller could persist Committed with no dispatch row, then regress to
    // Prepared, with the timeline dutifully recording the impossible sequence.
    let current_tag: String = tx
        .query_row(
            "SELECT state FROM attempt_projection WHERE attempt=?1",
            params![id16(attempt.as_bytes())],
            |r| r.get(0),
        )
        .optional()
        .map_err(backend)?
        .ok_or(StoreError::NotFound)?;
    if !transition_permitted(&current_tag, tag) {
        return Err(StoreError::IllegalTransition {
            from: current_tag,
            to: tag.to_string(),
        });
    }

    let changed = tx
        .execute(
            "UPDATE attempt_projection SET state=?1, version=?2, rat_id=?3, rat_standing_use=?4,
             rsv_id=?5, rsv_use=?6, dispatch_id=?7, refusal_ground=?8, resolution_id=?9
             WHERE attempt=?10 AND version=?11",
            params![
                tag,
                (expected_version + 1) as i64,
                rat_id,
                rat_use,
                rsv_id,
                rsv_use,
                dsp,
                ground,
                res,
                id16(attempt.as_bytes()),
                expected_version as i64,
            ],
        )
        .map_err(backend)?;
    if changed == 0 {
        let actual: Option<i64> = tx
            .query_row(
                "SELECT version FROM attempt_projection WHERE attempt=?1",
                params![id16(attempt.as_bytes())],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        return match actual {
            Some(v) => Err(StoreError::StaleVersion {
                expected: expected_version,
                actual: v as u64,
            }),
            None => Err(StoreError::NotFound),
        };
    }
    tx.execute(
        "INSERT INTO timeline (attempt, seq, kind, at) VALUES (?1, ?2, ?3, ?4)",
        params![
            id16(attempt.as_bytes()),
            (expected_version + 1) as i64,
            tag,
            at.0 as i64
        ],
    )
    .map_err(backend)?;
    Ok(())
}

/// Consume a standing grant inside a transaction, inserting the use record.
fn consume_standing(
    tx: &Transaction<'_>,
    grant: &StandingGrant,
    use_record: &StandingUse,
) -> Result<(), StoreError> {
    let changed = tx
        .execute(
            "UPDATE standing_projection SET consumed_by=?1, version=version+1
             WHERE grant_id=?2 AND consumed_by IS NULL",
            params![id16(use_record.id.as_bytes()), id16(grant.id().as_bytes())],
        )
        .map_err(backend)?;
    if changed == 0 {
        return Err(StoreError::AlreadyConsumed);
    }
    tx.execute(
        "INSERT INTO standing_use (id, grant_id, used_at) VALUES (?1, ?2, ?3)",
        params![
            id16(use_record.id.as_bytes()),
            id16(grant.id().as_bytes()),
            use_record.used_at.0 as i64
        ],
    )
    .map_err(backend)?;
    Ok(())
}

// Campaign-stage standing (S-2) row mapping. Every read path recomputes the
// content address from the persisted fields; a mismatch is typed corruption.

fn consumption_from_row_at(
    standing: Sha256Digest,
    r: &rusqlite::Row<'_>,
    o: usize,
) -> rusqlite::Result<CampaignStageConsumption> {
    let receipt: Option<String> = r.get(o + 6)?;
    Ok(CampaignStageConsumption {
        digest: parse_digest(&r.get::<_, String>(o)?).map_err(sql_corrupt)?,
        standing,
        campaign: r.get(o + 1)?,
        stage: r.get(o + 2)?,
        role: parse_role(&r.get::<_, String>(o + 3)?).map_err(sql_corrupt)?,
        consumed_at: ClockReading(r.get::<_, i64>(o + 4)? as u64),
        effect_completed: r.get::<_, i64>(o + 5)? != 0,
        receipt: receipt
            .map(|h| parse_digest(&h).map_err(sql_corrupt))
            .transpose()?,
    })
}

fn proposal_from_row_at(
    digest: Sha256Digest,
    r: &rusqlite::Row<'_>,
    o: usize,
) -> rusqlite::Result<CampaignStageProposal> {
    let basis_adjudication: Option<String> = r.get(o + 9)?;
    let repair_basis: Option<String> = r.get(o + 19)?;
    Ok(CampaignStageProposal {
        digest,
        upstream_digest: r.get(o)?,
        campaign: r.get(o + 1)?,
        stage: r.get(o + 2)?,
        stage_class: parse_stage_class(&r.get::<_, String>(o + 3)?).map_err(sql_corrupt)?,
        role: parse_role(&r.get::<_, String>(o + 4)?).map_err(sql_corrupt)?,
        effect_class: parse_stage_effect(&r.get::<_, String>(o + 5)?).map_err(sql_corrupt)?,
        basis: decode_basis(
            &r.get::<_, String>(o + 6)?,
            &r.get::<_, String>(o + 7)?,
            &r.get::<_, String>(o + 8)?,
            basis_adjudication.as_deref(),
        )
        .map_err(sql_corrupt)?,
        repositories: decode_pins(&r.get::<_, String>(o + 10)?).map_err(sql_corrupt)?,
        allowed_paths: split_list(&r.get::<_, String>(o + 11)?),
        evidence_contract: r.get(o + 12)?,
        handoff_schema: r.get(o + 13)?,
        expires_at: ClockReading(r.get::<_, i64>(o + 14)? as u64),
        nonce: r.get(o + 15)?,
        isolated_worktree: r.get(o + 16)?,
        review_requirement: parse_review_requirement(&r.get::<_, String>(o + 17)?)
            .map_err(sql_corrupt)?,
        nonclaims: split_list(&r.get::<_, String>(o + 18)?),
        repair: repair_basis
            .map(|b| decode_repair_basis(&b).map_err(sql_corrupt))
            .transpose()?,
        proposed_at: ClockReading(r.get::<_, i64>(o + 20)? as u64),
    })
}

fn proposal_from_row(
    digest: Sha256Digest,
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<CampaignStageProposal> {
    proposal_from_row_at(digest, r, 0)
}

fn standing_from_row_at(
    digest: Sha256Digest,
    r: &rusqlite::Row<'_>,
    o: usize,
) -> rusqlite::Result<CampaignStageStanding> {
    let consumed: Option<String> = r.get(o + 12)?;
    Ok(CampaignStageStanding::from_persisted(
        digest,
        parse_digest(&r.get::<_, String>(o)?).map_err(sql_corrupt)?,
        r.get(o + 1)?,
        r.get(o + 2)?,
        r.get(o + 3)?,
        parse_stage_class(&r.get::<_, String>(o + 4)?).map_err(sql_corrupt)?,
        parse_role(&r.get::<_, String>(o + 5)?).map_err(sql_corrupt)?,
        parse_stage_effect(&r.get::<_, String>(o + 6)?).map_err(sql_corrupt)?,
        decode_pins(&r.get::<_, String>(o + 7)?).map_err(sql_corrupt)?,
        split_list(&r.get::<_, String>(o + 8)?),
        ClockReading(r.get::<_, i64>(o + 9)? as u64),
        r.get(o + 10)?,
        ClockReading(r.get::<_, i64>(o + 11)? as u64),
        match consumed {
            None => CampaignStandingState::Available,
            Some(c) => CampaignStandingState::Consumed {
                consumption: parse_digest(&c).map_err(sql_corrupt)?,
            },
        },
    ))
}

fn standing_from_row(
    digest: Sha256Digest,
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<CampaignStageStanding> {
    standing_from_row_at(digest, r, 0)
}

fn standing_from_row_shifted(
    digest: Sha256Digest,
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<CampaignStageStanding> {
    standing_from_row_at(digest, r, 1)
}

fn adjudication_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AdjudicationReceipt> {
    let receipt = AdjudicationReceipt {
        digest: parse_digest(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
        campaign: r.get(1)?,
        stage: r.get(2)?,
        review_receipt: parse_digest(&r.get::<_, String>(3)?).map_err(sql_corrupt)?,
        verdict: parse_adjudication_verdict(&r.get::<_, String>(4)?).map_err(sql_corrupt)?,
        adjudicator: r.get(5)?,
        findings: split_list(&r.get::<_, String>(6)?),
        residuals: decode_residuals(&r.get::<_, String>(7)?).map_err(sql_corrupt)?,
        adjudicated_at: ClockReading(r.get::<_, i64>(8)? as u64),
    };
    if receipt.recompute_digest() != receipt.digest {
        return Err(sql_corrupt(CorruptColumn(format!(
            "campaign adjudication {} fields do not recompute to their digest",
            receipt.digest
        ))));
    }
    Ok(receipt)
}

impl Store for SqliteStore {
    fn register_repository(
        &mut self,
        registration: &RepositoryRegistration,
    ) -> Result<(), StoreError> {
        if registration.aliases.is_empty() {
            return Err(StoreError::Backend(
                "repository registration requires at least one explicit alias".into(),
            ));
        }
        let tx = self.tx()?;
        tx.execute(
            "INSERT OR IGNORE INTO repository (id, registered_at) VALUES (?1, ?2)",
            params![
                id16(registration.id.as_bytes()),
                registration.registered_at.0 as i64
            ],
        )
        .map_err(backend)?;

        for alias in &registration.aliases {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT repository_id FROM repository_locator
                     WHERE kind=?1 AND locator=?2",
                    params![alias.kind.tag(), alias.locator.as_str()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(backend)?;
            if existing
                .as_deref()
                .is_some_and(|id| id != id16(registration.id.as_bytes()))
            {
                return Err(StoreError::ImmutableRebind);
            }
            if alias.current {
                if alias.kind != RepositoryAliasKind::Path {
                    return Err(StoreError::Backend(
                        "only a path alias may be current".into(),
                    ));
                }
                tx.execute(
                    "UPDATE repository_locator SET current=0
                     WHERE repository_id=?1 AND kind='path' AND current=1",
                    params![id16(registration.id.as_bytes())],
                )
                .map_err(backend)?;
            }
            tx.execute(
                "INSERT INTO repository_locator
                 (repository_id, kind, locator, registered_at, current)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(repository_id, kind, locator) DO UPDATE SET
                   current=MAX(repository_locator.current, excluded.current)",
                params![
                    id16(registration.id.as_bytes()),
                    alias.kind.tag(),
                    alias.locator.as_str(),
                    alias.registered_at.0 as i64,
                    i64::from(alias.current)
                ],
            )
            .map_err(backend)?;
        }
        tx.commit().map_err(backend)
    }

    fn add_repository_alias(
        &mut self,
        repository: RepositoryId,
        alias: &RepositoryAlias,
    ) -> Result<(), StoreError> {
        // Refuse aliases for an unregistered logical identity.
        let present: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM repository WHERE id=?1",
                params![id16(repository.as_bytes())],
                |r| r.get(0),
            )
            .map_err(backend)?;
        if present == 0 {
            return Err(StoreError::NotFound);
        }
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT repository_id FROM repository_locator
                 WHERE kind=?1 AND locator=?2",
                params![alias.kind.tag(), alias.locator.as_str()],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        if existing
            .as_deref()
            .is_some_and(|id| id != id16(repository.as_bytes()))
        {
            return Err(StoreError::ImmutableRebind);
        }
        if alias.current && alias.kind != RepositoryAliasKind::Path {
            return Err(StoreError::Backend(
                "only a path alias may be current".into(),
            ));
        }

        let tx = self.tx()?;
        if alias.current {
            tx.execute(
                "UPDATE repository_locator SET current=0
                 WHERE repository_id=?1 AND kind='path' AND current=1",
                params![id16(repository.as_bytes())],
            )
            .map_err(backend)?;
        }
        tx.execute(
            "INSERT INTO repository_locator
             (repository_id, kind, locator, registered_at, current)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(repository_id, kind, locator) DO UPDATE SET
               current=excluded.current",
            params![
                id16(repository.as_bytes()),
                alias.kind.tag(),
                alias.locator.as_str(),
                alias.registered_at.0 as i64,
                i64::from(alias.current)
            ],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    fn get_repository(
        &mut self,
        repository: RepositoryId,
    ) -> Result<RepositoryRegistration, StoreError> {
        let registered_at: i64 = self
            .conn
            .query_row(
                "SELECT registered_at FROM repository WHERE id=?1",
                params![id16(repository.as_bytes())],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)?;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT kind, locator, registered_at, current
                 FROM repository_locator WHERE repository_id=?1
                 ORDER BY registered_at, kind, locator",
            )
            .map_err(backend)?;
        let aliases = stmt
            .query_map(params![id16(repository.as_bytes())], |r| {
                let kind: String = r.get(0)?;
                let kind = RepositoryAliasKind::from_tag(&kind).ok_or_else(|| {
                    sql_corrupt(CorruptColumn(format!(
                        "unknown repository alias kind {kind:?}"
                    )))
                })?;
                Ok(RepositoryAlias {
                    kind,
                    locator: RepositoryLocator::new(r.get::<_, String>(1)?),
                    registered_at: ClockReading(r.get::<_, i64>(2)? as u64),
                    current: r.get::<_, i64>(3)? != 0,
                })
            })
            .map_err(backend)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?;
        Ok(RepositoryRegistration {
            id: repository,
            registered_at: ClockReading(registered_at as u64),
            aliases,
        })
    }

    fn find_repository_by_path(
        &mut self,
        path: &RepositoryLocator,
    ) -> Result<Option<RepositoryRegistration>, StoreError> {
        let id: Option<String> = self
            .conn
            .query_row(
                "SELECT repository_id FROM repository_locator
                 WHERE kind='path' AND locator=?1",
                params![path.as_str()],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        id.map(|raw| {
            let parsed =
                parse_id16::<RepositoryId>(&raw).map_err(|e| StoreError::Corrupt(e.to_string()))?;
            self.get_repository(parsed)
        })
        .transpose()
    }

    fn bind_work_request_repository(
        &mut self,
        work_request: WorkRequestId,
        repository: RepositoryId,
    ) -> Result<(), StoreError> {
        let registered: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM repository WHERE id=?1",
                params![id16(repository.as_bytes())],
                |r| r.get(0),
            )
            .map_err(backend)?;
        if registered == 0 {
            return Err(StoreError::NotFound);
        }
        let request_path: Option<String> = self
            .conn
            .query_row(
                "SELECT repository FROM work_request WHERE id=?1",
                params![id16(work_request.as_bytes())],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        let request_path = request_path.ok_or(StoreError::NotFound)?;
        let retained_alias: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM repository_locator
                 WHERE repository_id=?1 AND kind='path' AND locator=?2",
                params![id16(repository.as_bytes()), request_path],
                |r| r.get(0),
            )
            .map_err(backend)?;
        if retained_alias == 0 {
            return Err(StoreError::ImmutableRebind);
        }
        let changed = self
            .conn
            .execute(
                "UPDATE work_request SET repository_id=?1
                 WHERE id=?2 AND repository_id IS NULL",
                params![id16(repository.as_bytes()), id16(work_request.as_bytes())],
            )
            .map_err(backend)?;
        if changed == 1 {
            return Ok(());
        }
        let existing: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT repository_id FROM work_request WHERE id=?1",
                params![id16(work_request.as_bytes())],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        match existing {
            None => Err(StoreError::NotFound),
            Some(Some(id)) if id == id16(repository.as_bytes()) => Ok(()),
            Some(Some(_)) => Err(StoreError::ImmutableRebind),
            Some(None) => Err(StoreError::Backend(
                "repository binding update made no progress".into(),
            )),
        }
    }

    fn create_work_request(&mut self, wr: &WorkRequest) -> Result<(), StoreError> {
        if let Some(repository_id) = wr.repository_id {
            let registered_current_path: i64 = self
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM repository_locator
                     WHERE repository_id=?1 AND kind='path' AND locator=?2 AND current=1",
                    params![id16(repository_id.as_bytes()), wr.repository.as_str()],
                    |r| r.get(0),
                )
                .map_err(backend)?;
            if registered_current_path == 0 {
                return Err(StoreError::NotFound);
            }
        }
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO work_request
                 (id, repository_id, repository, target_ref, goal, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id16(wr.id.as_bytes()),
                    wr.repository_id.map(|id| id16(id.as_bytes())),
                    wr.repository.as_str(),
                    wr.target_ref.as_str(),
                    wr.goal,
                    wr.created_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self.get_work_request(wr.id)?;
            if &existing != wr {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_work_request(&mut self, id: WorkRequestId) -> Result<WorkRequest, StoreError> {
        self.conn
            .query_row(
                "SELECT id, repository_id, repository, target_ref, goal, created_at
                 FROM work_request WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    let repository_id: Option<String> = r.get(1)?;
                    Ok(WorkRequest {
                        id: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                        repository_id: repository_id
                            .map(|raw| parse_id16(&raw).map_err(sql_corrupt))
                            .transpose()?,
                        repository: repo(&r.get::<_, String>(2)?),
                        target_ref: refname(&r.get::<_, String>(3)?),
                        goal: r.get(4)?,
                        created_at: ClockReading(r.get::<_, i64>(5)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn create_preparation_run(&mut self, run: &PreparationRun) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO preparation_run (id, work_request, started_at, deadline)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    id16(run.id.as_bytes()),
                    id16(run.work_request.as_bytes()),
                    run.started_at.0 as i64,
                    run.deadline.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self.get_preparation_run(run.id)?;
            let same = existing.id == run.id
                && existing.work_request == run.work_request
                && existing.started_at == run.started_at
                && existing.deadline == run.deadline;
            if !same {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_preparation_run(&mut self, id: PreparationRunId) -> Result<PreparationRun, StoreError> {
        let base = self
            .conn
            .query_row(
                "SELECT id, work_request, started_at, deadline FROM preparation_run WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    Ok((
                        parse_id16::<PreparationRunId>(&r.get::<_, String>(0)?)
                            .map_err(sql_corrupt)?,
                        parse_id16::<WorkRequestId>(&r.get::<_, String>(1)?)
                            .map_err(sql_corrupt)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)?;
        let end: Option<String> = self
            .conn
            .query_row(
                "SELECT end_kind FROM preparation_run_end WHERE run_id=?1",
                params![id16(id.as_bytes())],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        Ok(PreparationRun {
            id: base.0,
            work_request: base.1,
            started_at: ClockReading(base.2 as u64),
            deadline: ClockReading(base.3 as u64),
            status: match end {
                None => PreparationStatus::Running,
                Some(tag) => PreparationStatus::Ended(parse_end_tag(&tag)?),
            },
        })
    }

    fn end_preparation_run(
        &mut self,
        id: PreparationRunId,
        end: PreparationEnd,
        at: ClockReading,
    ) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO preparation_run_end (run_id, end_kind, at) VALUES (?1, ?2, ?3)",
                params![id16(id.as_bytes()), end_tag(end), at.0 as i64],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing: String = self
                .conn
                .query_row(
                    "SELECT end_kind FROM preparation_run_end WHERE run_id=?1",
                    params![id16(id.as_bytes())],
                    |r| r.get(0),
                )
                .map_err(backend)?;
            if existing != end_tag(end) {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn ingest_candidate(&mut self, artifact: &CandidateArtifact) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO candidate_artifact
                 (id, preparation_run, content_digest, content_len, ingested_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id16(artifact.id.as_bytes()),
                    id16(artifact.preparation_run.as_bytes()),
                    artifact.content_digest.to_hex(),
                    artifact.content_len as i64,
                    artifact.ingested_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self.get_candidate(artifact.id)?;
            if &existing != artifact {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_candidate(&mut self, id: CandidateArtifactId) -> Result<CandidateArtifact, StoreError> {
        self.conn
            .query_row(
                "SELECT id, preparation_run, content_digest, content_len, ingested_at
                 FROM candidate_artifact WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    Ok(CandidateArtifact {
                        id: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                        preparation_run: parse_id16(&r.get::<_, String>(1)?)
                            .map_err(sql_corrupt)?,
                        content_digest: parse_digest(&r.get::<_, String>(2)?)
                            .map_err(sql_corrupt)?,
                        content_len: r.get::<_, i64>(3)? as u64,
                        ingested_at: ClockReading(r.get::<_, i64>(4)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn admit_attempt(&mut self, attempt: &PreparedAttempt) -> Result<(), StoreError> {
        let tx = self.tx()?;
        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO attempt
                 (id, work_request, candidate, repository, basis, artifact_digest, target_ref,
                  expected_basis, patch_digest, allowed_paths, argv, environment, admitted_at,
                  prepared_digest)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    id16(attempt.attempt_id.as_bytes()),
                    id16(attempt.work_request.as_bytes()),
                    id16(attempt.candidate.as_bytes()),
                    attempt.repository.as_str(),
                    attempt.basis.as_str(),
                    attempt.artifact_digest.to_hex(),
                    attempt.effect.target_ref.as_str(),
                    attempt.effect.expected_basis.as_str(),
                    attempt.effect.patch_digest.to_hex(),
                    join_list(&attempt.effect.allowed_paths),
                    join_list(&attempt.observation_plan.argv),
                    attempt.observation_plan.environment_description,
                    attempt.admitted_at.0 as i64,
                    attempt.prepared_attempt_digest.to_hex()
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            drop(tx);
            let existing = self.get_attempt(attempt.attempt_id)?;
            if &existing.attempt != attempt {
                return Err(StoreError::ImmutableRebind);
            }
            return Ok(()); // idempotent duplicate
        }
        tx.execute(
            "INSERT INTO attempt_projection (attempt, state, version) VALUES (?1, 'prepared', 0)",
            params![id16(attempt.attempt_id.as_bytes())],
        )
        .map_err(backend)?;
        tx.execute(
            "INSERT INTO timeline (attempt, seq, kind, at) VALUES (?1, 0, 'admitted', ?2)",
            params![
                id16(attempt.attempt_id.as_bytes()),
                attempt.admitted_at.0 as i64
            ],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    fn get_attempt(&mut self, id: AttemptId) -> Result<ProjectedAttempt, StoreError> {
        let attempt = self
            .conn
            .query_row(
                "SELECT work_request, candidate, repository, basis, artifact_digest, target_ref,
                        expected_basis, patch_digest, allowed_paths, argv, environment,
                        admitted_at
                 FROM attempt WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    Ok(PreparedAttempt::admit(
                        id,
                        parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                        parse_id16(&r.get::<_, String>(1)?).map_err(sql_corrupt)?,
                        repo(&r.get::<_, String>(2)?),
                        commit(&r.get::<_, String>(3)?),
                        parse_digest(&r.get::<_, String>(4)?).map_err(sql_corrupt)?,
                        gwr_core::effect_spec::GitRefEffect {
                            target_ref: refname(&r.get::<_, String>(5)?),
                            expected_basis: commit(&r.get::<_, String>(6)?),
                            patch_digest: parse_digest(&r.get::<_, String>(7)?)
                                .map_err(sql_corrupt)?,
                            allowed_paths: split_list(&r.get::<_, String>(8)?),
                        },
                        ObservationPlan {
                            argv: split_list(&r.get::<_, String>(9)?),
                            environment_description: r.get(10)?,
                        },
                        ClockReading(r.get::<_, i64>(11)? as u64),
                    ))
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)?;
        let (state, version) = self
            .conn
            .query_row(
                "SELECT state, version, rat_id, rat_standing_use, rsv_id, rsv_use, dispatch_id,
                        refusal_ground, resolution_id
                 FROM attempt_projection WHERE attempt=?1",
                params![id16(id.as_bytes())],
                |r| {
                    let tag: String = r.get(0)?;
                    let version = r.get::<_, i64>(1)? as u64;
                    let cols = ProjCols {
                        rat_id: r.get(2)?,
                        rat_use: r.get(3)?,
                        rsv_id: r.get(4)?,
                        rsv_use: r.get(5)?,
                        dispatch: r.get(6)?,
                        ground: r.get(7)?,
                        resolution: r.get(8)?,
                    };
                    Ok((tag, version, cols))
                },
            )
            .optional()
            .map_err(backend)?
            .map(|(tag, version, cols)| {
                reconstruct_state(&tag, &cols, &attempt.prepared_attempt_digest)
                    .map(|s| (s, version))
            })
            .ok_or(StoreError::NotFound)??;
        Ok(ProjectedAttempt {
            attempt,
            state,
            version,
        })
    }

    fn find_attempt_dispatch(&mut self, id: AttemptId) -> Result<Option<DispatchId>, StoreError> {
        self.conn
            .query_row(
                "SELECT id FROM dispatch WHERE attempt=?1",
                params![id16(id.as_bytes())],
                |r| parse_id16::<DispatchId>(&r.get::<_, String>(0)?).map_err(sql_corrupt),
            )
            .optional()
            .map_err(backend)
    }

    fn find_dispatch_attempt(&mut self, id: DispatchId) -> Result<Option<AttemptId>, StoreError> {
        self.conn
            .query_row(
                "SELECT attempt FROM dispatch WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| parse_id16::<AttemptId>(&r.get::<_, String>(0)?).map_err(sql_corrupt),
            )
            .optional()
            .map_err(backend)
    }

    fn get_dispatch_envelope(&mut self, id: AttemptId) -> Result<DispatchEnvelope, StoreError> {
        self.conn
            .query_row(
                "SELECT id, prepared_digest, reservation_use, repository, target_ref,
                        expected_basis, patch_digest, allowed_paths, created_at
                 FROM dispatch WHERE attempt=?1",
                params![id16(id.as_bytes())],
                |r| {
                    Ok(DispatchEnvelope {
                        dispatch: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                        attempt: id,
                        prepared_attempt_digest: parse_digest(&r.get::<_, String>(1)?)
                            .map_err(sql_corrupt)?,
                        reservation_use: parse_id16(&r.get::<_, String>(2)?)
                            .map_err(sql_corrupt)?,
                        repository: repo(&r.get::<_, String>(3)?),
                        target_ref: refname(&r.get::<_, String>(4)?),
                        expected_basis: commit(&r.get::<_, String>(5)?),
                        patch_digest: parse_digest(&r.get::<_, String>(6)?).map_err(sql_corrupt)?,
                        allowed_paths: split_list(&r.get::<_, String>(7)?),
                        created_at: ClockReading(r.get::<_, i64>(8)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn create_standing_grant(&mut self, grant: &StandingGrant) -> Result<(), StoreError> {
        let tx = self.tx()?;
        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO standing_grant
                 (id, actor, act, repository, attempt_digest, expires_at, source)
                 VALUES (?1,?2,?3,?4,?5,?6,'local')",
                params![
                    id16(grant.id().as_bytes()),
                    id16(grant.scope().actor.as_bytes()),
                    act_tag(grant.scope().act),
                    grant.scope().repository.as_str(),
                    grant.scope().attempt_digest.to_hex(),
                    grant.expires_at().0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            drop(tx);
            let existing = self.get_standing_grant(grant.id())?;
            if existing.scope() != grant.scope() || existing.expires_at() != grant.expires_at() {
                return Err(StoreError::ImmutableRebind);
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO standing_projection (grant_id, consumed_by, version) VALUES (?1, NULL, 0)",
            params![id16(grant.id().as_bytes())],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    fn get_standing_grant(&mut self, id: StandingGrantId) -> Result<StandingGrant, StoreError> {
        self.conn
            .query_row(
                "SELECT g.actor, g.act, g.repository, g.attempt_digest, g.expires_at,
                        p.consumed_by
                 FROM standing_grant g JOIN standing_projection p ON p.grant_id = g.id
                 WHERE g.id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    let consumed: Option<String> = r.get(5)?;
                    Ok(StandingGrant::from_persisted(
                        id,
                        StandingScope {
                            actor: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                            act: parse_act_tag(&r.get::<_, String>(1)?).map_err(sql_corrupt)?,
                            repository: repo(&r.get::<_, String>(2)?),
                            attempt_digest: parse_digest(&r.get::<_, String>(3)?)
                                .map_err(sql_corrupt)?,
                        },
                        ClockReading(r.get::<_, i64>(4)? as u64),
                        match consumed {
                            None => GrantState::Available,
                            Some(u) => GrantState::Consumed {
                                used_as: parse_id16(&u).map_err(sql_corrupt)?,
                            },
                        },
                    ))
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn create_reservation(
        &mut self,
        claim: &ReservationClaim,
        now: ClockReading,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        // Exclusivity: any active, unexpired reservation on the same repository
        // and target ref conflicts. Conflict produces refusal, not waiting.
        let conflicts: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM reservation r
                 JOIN reservation_projection p ON p.reservation_id = r.id
                 WHERE r.repository=?1 AND r.target_ref=?2 AND p.consumed_by IS NULL
                   AND r.expires_at > ?3 AND r.id <> ?4",
                params![
                    claim.repository().as_str(),
                    claim.target_ref().as_str(),
                    now.0 as i64,
                    id16(claim.id().as_bytes())
                ],
                |r| r.get(0),
            )
            .map_err(backend)?;
        if conflicts > 0 {
            return Err(StoreError::ReservationConflict);
        }
        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO reservation
                 (id, repository, target_ref, basis, attempt, expires_at)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    id16(claim.id().as_bytes()),
                    claim.repository().as_str(),
                    claim.target_ref().as_str(),
                    claim.basis().as_str(),
                    id16(claim.attempt().as_bytes()),
                    claim.expires_at().0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            drop(tx);
            let existing = self.get_reservation(claim.id())?;
            if existing.repository() != claim.repository()
                || existing.target_ref() != claim.target_ref()
                || existing.basis() != claim.basis()
                || existing.attempt() != claim.attempt()
                || existing.expires_at() != claim.expires_at()
            {
                return Err(StoreError::ImmutableRebind);
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO reservation_projection (reservation_id, consumed_by, version)
             VALUES (?1, NULL, 0)",
            params![id16(claim.id().as_bytes())],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    fn get_reservation(&mut self, id: ReservationId) -> Result<ReservationClaim, StoreError> {
        self.conn
            .query_row(
                "SELECT r.repository, r.target_ref, r.basis, r.attempt, r.expires_at,
                        p.consumed_by
                 FROM reservation r JOIN reservation_projection p ON p.reservation_id = r.id
                 WHERE r.id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    let consumed: Option<String> = r.get(5)?;
                    Ok(ReservationClaim::from_persisted(
                        id,
                        repo(&r.get::<_, String>(0)?),
                        refname(&r.get::<_, String>(1)?),
                        commit(&r.get::<_, String>(2)?),
                        parse_id16(&r.get::<_, String>(3)?).map_err(sql_corrupt)?,
                        ClockReading(r.get::<_, i64>(4)? as u64),
                        match consumed {
                            None => ClaimState::Active,
                            Some(u) => ClaimState::Consumed {
                                used_as: parse_id16(&u).map_err(sql_corrupt)?,
                            },
                        },
                    ))
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn record_ratification(
        &mut self,
        expected_version: u64,
        receipt: &RatificationReceipt,
        new_state: &AttemptState,
        consumed_grant: &StandingGrant,
        standing_use: &StandingUse,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        consume_standing(&tx, consumed_grant, standing_use)?;
        tx.execute(
            "INSERT INTO ratification (id, attempt, prepared_digest, actor, standing_use, at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                id16(receipt.ratification.as_bytes()),
                id16(receipt.attempt.as_bytes()),
                receipt.prepared_attempt_digest.to_hex(),
                id16(receipt.actor.as_bytes()),
                id16(receipt.standing_use.as_bytes()),
                receipt.clock_reading.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            receipt.attempt,
            expected_version,
            new_state,
            receipt.clock_reading,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_reserved(
        &mut self,
        expected_version: u64,
        attempt: AttemptId,
        new_state: &AttemptState,
        at: ClockReading,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        advance_projection(&tx, attempt, expected_version, new_state, at)?;
        tx.commit().map_err(backend)
    }

    fn record_dispatch(
        &mut self,
        expected_version: u64,
        envelope: &DispatchEnvelope,
        new_state: &AttemptState,
        consumed_claim: &ReservationClaim,
    ) -> Result<(), StoreError> {
        let ClaimState::Consumed { used_as } = consumed_claim.state() else {
            return Err(StoreError::Backend(
                "record_dispatch requires a consumed claim".into(),
            ));
        };
        let tx = self.tx()?;
        let changed = tx
            .execute(
                "UPDATE reservation_projection SET consumed_by=?1, version=version+1
                 WHERE reservation_id=?2 AND consumed_by IS NULL",
                params![
                    id16(used_as.as_bytes()),
                    id16(consumed_claim.id().as_bytes())
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            return Err(StoreError::AlreadyConsumed);
        }
        tx.execute(
            "INSERT INTO reservation_use (id, reservation_id, used_at) VALUES (?1, ?2, ?3)",
            params![
                id16(used_as.as_bytes()),
                id16(consumed_claim.id().as_bytes()),
                envelope.created_at.0 as i64
            ],
        )
        .map_err(backend)?;
        tx.execute(
            "INSERT INTO dispatch
             (id, attempt, prepared_digest, reservation_use, repository, target_ref,
              expected_basis, patch_digest, allowed_paths, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                id16(envelope.dispatch.as_bytes()),
                id16(envelope.attempt.as_bytes()),
                envelope.prepared_attempt_digest.to_hex(),
                id16(envelope.reservation_use.as_bytes()),
                envelope.repository.as_str(),
                envelope.target_ref.as_str(),
                envelope.expected_basis.as_str(),
                envelope.patch_digest.to_hex(),
                join_list(&envelope.allowed_paths),
                envelope.created_at.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            envelope.attempt,
            expected_version,
            new_state,
            envelope.created_at,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_commitment(
        &mut self,
        expected_version: u64,
        commitment_record: &Commitment,
        new_state: &AttemptState,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        tx.execute(
            "INSERT INTO commitment
             (attempt, dispatch, target_ref, previous_value, result_commit, journal_digest, at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                id16(commitment_record.attempt.as_bytes()),
                id16(commitment_record.dispatch.as_bytes()),
                commitment_record.target_ref.as_str(),
                commitment_record.previous_value.as_str(),
                commitment_record.result_commit.as_str(),
                commitment_record.journal_digest.to_hex(),
                commitment_record.committed_at.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            commitment_record.attempt,
            expected_version,
            new_state,
            commitment_record.committed_at,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_dispatch_refusal(
        &mut self,
        expected_version: u64,
        refusal: &DispatchRefusalRecord,
        new_state: &AttemptState,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        tx.execute(
            "INSERT INTO dispatch_refusal (attempt, dispatch, ground, journal_digest, at)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                id16(refusal.attempt.as_bytes()),
                id16(refusal.dispatch.as_bytes()),
                ground_tag(refusal.ground),
                refusal.journal_digest.to_hex(),
                refusal.refused_at.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            refusal.attempt,
            expected_version,
            new_state,
            refusal.refused_at,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_indeterminate(
        &mut self,
        expected_version: u64,
        record: &IndeterminateRecord,
        new_state: &AttemptState,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        tx.execute(
            "INSERT INTO indeterminate_outcome (attempt, dispatch, last_journal_digest, at)
             VALUES (?1,?2,?3,?4)",
            params![
                id16(record.attempt.as_bytes()),
                id16(record.dispatch.as_bytes()),
                record.last_journal_digest.as_ref().map(|d| d.to_hex()),
                record.recorded_at.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            record.attempt,
            expected_version,
            new_state,
            record.recorded_at,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_recovery_resolution(
        &mut self,
        expected_version: u64,
        resolution: &RecoveryResolution,
        new_state: &AttemptState,
        consumed_grant: &StandingGrant,
        standing_use: &StandingUse,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        consume_standing(&tx, consumed_grant, standing_use)?;
        tx.execute(
            "INSERT INTO recovery_resolution
             (id, attempt, dispatch, fact, verdict, standing_use, at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                id16(resolution.id.as_bytes()),
                id16(resolution.attempt.as_bytes()),
                id16(resolution.dispatch.as_bytes()),
                id16(resolution.fact.as_bytes()),
                verdict_tag(resolution.verdict),
                id16(resolution.recovery_standing_use.as_bytes()),
                resolution.resolved_at.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            resolution.attempt,
            expected_version,
            new_state,
            resolution.resolved_at,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_recovery_fact(&mut self, fact: &RecoveryFact) -> Result<(), StoreError> {
        let (source_kind, source_detail) = source_tags(&fact.source);
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO recovery_fact
                 (id, attempt, dispatch, prepared_digest, repository, target_ref, basis,
                  observed_ref, expected_result, journal_digest, source_kind, source_detail,
                  recorded_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    id16(fact.id.as_bytes()),
                    id16(fact.attempt.as_bytes()),
                    id16(fact.dispatch.as_bytes()),
                    fact.prepared_attempt_digest.to_hex(),
                    fact.repository.as_str(),
                    fact.target_ref.as_str(),
                    fact.basis.as_str(),
                    fact.observed_ref.as_str(),
                    fact.expected_result_commit
                        .as_ref()
                        .map(|c| c.as_str().to_string()),
                    fact.journal_digest.to_hex(),
                    source_kind,
                    source_detail,
                    fact.recorded_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self.get_recovery_fact(fact.id)?;
            if &existing != fact {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_recovery_fact(&mut self, id: RecoveryFactId) -> Result<RecoveryFact, StoreError> {
        self.conn
            .query_row(
                "SELECT attempt, dispatch, prepared_digest, repository, target_ref, basis,
                        observed_ref, expected_result, journal_digest, source_kind,
                        source_detail, recorded_at
                 FROM recovery_fact WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    Ok(RecoveryFact {
                        id,
                        attempt: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                        dispatch: parse_id16(&r.get::<_, String>(1)?).map_err(sql_corrupt)?,
                        prepared_attempt_digest: parse_digest(&r.get::<_, String>(2)?)
                            .map_err(sql_corrupt)?,
                        repository: repo(&r.get::<_, String>(3)?),
                        target_ref: refname(&r.get::<_, String>(4)?),
                        basis: commit(&r.get::<_, String>(5)?),
                        observed_ref: commit(&r.get::<_, String>(6)?),
                        expected_result_commit: r.get::<_, Option<String>>(7)?.map(|s| commit(&s)),
                        journal_digest: parse_digest(&r.get::<_, String>(8)?)
                            .map_err(sql_corrupt)?,
                        source: parse_source(
                            &r.get::<_, String>(9)?,
                            r.get::<_, Option<String>>(10)?,
                        )
                        .map_err(sql_corrupt)?,
                        recorded_at: ClockReading(r.get::<_, i64>(11)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn record_observation(&mut self, obs: &ObservationRecord) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO observation
                 (id, attempt, argv, workdir, result_commit, environment, exit_status,
                  stdout_digest, stderr_digest, at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    id16(obs.id.as_bytes()),
                    id16(obs.attempt.as_bytes()),
                    join_list(&obs.argv),
                    obs.working_directory_identity,
                    obs.result_commit.as_str(),
                    obs.environment_description,
                    obs.exit_status,
                    obs.stdout_digest.to_hex(),
                    obs.stderr_digest.to_hex(),
                    obs.observed_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self
                .get_observations(obs.attempt)?
                .into_iter()
                .find(|o| o.id == obs.id)
                .ok_or(StoreError::ImmutableRebind)?;
            if &existing != obs {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_observations(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Vec<ObservationRecord>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, argv, workdir, result_commit, environment, exit_status,
                        stdout_digest, stderr_digest, at
                 FROM observation WHERE attempt=?1 ORDER BY at",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![id16(attempt.as_bytes())], |r| {
                Ok(ObservationRecord {
                    id: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                    attempt,
                    argv: split_list(&r.get::<_, String>(1)?),
                    working_directory_identity: r.get(2)?,
                    result_commit: commit(&r.get::<_, String>(3)?),
                    environment_description: r.get(4)?,
                    exit_status: r.get(5)?,
                    stdout_digest: parse_digest(&r.get::<_, String>(6)?).map_err(sql_corrupt)?,
                    stderr_digest: parse_digest(&r.get::<_, String>(7)?).map_err(sql_corrupt)?,
                    observed_at: ClockReading(r.get::<_, i64>(8)? as u64),
                })
            })
            .map_err(backend)?;
        rows.collect::<Result<_, _>>().map_err(backend)
    }

    fn get_commitment(&mut self, attempt: AttemptId) -> Result<Commitment, StoreError> {
        self.conn
            .query_row(
                "SELECT dispatch, target_ref, previous_value, result_commit, journal_digest, at
                 FROM commitment WHERE attempt=?1",
                params![id16(attempt.as_bytes())],
                |r| {
                    Ok(Commitment {
                        attempt,
                        dispatch: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                        target_ref: refname(&r.get::<_, String>(1)?),
                        previous_value: commit(&r.get::<_, String>(2)?),
                        result_commit: commit(&r.get::<_, String>(3)?),
                        journal_digest: parse_digest(&r.get::<_, String>(4)?)
                            .map_err(sql_corrupt)?,
                        committed_at: ClockReading(r.get::<_, i64>(5)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn get_indeterminate(&mut self, attempt: AttemptId) -> Result<IndeterminateRecord, StoreError> {
        self.conn
            .query_row(
                "SELECT dispatch, last_journal_digest, at FROM indeterminate_outcome
                 WHERE attempt=?1",
                params![id16(attempt.as_bytes())],
                |r| {
                    Ok(IndeterminateRecord {
                        attempt,
                        dispatch: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                        last_journal_digest: r
                            .get::<_, Option<String>>(1)?
                            .map(|d| parse_digest(&d).map_err(sql_corrupt))
                            .transpose()?,
                        recorded_at: ClockReading(r.get::<_, i64>(2)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn find_commitment_owner(
        &mut self,
        result_commit: &gwr_core::work_request::CommitHash,
    ) -> Result<Option<AttemptId>, StoreError> {
        self.conn
            .query_row(
                "SELECT attempt FROM commitment WHERE result_commit=?1",
                params![result_commit.as_str()],
                |r| parse_id16::<AttemptId>(&r.get::<_, String>(0)?).map_err(sql_corrupt),
            )
            .optional()
            .map_err(backend)
    }

    fn record_reliance_admission(&mut self, adm: &ReviewQueueAdmission) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO reliance_admission (attempt, observation, result_commit, at)
                 VALUES (?1,?2,?3,?4)",
                params![
                    id16(adm.attempt.as_bytes()),
                    id16(adm.observation.as_bytes()),
                    adm.result_commit.as_str(),
                    adm.admitted_at.0 as i64
                ],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn record_reliance_refusal(
        &mut self,
        attempt: AttemptId,
        refusal: &RelianceRefusal,
        subject: Option<&RelianceSubject>,
        at: ClockReading,
    ) -> Result<(), StoreError> {
        let (kind, detail) = reliance_refusal_tags(refusal);
        let (observation, consumer, claim) = match subject {
            Some(s) => (
                Some(id16(s.observation.as_bytes())),
                Some(s.consumer.clone()),
                Some(s.claim.tag().to_string()),
            ),
            None => (None, None, None),
        };
        self.conn
            .execute(
                "INSERT INTO reliance_refusal (attempt, kind, detail, observation, consumer, \
                 claim, at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id16(attempt.as_bytes()),
                    kind,
                    detail,
                    observation,
                    consumer,
                    claim,
                    at.0 as i64
                ],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn create_residual_obligation(&mut self, ob: &ResidualObligation) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO residual_obligation (id, attempt, kind, at)
                 VALUES (?1,?2,?3,?4)",
                params![
                    id16(ob.id.as_bytes()),
                    id16(ob.attempt.as_bytes()),
                    obligation_tag(ob.kind),
                    ob.recorded_at.0 as i64
                ],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn get_residual_obligations(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Vec<ResidualObligation>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, kind, at FROM residual_obligation WHERE attempt=?1 ORDER BY at")
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![id16(attempt.as_bytes())], |r| {
                Ok(ResidualObligation {
                    id: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                    attempt,
                    kind: parse_obligation_tag(&r.get::<_, String>(1)?).map_err(sql_corrupt)?,
                    recorded_at: ClockReading(r.get::<_, i64>(2)? as u64),
                })
            })
            .map_err(backend)?;
        rows.collect::<Result<_, _>>().map_err(backend)
    }

    fn record_reconciliation(&mut self, rec: &Reconciliation) -> Result<(), StoreError> {
        let retained: Vec<String> = rec
            .retained_obligations
            .iter()
            .map(|o| id16(o.as_bytes()))
            .collect();
        self.conn
            .execute(
                "INSERT OR IGNORE INTO reconciliation (attempt, retained, at) VALUES (?1,?2,?3)",
                params![
                    id16(rec.attempt.as_bytes()),
                    join_list(&retained),
                    rec.reconciled_at.0 as i64
                ],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn timeline(&mut self, attempt: AttemptId) -> Result<Vec<TimelineEntry>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, kind, at FROM timeline WHERE attempt=?1 ORDER BY seq")
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![id16(attempt.as_bytes())], |r| {
                Ok(TimelineEntry {
                    seq: r.get::<_, i64>(0)? as u64,
                    kind: r.get(1)?,
                    at: ClockReading(r.get::<_, i64>(2)? as u64),
                })
            })
            .map_err(backend)?;
        rows.collect::<Result<_, _>>().map_err(backend)
    }

    fn list_attempts(&mut self) -> Result<Vec<AttemptId>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM attempt ORDER BY admitted_at, id")
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |r| {
                parse_id16::<AttemptId>(&r.get::<_, String>(0)?).map_err(sql_corrupt)
            })
            .map_err(backend)?;
        rows.collect::<Result<_, _>>().map_err(backend)
    }

    fn get_ratification(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Option<RatificationReceipt>, StoreError> {
        self.conn
            .query_row(
                "SELECT id, prepared_digest, actor, standing_use, at
                 FROM ratification WHERE attempt=?1",
                params![id16(attempt.as_bytes())],
                |r| {
                    Ok(RatificationReceipt {
                        ratification: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                        attempt,
                        prepared_attempt_digest: parse_digest(&r.get::<_, String>(1)?)
                            .map_err(sql_corrupt)?,
                        actor: parse_id16(&r.get::<_, String>(2)?).map_err(sql_corrupt)?,
                        standing_use: parse_id16(&r.get::<_, String>(3)?).map_err(sql_corrupt)?,
                        clock_reading: ClockReading(r.get::<_, i64>(4)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)
    }

    fn get_standing_use(&mut self, id: StandingUseId) -> Result<Option<StandingUse>, StoreError> {
        self.conn
            .query_row(
                "SELECT grant_id, used_at FROM standing_use WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    Ok(StandingUse {
                        id,
                        grant: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                        used_at: ClockReading(r.get::<_, i64>(1)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)
    }

    fn get_dispatch_refusal(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Option<DispatchRefusalRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT dispatch, ground, journal_digest, at FROM dispatch_refusal
                 WHERE attempt=?1",
                params![id16(attempt.as_bytes())],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(backend)?
            .map(|(dispatch, ground, journal, at)| {
                Ok(DispatchRefusalRecord {
                    attempt,
                    dispatch: parse_id16(&dispatch)
                        .map_err(|e| StoreError::Corrupt(e.to_string()))?,
                    ground: parse_ground_tag(&ground)?,
                    journal_digest: parse_digest(&journal)
                        .map_err(|e| StoreError::Corrupt(e.to_string()))?,
                    refused_at: ClockReading(at as u64),
                })
            })
            .transpose()
    }

    fn get_recovery_facts(&mut self, attempt: AttemptId) -> Result<Vec<RecoveryFact>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, dispatch, prepared_digest, repository, target_ref, basis,
                        observed_ref, expected_result, journal_digest, source_kind,
                        source_detail, recorded_at
                 FROM recovery_fact WHERE attempt=?1 ORDER BY recorded_at, id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![id16(attempt.as_bytes())], |r| {
                Ok(RecoveryFact {
                    id: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                    attempt,
                    dispatch: parse_id16(&r.get::<_, String>(1)?).map_err(sql_corrupt)?,
                    prepared_attempt_digest: parse_digest(&r.get::<_, String>(2)?)
                        .map_err(sql_corrupt)?,
                    repository: repo(&r.get::<_, String>(3)?),
                    target_ref: refname(&r.get::<_, String>(4)?),
                    basis: commit(&r.get::<_, String>(5)?),
                    observed_ref: commit(&r.get::<_, String>(6)?),
                    expected_result_commit: r.get::<_, Option<String>>(7)?.map(|s| commit(&s)),
                    journal_digest: parse_digest(&r.get::<_, String>(8)?).map_err(sql_corrupt)?,
                    source: parse_source(&r.get::<_, String>(9)?, r.get::<_, Option<String>>(10)?)
                        .map_err(sql_corrupt)?,
                    recorded_at: ClockReading(r.get::<_, i64>(11)? as u64),
                })
            })
            .map_err(backend)?;
        rows.collect::<Result<_, _>>().map_err(backend)
    }

    fn get_recovery_resolution(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Option<RecoveryResolution>, StoreError> {
        self.conn
            .query_row(
                "SELECT id, dispatch, fact, verdict, standing_use, at
                 FROM recovery_resolution WHERE attempt=?1",
                params![id16(attempt.as_bytes())],
                |r| {
                    Ok(RecoveryResolution {
                        id: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                        attempt,
                        dispatch: parse_id16(&r.get::<_, String>(1)?).map_err(sql_corrupt)?,
                        fact: parse_id16(&r.get::<_, String>(2)?).map_err(sql_corrupt)?,
                        verdict: parse_verdict_tag(&r.get::<_, String>(3)?).map_err(sql_corrupt)?,
                        recovery_standing_use: parse_id16(&r.get::<_, String>(4)?)
                            .map_err(sql_corrupt)?,
                        resolved_at: ClockReading(r.get::<_, i64>(5)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)
    }

    fn get_reliance_admissions(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Vec<ReviewQueueAdmission>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT observation, result_commit, at FROM reliance_admission
                 WHERE attempt=?1 ORDER BY at",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![id16(attempt.as_bytes())], |r| {
                Ok(ReviewQueueAdmission {
                    attempt,
                    observation: parse_id16(&r.get::<_, String>(0)?).map_err(sql_corrupt)?,
                    result_commit: commit(&r.get::<_, String>(1)?),
                    admitted_at: ClockReading(r.get::<_, i64>(2)? as u64),
                })
            })
            .map_err(backend)?;
        rows.collect::<Result<_, _>>().map_err(backend)
    }

    fn get_reliance_refusals(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Vec<RelianceRefusalRecord>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT kind, detail, observation, consumer, claim, at FROM reliance_refusal
                 WHERE attempt=?1 ORDER BY id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![id16(attempt.as_bytes())], |r| {
                let kind: String = r.get(0)?;
                let detail: Option<String> = r.get(1)?;
                let observation: Option<String> = r.get(2)?;
                let consumer: Option<String> = r.get(3)?;
                let claim: Option<String> = r.get(4)?;
                let refusal =
                    parse_reliance_refusal(&kind, detail.as_deref()).map_err(sql_corrupt)?;
                // Subject columns were added by migration 0002. Rows written
                // before it genuinely lack a subject; a row with only part of
                // one is corrupt, not defaulted.
                let subject = match (observation, consumer, claim) {
                    (None, None, None) => None,
                    (Some(o), Some(c), Some(cl)) => Some(RelianceSubject {
                        observation: parse_id16(&o).map_err(sql_corrupt)?,
                        consumer: c,
                        claim: parse_claim_tag(&cl).map_err(sql_corrupt)?,
                    }),
                    _ => {
                        return Err(sql_corrupt(CorruptColumn(
                            "partial reliance-refusal subject".into(),
                        )))
                    }
                };
                Ok(RelianceRefusalRecord {
                    attempt,
                    refusal,
                    subject,
                    at: ClockReading(r.get::<_, i64>(5)? as u64),
                })
            })
            .map_err(backend)?;
        rows.collect::<Result<_, _>>().map_err(backend)
    }

    fn get_reconciliation(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Option<Reconciliation>, StoreError> {
        self.conn
            .query_row(
                "SELECT retained, at FROM reconciliation WHERE attempt=?1",
                params![id16(attempt.as_bytes())],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(backend)?
            .map(|(retained, at)| {
                let retained_obligations = split_list(&retained)
                    .iter()
                    .map(|o| {
                        parse_id16::<ObligationId>(o)
                            .map_err(|e| StoreError::Corrupt(e.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Reconciliation {
                    attempt,
                    retained_obligations,
                    reconciled_at: ClockReading(at as u64),
                })
            })
            .transpose()
    }

    fn record_authz_issuance(&mut self, i: &AcceptedIssuance) -> Result<(), StoreError> {
        let (kinds, statements): (Vec<String>, Vec<String>) = i
            .premises
            .iter()
            .map(|p| (p.kind.clone(), p.statement.clone()))
            .unzip();
        // Residual items are stored as one length-prefixed list of five-field
        // groups, in the upstream's own vocabulary — never mapped onto Docket's
        // obligation kinds.
        let mut residual_fields: Vec<String> = Vec::new();
        for r in &i.residuals {
            residual_fields.push(r.source_system.clone());
            residual_fields.push(r.obligation_id.clone());
            residual_fields.push(r.subject.clone());
            residual_fields.push(r.kind.clone());
            residual_fields.push(r.statement.clone());
        }
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO authz_issuance
                 (issuance_id, attempt, decision_id, issuer_principal, issuer_key_id,
                  target_id, request_raw_sha256, request_upstream_digest, prepared_digest,
                  requested_actor, issued_at, expires_at, premise_kinds, premise_statements,
                  residual_status, residual_items, consumption_ledger, consumption_use_digest,
                  body_b64, accepted_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
                params![
                    i.issuance_id,
                    id16(i.attempt.as_bytes()),
                    i.decision_id,
                    i.issuer_principal,
                    i.issuer_key_id,
                    i.target_id,
                    i.request_raw_sha256,
                    i.request_upstream_digest,
                    i.prepared_digest.to_hex(),
                    i.requested_actor,
                    i.issued_at.0 as i64,
                    i.expires_at.0 as i64,
                    join_list(&kinds),
                    join_list(&statements),
                    i.residual_status.tag(),
                    join_list(&residual_fields),
                    i.consumption_ledger,
                    i.consumption_use_digest,
                    i.body_b64,
                    i.accepted_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            // An identity already present must name exactly the same accepted
            // record; a different body under the same identity is substitution.
            let existing = self.get_authz_issuance(&i.issuance_id)?;
            match existing {
                Some(e) if e.body_b64 == i.body_b64 && e.attempt == i.attempt => Ok(()),
                Some(_) => Err(StoreError::ImmutableRebind),
                None => Err(StoreError::Backend(
                    "issuance insert reported no change but no row exists".into(),
                )),
            }
        } else {
            Ok(())
        }
    }

    fn get_authz_issuance(
        &mut self,
        issuance_id: &str,
    ) -> Result<Option<AcceptedIssuance>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT attempt, decision_id, issuer_principal, issuer_key_id, target_id,
                        request_raw_sha256, request_upstream_digest, prepared_digest,
                        requested_actor, issued_at, expires_at, premise_kinds,
                        premise_statements, residual_status, residual_items,
                        consumption_ledger, consumption_use_digest, body_b64, accepted_at
                 FROM authz_issuance WHERE issuance_id=?1",
                params![issuance_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, String>(8)?,
                        r.get::<_, i64>(9)?,
                        r.get::<_, i64>(10)?,
                        r.get::<_, String>(11)?,
                        r.get::<_, String>(12)?,
                        r.get::<_, String>(13)?,
                        r.get::<_, String>(14)?,
                        r.get::<_, String>(15)?,
                        r.get::<_, String>(16)?,
                        r.get::<_, String>(17)?,
                        r.get::<_, i64>(18)?,
                    ))
                },
            )
            .optional()
            .map_err(backend)?;
        let Some(row) = row else { return Ok(None) };
        let kinds = split_list(&row.11);
        let statements = split_list(&row.12);
        if kinds.len() != statements.len() {
            return Err(StoreError::Corrupt(
                "authz_issuance premise columns disagree in length".into(),
            ));
        }
        let residual_fields = split_list(&row.14);
        if !residual_fields.len().is_multiple_of(5) {
            return Err(StoreError::Corrupt(
                "authz_issuance residual items are not whole five-field groups".into(),
            ));
        }
        let residual_status = UpstreamResidualStatus::from_tag(&row.13)
            .ok_or_else(|| StoreError::Corrupt(format!("unknown residual status {:?}", row.13)))?;
        Ok(Some(AcceptedIssuance {
            issuance_id: issuance_id.to_string(),
            attempt: parse_id16(&row.0).map_err(|e| StoreError::Corrupt(e.to_string()))?,
            decision_id: row.1,
            issuer_principal: row.2,
            issuer_key_id: row.3,
            target_id: row.4,
            request_raw_sha256: row.5,
            request_upstream_digest: row.6,
            prepared_digest: parse_digest(&row.7)
                .map_err(|e| StoreError::Corrupt(e.to_string()))?,
            requested_actor: row.8,
            issued_at: ClockReading(row.9 as u64),
            expires_at: ClockReading(row.10 as u64),
            premises: kinds
                .into_iter()
                .zip(statements)
                .map(|(kind, statement)| UpstreamPremise { kind, statement })
                .collect(),
            residual_status,
            residuals: residual_fields
                .chunks(5)
                .map(|c| UpstreamResidual {
                    source_system: c[0].clone(),
                    obligation_id: c[1].clone(),
                    subject: c[2].clone(),
                    kind: c[3].clone(),
                    statement: c[4].clone(),
                })
                .collect(),
            consumption_ledger: row.15,
            consumption_use_digest: row.16,
            body_b64: row.17,
            accepted_at: ClockReading(row.18 as u64),
        }))
    }

    fn find_attempt_issuance(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Option<AcceptedIssuance>, StoreError> {
        let id: Option<String> = self
            .conn
            .query_row(
                "SELECT issuance_id FROM authz_issuance WHERE attempt=?1
                 ORDER BY accepted_at, issuance_id LIMIT 1",
                params![id16(attempt.as_bytes())],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        match id {
            Some(id) => self.get_authz_issuance(&id),
            None => Ok(None),
        }
    }

    fn create_upstream_standing_grant(
        &mut self,
        grant: &StandingGrant,
        issuance_id: &str,
    ) -> Result<(), StoreError> {
        // One issuance justifies at most one grant, across attempts and
        // repetitions. Checked explicitly so the refusal is legible rather than
        // an ignored insert.
        let existing_for_issuance: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM standing_grant WHERE issuance_id=?1",
                params![issuance_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        if let Some(existing) = existing_for_issuance {
            if existing != id16(grant.id().as_bytes()) {
                return Err(StoreError::ImmutableRebind);
            }
            return Ok(());
        }
        let tx = self.tx()?;
        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO standing_grant
                 (id, actor, act, repository, attempt_digest, expires_at, source, issuance_id)
                 VALUES (?1,?2,?3,?4,?5,?6,'upstream',?7)",
                params![
                    id16(grant.id().as_bytes()),
                    id16(grant.scope().actor.as_bytes()),
                    act_tag(grant.scope().act),
                    grant.scope().repository.as_str(),
                    grant.scope().attempt_digest.to_hex(),
                    grant.expires_at().0 as i64,
                    issuance_id
                ],
            )
            .map_err(|e| {
                if e.to_string().contains("UNIQUE") {
                    StoreError::ImmutableRebind
                } else {
                    backend(e)
                }
            })?;
        if changed == 0 {
            drop(tx);
            let existing = self.get_standing_grant(grant.id())?;
            if existing.scope() != grant.scope() || existing.expires_at() != grant.expires_at() {
                return Err(StoreError::ImmutableRebind);
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO standing_projection (grant_id, consumed_by, version) VALUES (?1, NULL, 0)",
            params![id16(grant.id().as_bytes())],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    fn get_grant_authorization(
        &mut self,
        grant: StandingGrantId,
    ) -> Result<Option<(AuthorizationSource, Option<String>)>, StoreError> {
        let row: Option<(Option<String>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT source, issuance_id FROM standing_grant WHERE id=?1",
                params![id16(grant.as_bytes())],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(backend)?;
        match row {
            None | Some((None, _)) => Ok(None),
            Some((Some(tag), issuance)) => {
                let source = AuthorizationSource::from_tag(&tag).ok_or_else(|| {
                    StoreError::Corrupt(format!("unknown authorization source {tag:?}"))
                })?;
                Ok(Some((source, issuance)))
            }
        }
    }

    // Campaign-stage standing (S-2). Content-addressed records: every read
    // recomputes the digest from the persisted fields and a mismatch is a
    // typed corruption error, never a silently altered record.

    fn record_campaign_proposal(&mut self, p: &CampaignStageProposal) -> Result<(), StoreError> {
        let (basis_kind, basis_identity, basis_stage, basis_adjudication) = encode_basis(&p.basis);
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO campaign_stage_proposal
                 (digest, upstream_digest, campaign, stage, stage_class, role, effect_class,
                  basis_kind, basis_identity, basis_stage, basis_adjudication,
                  repositories, allowed_paths, evidence_contract, handoff_schema,
                  expires_at, nonce, isolated_worktree, review_requirement, nonclaims,
                  repair_basis, proposed_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
                params![
                    p.digest.to_hex(),
                    p.upstream_digest,
                    p.campaign,
                    p.stage,
                    stage_class_tag(p.stage_class),
                    role_tag(p.role),
                    stage_effect_tag(p.effect_class),
                    basis_kind,
                    basis_identity,
                    basis_stage,
                    basis_adjudication,
                    encode_pins(&p.repositories),
                    join_list(&p.allowed_paths),
                    p.evidence_contract,
                    p.handoff_schema,
                    p.expires_at.0 as i64,
                    p.nonce,
                    p.isolated_worktree,
                    review_requirement_tag(p.review_requirement),
                    join_list(&p.nonclaims),
                    p.repair.as_ref().map(encode_repair_basis),
                    p.proposed_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self
                .get_campaign_proposal(&p.digest)?
                .ok_or_else(|| StoreError::Corrupt("campaign proposal vanished".into()))?;
            if &existing != p {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_campaign_proposal(
        &mut self,
        digest: &Sha256Digest,
    ) -> Result<Option<CampaignStageProposal>, StoreError> {
        let row: Option<CampaignStageProposal> = self
            .conn
            .query_row(
                "SELECT upstream_digest, campaign, stage, stage_class, role, effect_class,
                        basis_kind, basis_identity, basis_stage, basis_adjudication,
                        repositories, allowed_paths, evidence_contract, handoff_schema,
                        expires_at, nonce, isolated_worktree, review_requirement, nonclaims,
                        repair_basis, proposed_at
                 FROM campaign_stage_proposal WHERE digest=?1",
                params![digest.to_hex()],
                |r| proposal_from_row(*digest, r),
            )
            .optional()
            .map_err(backend)?;
        match row {
            Some(p) if p.recompute_digest() != p.digest => Err(StoreError::Corrupt(format!(
                "campaign proposal {} fields do not recompute to their digest",
                p.digest
            ))),
            other => Ok(other),
        }
    }

    fn find_campaign_proposals(
        &mut self,
        campaign: &str,
        stage: &str,
    ) -> Result<Vec<CampaignStageProposal>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT digest, upstream_digest, campaign, stage, stage_class, role, effect_class,
                        basis_kind, basis_identity, basis_stage, basis_adjudication,
                        repositories, allowed_paths, evidence_contract, handoff_schema,
                        expires_at, nonce, isolated_worktree, review_requirement, nonclaims,
                        repair_basis, proposed_at
                 FROM campaign_stage_proposal WHERE campaign=?1 AND stage=?2
                 ORDER BY proposed_at, rowid",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![campaign, stage], |r| {
                let digest = parse_digest(&r.get::<_, String>(0)?).map_err(sql_corrupt)?;
                proposal_from_row_at(digest, r, 1)
            })
            .map_err(backend)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(backend)
    }

    fn record_campaign_standing(&mut self, s: &CampaignStageStanding) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO campaign_stage_standing
                 (digest, proposal_digest, upstream_digest, campaign, stage, stage_class,
                  role, effect_class, repositories, allowed_paths, expires_at, nonce, issued_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    s.digest().to_hex(),
                    s.proposal_digest().to_hex(),
                    s.upstream_digest(),
                    s.campaign(),
                    s.stage(),
                    stage_class_tag(s.stage_class()),
                    role_tag(s.role()),
                    stage_effect_tag(s.effect_class()),
                    encode_pins(s.repositories()),
                    join_list(s.allowed_paths()),
                    s.expires_at().0 as i64,
                    s.nonce(),
                    s.issued_at().0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self
                .get_campaign_standing(&s.digest())?
                .ok_or_else(|| StoreError::Corrupt("campaign standing vanished".into()))?;
            let mut existing_available = existing.clone();
            if let CampaignStandingState::Consumed { .. } = existing.state() {
                // The standing row is immutable; consumption state lives in
                // the consumption table and is not part of the comparison.
                existing_available = CampaignStageStanding::from_persisted(
                    existing.digest(),
                    existing.proposal_digest(),
                    existing.upstream_digest().to_string(),
                    existing.campaign().to_string(),
                    existing.stage().to_string(),
                    existing.stage_class(),
                    existing.role(),
                    existing.effect_class(),
                    existing.repositories().to_vec(),
                    existing.allowed_paths().to_vec(),
                    existing.expires_at(),
                    existing.nonce().to_string(),
                    existing.issued_at(),
                    CampaignStandingState::Available,
                );
            }
            if &existing_available != s {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_campaign_standing(
        &mut self,
        digest: &Sha256Digest,
    ) -> Result<Option<CampaignStageStanding>, StoreError> {
        self.conn
            .query_row(
                "SELECT s.proposal_digest, s.upstream_digest, s.campaign, s.stage,
                        s.stage_class, s.role, s.effect_class, s.repositories, s.allowed_paths,
                        s.expires_at, s.nonce, s.issued_at, c.digest
                 FROM campaign_stage_standing s
                 LEFT JOIN campaign_stage_consumption c ON c.standing = s.digest
                 WHERE s.digest=?1",
                params![digest.to_hex()],
                |r| standing_from_row(*digest, r),
            )
            .optional()
            .map_err(backend)?
            .map(|s| {
                if s.recompute_digest() != s.digest() {
                    return Err(StoreError::Corrupt(format!(
                        "campaign standing {} fields do not recompute to their digest",
                        s.digest()
                    )));
                }
                Ok(s)
            })
            .transpose()
    }

    fn latest_campaign_standing(
        &mut self,
        campaign: &str,
        stage: &str,
    ) -> Result<Option<CampaignStageStanding>, StoreError> {
        self.conn
            .query_row(
                "SELECT s.digest, s.proposal_digest, s.upstream_digest, s.campaign, s.stage,
                        s.stage_class, s.role, s.effect_class, s.repositories, s.allowed_paths,
                        s.expires_at, s.nonce, s.issued_at, c.digest
                 FROM campaign_stage_standing s
                 LEFT JOIN campaign_stage_consumption c ON c.standing = s.digest
                 WHERE s.campaign=?1 AND s.stage=?2
                 ORDER BY s.issued_at DESC, s.rowid DESC LIMIT 1",
                params![campaign, stage],
                |r| {
                    let digest = parse_digest(&r.get::<_, String>(0)?).map_err(sql_corrupt)?;
                    standing_from_row_shifted(digest, r)
                },
            )
            .optional()
            .map_err(backend)
    }

    fn record_campaign_consumption(
        &mut self,
        c: &CampaignStageConsumption,
    ) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO campaign_stage_consumption
                 (standing, digest, campaign, stage, role, consumed_at, effect_completed, receipt)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    c.standing.to_hex(),
                    c.digest.to_hex(),
                    c.campaign,
                    c.stage,
                    role_tag(c.role),
                    c.consumed_at.0 as i64,
                    c.effect_completed as i64,
                    c.receipt.map(|r| r.to_hex())
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self
                .get_campaign_consumption(&c.standing)?
                .ok_or_else(|| StoreError::Corrupt("campaign consumption vanished".into()))?;
            if &existing != c {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_campaign_consumption(
        &mut self,
        standing: &Sha256Digest,
    ) -> Result<Option<CampaignStageConsumption>, StoreError> {
        self.conn
            .query_row(
                "SELECT digest, campaign, stage, role, consumed_at, effect_completed, receipt
                 FROM campaign_stage_consumption WHERE standing=?1",
                params![standing.to_hex()],
                |r| consumption_from_row_at(*standing, r, 0),
            )
            .optional()
            .map_err(backend)
    }

    fn burn_campaign_standing(
        &mut self,
        standing: &CampaignStageStanding,
        record: &CampaignStageConsumption,
    ) -> Result<CampaignBurn, StoreError> {
        // One immediate transaction: SQLite serializes writers, so the
        // check-and-insert below is atomic across threads, processes, and
        // service instances. Exactly one concurrent caller inserts the row.
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(backend)?;
        // Supersession, decided inside the transaction.
        let latest: Option<(String, i64)> = tx
            .query_row(
                "SELECT digest, issued_at FROM campaign_stage_standing
                 WHERE campaign=?1 AND stage=?2
                 ORDER BY issued_at DESC, rowid DESC LIMIT 1",
                params![standing.campaign(), standing.stage()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(backend)?;
        if let Some((digest, issued_at)) = latest {
            if digest != standing.digest().to_hex() && issued_at as u64 > standing.issued_at().0 {
                return Ok(CampaignBurn::Superseded);
            }
        }
        // An existing burn is returned for exact classification, never
        // overwritten and never a second success.
        let existing = tx
            .query_row(
                "SELECT digest, campaign, stage, role, consumed_at, effect_completed, receipt
                 FROM campaign_stage_consumption WHERE standing=?1",
                params![standing.digest().to_hex()],
                |r| consumption_from_row_at(standing.digest(), r, 0),
            )
            .optional()
            .map_err(backend)?;
        if let Some(row) = existing {
            return Ok(CampaignBurn::Existing(row));
        }
        tx.execute(
            "INSERT INTO campaign_stage_consumption
             (standing, digest, campaign, stage, role, consumed_at, effect_completed, receipt)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                record.standing.to_hex(),
                record.digest.to_hex(),
                record.campaign,
                record.stage,
                role_tag(record.role),
                record.consumed_at.0 as i64,
                record.effect_completed as i64,
                record.receipt.map(|r| r.to_hex())
            ],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)?;
        Ok(CampaignBurn::Burned)
    }

    fn mark_campaign_effect_completed(
        &mut self,
        standing: &Sha256Digest,
    ) -> Result<(), StoreError> {
        self.conn
            .execute(
                "UPDATE campaign_stage_consumption SET effect_completed=1 WHERE standing=?1",
                params![standing.to_hex()],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn record_campaign_receipt(
        &mut self,
        standing: &Sha256Digest,
        receipt: &Sha256Digest,
    ) -> Result<(), StoreError> {
        let existing: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT receipt FROM campaign_stage_consumption WHERE standing=?1",
                params![standing.to_hex()],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        let Some(existing) = existing else {
            return Err(StoreError::NotFound);
        };
        if let Some(h) = &existing {
            if h != &receipt.to_hex() {
                // A recorded receipt is immutable testimony about which
                // consuming receipt this burn's effect produced.
                return Err(StoreError::ImmutableRebind);
            }
        }
        self.conn
            .execute(
                "UPDATE campaign_stage_consumption SET effect_completed=1, receipt=?2
                 WHERE standing=?1",
                params![standing.to_hex(), receipt.to_hex()],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn campaign_stage_receipts(
        &mut self,
        campaign: &str,
        stage: &str,
    ) -> Result<Vec<Sha256Digest>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT receipt FROM campaign_stage_consumption
                 WHERE campaign=?1 AND stage=?2 AND receipt IS NOT NULL ORDER BY consumed_at",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![campaign, stage], |r| {
                parse_digest(&r.get::<_, String>(0)?).map_err(sql_corrupt)
            })
            .map_err(backend)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(backend)
    }

    fn record_campaign_adjudication(&mut self, a: &AdjudicationReceipt) -> Result<(), StoreError> {
        let tx = self.tx()?;
        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO campaign_stage_adjudication
                 (digest, campaign, stage, review_receipt, verdict, adjudicator, findings,
                  residuals, adjudicated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    a.digest.to_hex(),
                    a.campaign,
                    a.stage,
                    a.review_receipt.to_hex(),
                    adjudication_verdict_tag(a.verdict),
                    a.adjudicator,
                    join_list(&a.findings),
                    encode_residuals(&a.residuals),
                    a.adjudicated_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            drop(tx);
            let existing = self
                .find_campaign_adjudication(&a.campaign, &a.stage, &a.review_receipt)?
                .filter(|e| e.digest == a.digest)
                .ok_or_else(|| StoreError::Corrupt("campaign adjudication vanished".into()))?;
            if &existing != a {
                return Err(StoreError::ImmutableRebind);
            }
            return Ok(());
        }
        for r in &a.residuals {
            tx.execute(
                "INSERT INTO campaign_residual_obligation
                 (adjudication, campaign, stage, kind, statement, at)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    a.digest.to_hex(),
                    a.campaign,
                    a.stage,
                    r.kind,
                    r.statement,
                    a.adjudicated_at.0 as i64
                ],
            )
            .map_err(backend)?;
        }
        tx.commit().map_err(backend)
    }

    fn get_campaign_adjudications(
        &mut self,
        campaign: &str,
        stage: &str,
    ) -> Result<Vec<AdjudicationReceipt>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT digest, campaign, stage, review_receipt, verdict, adjudicator, findings,
                        residuals, adjudicated_at
                 FROM campaign_stage_adjudication WHERE campaign=?1 AND stage=?2
                 ORDER BY adjudicated_at, rowid",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![campaign, stage], adjudication_from_row)
            .map_err(backend)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(backend)
    }

    fn find_campaign_adjudication(
        &mut self,
        campaign: &str,
        stage: &str,
        review_receipt: &Sha256Digest,
    ) -> Result<Option<AdjudicationReceipt>, StoreError> {
        self.conn
            .query_row(
                "SELECT digest, campaign, stage, review_receipt, verdict, adjudicator, findings,
                        residuals, adjudicated_at
                 FROM campaign_stage_adjudication
                 WHERE campaign=?1 AND stage=?2 AND review_receipt=?3
                 ORDER BY adjudicated_at, rowid LIMIT 1",
                params![campaign, stage, review_receipt.to_hex()],
                adjudication_from_row,
            )
            .optional()
            .map_err(backend)
    }

    fn get_campaign_adjudication(
        &mut self,
        digest: &Sha256Digest,
    ) -> Result<Option<AdjudicationReceipt>, StoreError> {
        self.conn
            .query_row(
                "SELECT digest, campaign, stage, review_receipt, verdict, adjudicator, findings,
                        residuals, adjudicated_at
                 FROM campaign_stage_adjudication WHERE digest=?1",
                params![digest.to_hex()],
                adjudication_from_row,
            )
            .optional()
            .map_err(backend)?
            .map(|a| {
                if a.recompute_digest() != a.digest {
                    return Err(StoreError::Corrupt(format!(
                        "campaign adjudication {} fields do not recompute to their digest",
                        a.digest
                    )));
                }
                Ok(a)
            })
            .transpose()
    }

    fn find_campaign_consumptions_by_receipt(
        &mut self,
        campaign: &str,
        stage: &str,
        receipt: &Sha256Digest,
    ) -> Result<Vec<CampaignStageConsumption>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT standing, digest, campaign, stage, role, consumed_at, effect_completed,
                        receipt
                 FROM campaign_stage_consumption
                 WHERE campaign=?1 AND stage=?2 AND receipt=?3
                 ORDER BY consumed_at, rowid",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![campaign, stage, receipt.to_hex()], |r| {
                let standing = parse_digest(&r.get::<_, String>(0)?).map_err(sql_corrupt)?;
                consumption_from_row_at(standing, r, 1)
            })
            .map_err(backend)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(backend)
    }

    fn get_campaign_residuals(
        &mut self,
        campaign: &str,
        stage: &str,
    ) -> Result<Vec<gwr_core::campaign::adjudication::ResidualStatement>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT kind, statement FROM campaign_residual_obligation
                 WHERE campaign=?1 AND stage=?2 ORDER BY at, rowid",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![campaign, stage], |r| {
                Ok(gwr_core::campaign::adjudication::ResidualStatement {
                    kind: r.get(0)?,
                    statement: r.get(1)?,
                })
            })
            .map_err(backend)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(backend)
    }
}
