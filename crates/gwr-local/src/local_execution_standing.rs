//! Narrow prospective execution standing for one Docket deployment.

use gwr_runtime::governed_loop::{
    hash_domain, require_digest, ExecutionStandingRequestV1, ExecutionStandingResolutionV1,
    ExecutionStandingStatusV1, STANDING_RESOLUTION_SCHEMA_V1,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

pub const MAX_GRANT_LIFETIME_MS: u64 = 300_000;
pub const MIGRATION: &str = include_str!("../migrations/0007_local_execution_standing.sql");

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantIdentity<'a> {
    schema: &'static str,
    operator: &'a str,
    campaign: &'a str,
    occurrence: &'a str,
    program: &'a str,
    work_schema: &'a str,
    work: &'a str,
    subject: &'a str,
    scope: &'a str,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalResolverConfigV1 {
    pub schema: String,
    pub state_database: PathBuf,
    pub operator: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCustodySnapshotV1 {
    pub schema: String,
    pub issuance: String,
    pub execution_standing: String,
    pub revision: u64,
    pub status: String,
    pub resolved_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub currentness: String,
    pub resolution: String,
}

#[derive(Clone, Debug)]
pub struct GrantInput<'a> {
    pub operator: &'a str,
    pub campaign: &'a str,
    pub occurrence: &'a str,
    pub program: &'a str,
    pub work_schema: &'a str,
    pub work: &'a str,
    pub subject: &'a str,
    pub scope: &'a str,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

fn i64v(value: u64) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| "local-standing-time-range".to_owned())
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| format!("local-standing-canonical:{e}"))
}

fn revision_identity(id: &str, revision: u64, status: &str, changed: u64) -> String {
    hash_domain(
        "docket.governed-loop.local-standing-revision/v1",
        format!("{id}\0{revision}\0{status}\0{changed}").as_bytes(),
    )
}

fn currentness(
    id: &str,
    revision: u64,
    revision_identity: &str,
    status: &str,
    resolved: u64,
    expires: u64,
) -> String {
    hash_domain(
        "docket.governed-loop.local-standing-currentness/v1",
        format!("{id}\0{revision}\0{revision_identity}\0{status}\0{resolved}\0{expires}")
            .as_bytes(),
    )
}

pub fn migrate(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| format!("local-standing-migrate-lock:{e}"))?;
    let result = (|| {
        connection
            .execute_batch(MIGRATION)
            .map_err(|e| format!("local-standing-migrate:{e}"))?;
        let has_attempt:i64=connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='governed_loop_attempt'",[],|r|r.get(0)).map_err(|e|format!("local-standing-mode-table-check:{e}"))?;
        let has_mode:i64=connection.query_row("SELECT COUNT(*) FROM pragma_table_info('governed_loop_attempt') WHERE name='local_standing_mode'",[],|r|r.get(0)).map_err(|e|format!("local-standing-mode-check:{e}"))?;
        if has_attempt == 1 && has_mode == 0 {
            connection.execute("ALTER TABLE governed_loop_attempt ADD COLUMN local_standing_mode INTEGER NOT NULL DEFAULT 0 CHECK(local_standing_mode IN (0,1))",[]).map_err(|e|format!("local-standing-mode-add:{e}"))?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => connection
            .execute_batch("COMMIT")
            .map_err(|e| format!("local-standing-migrate-commit:{e}")),
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

pub fn grant_identity(input: &GrantInput<'_>) -> Result<String, String> {
    let identity = GrantIdentity {
        schema: "docket.governed-loop.local-execution-standing-grant/v1",
        operator: input.operator,
        campaign: input.campaign,
        occurrence: input.occurrence,
        program: input.program,
        work_schema: input.work_schema,
        work: input.work,
        subject: input.subject,
        scope: input.scope,
        issued_at_unix_ms: input.issued_at_unix_ms,
        expires_at_unix_ms: input.expires_at_unix_ms,
    };
    Ok(hash_domain(
        "docket.governed-loop.local-execution-standing/v1",
        &canonical(&identity)?,
    ))
}

pub fn grant(database: &Path, input: &GrantInput<'_>) -> Result<String, String> {
    if input.operator.is_empty()
        || input.operator.len() > 256
        || !input
            .operator
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'/'))
    {
        return Err("local-standing-operator".to_owned());
    }
    for (v, name) in [
        (input.campaign, "campaign"),
        (input.program, "program"),
        (input.work, "work"),
        (input.subject, "subject"),
        (input.scope, "scope"),
    ] {
        require_digest(v, name)?;
    }
    if input.occurrence.len() != 36
        || input.occurrence.bytes().enumerate().any(|(n, b)| {
            if matches!(n, 8 | 13 | 18 | 23) {
                b != b'-'
            } else {
                !(b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
        })
    {
        return Err("local-standing-occurrence".to_owned());
    }
    if input.work_schema.is_empty()
        || input.work_schema.len() > 128
        || !input
            .work_schema
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
    {
        return Err("local-standing-work-schema".to_owned());
    }
    if input.expires_at_unix_ms <= input.issued_at_unix_ms
        || input.expires_at_unix_ms - input.issued_at_unix_ms > MAX_GRANT_LIFETIME_MS
    {
        return Err("local-standing-lifetime".to_owned());
    }
    let id = grant_identity(input)?;
    let cur = revision_identity(&id, 1, "current", input.issued_at_unix_ms);
    let mut db = Connection::open(database).map_err(|e| format!("local-standing-open:{e}"))?;
    db.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| e.to_string())?;
    migrate(&db)?;
    let tx = db
        .transaction()
        .map_err(|e| format!("local-standing-transaction:{e}"))?;
    tx.execute(
        "INSERT OR IGNORE INTO local_execution_standing_deployment
         (singleton,mode,operator,max_lifetime_ms) VALUES (1,'snapshot_currentness',?1,300000)",
        [input.operator],
    )
    .map_err(|e| format!("local-standing-enrollment:{e}"))?;
    let enrolled: String = tx
        .query_row(
            "SELECT operator FROM local_execution_standing_deployment WHERE singleton=1
         AND mode='snapshot_currentness' AND max_lifetime_ms=300000",
            [],
            |r| r.get(0),
        )
        .map_err(|e| format!("local-standing-enrollment-read:{e}"))?;
    if enrolled != input.operator {
        return Err("local-standing-operator-enrollment-mismatch".to_owned());
    }
    tx.execute(
        "INSERT INTO local_execution_standing_grant VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            id,
            input.operator,
            input.campaign,
            input.occurrence,
            input.program,
            input.work_schema,
            input.work,
            input.subject,
            input.scope,
            i64v(input.issued_at_unix_ms)?,
            i64v(input.expires_at_unix_ms)?
        ],
    )
    .map_err(|e| format!("local-standing-grant:{e}"))?;
    tx.execute(
        "INSERT INTO local_execution_standing_revision VALUES (?1,1,'current',?2,?3)",
        params![id, i64v(input.issued_at_unix_ms)?, cur],
    )
    .map_err(|e| format!("local-standing-revision:{e}"))?;
    tx.execute(
        "INSERT INTO local_execution_standing_projection VALUES (?1,1)",
        params![id],
    )
    .map_err(|e| format!("local-standing-projection:{e}"))?;
    tx.commit()
        .map_err(|e| format!("local-standing-commit:{e}"))?;
    Ok(id)
}

pub fn transition(database: &Path, id: &str, status: &str, at: u64) -> Result<u64, String> {
    if !matches!(status, "revoked" | "superseded") {
        return Err("local-standing-transition".to_owned());
    }
    require_digest(id, "execution standing")?;
    let mut db = Connection::open(database).map_err(|e| format!("local-standing-open:{e}"))?;
    db.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| e.to_string())?;
    migrate(&db)?;
    let tx = db
        .transaction()
        .map_err(|e| format!("local-standing-transaction:{e}"))?;
    let (revision, prior, prior_at): (u64,String,u64) = tx.query_row("SELECT p.revision,r.status,r.changed_at FROM local_execution_standing_projection p JOIN local_execution_standing_revision r USING(execution_standing,revision) WHERE p.execution_standing=?1", [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|e| format!("local-standing-missing:{e}"))?;
    if prior != "current" {
        return Err("local-standing-not-current".to_owned());
    }
    if at < prior_at {
        return Err("local-standing-time-regression".to_owned());
    }
    let next = revision
        .checked_add(1)
        .ok_or_else(|| "local-standing-revision-range".to_owned())?;
    let cur = revision_identity(id, next, status, at);
    tx.execute(
        "INSERT INTO local_execution_standing_revision VALUES (?1,?2,?3,?4,?5)",
        params![id, next, status, i64v(at)?, cur],
    )
    .map_err(|e| format!("local-standing-revision:{e}"))?;
    tx.execute("UPDATE local_execution_standing_projection SET revision=?2 WHERE execution_standing=?1 AND revision=?3", params![id,next,revision]).map_err(|e| format!("local-standing-projection:{e}"))?;
    tx.commit()
        .map_err(|e| format!("local-standing-commit:{e}"))?;
    Ok(next)
}

pub fn resolve(
    database: &Path,
    operator: &str,
    request: &ExecutionStandingRequestV1,
) -> Result<ExecutionStandingResolutionV1, String> {
    let db = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|e| format!("local-standing-read-open:{e}"))?;
    let enrolled:String=db.query_row("SELECT operator FROM local_execution_standing_deployment WHERE singleton=1 AND mode='snapshot_currentness' AND max_lifetime_ms=300000",[],|r|r.get(0)).map_err(|e|format!("local-standing-enrollment-read:{e}"))?;
    if enrolled != operator {
        return Err("local-standing-operator-enrollment-mismatch".to_owned());
    }
    let mut statement=db.prepare("SELECT g.execution_standing,p.revision,r.status,g.issued_at,g.expires_at,r.revision_identity,r.changed_at FROM local_execution_standing_grant g JOIN local_execution_standing_projection p USING(execution_standing) JOIN local_execution_standing_revision r USING(execution_standing,revision) WHERE g.operator=?1 AND g.campaign=?2 AND g.occurrence=?3 AND g.program=?4 AND g.work_schema=?5 AND g.work=?6 AND g.subject=?7 AND g.scope=?8 LIMIT 2").map_err(|e|format!("local-standing-query-prepare:{e}"))?;
    let mut rows = statement
        .query(params![
            operator,
            request.issuance.key.campaign,
            request.issuance.key.occurrence,
            request.issuance.program,
            request.issuance.work_schema,
            request.issuance.work,
            request.issuance.subject,
            request.issuance.scope
        ])
        .map_err(|e| format!("local-standing-query:{e}"))?;
    let Some(row) = rows.next().map_err(|e| format!("local-standing-row:{e}"))? else {
        return Err("local-standing-absent".to_owned());
    };
    let found: (String, u64, String, u64, u64, String, u64) = (
        row.get(0).map_err(|e| e.to_string())?,
        row.get(1).map_err(|e| e.to_string())?,
        row.get(2).map_err(|e| e.to_string())?,
        row.get(3).map_err(|e| e.to_string())?,
        row.get(4).map_err(|e| e.to_string())?,
        row.get(5).map_err(|e| e.to_string())?,
        row.get(6).map_err(|e| e.to_string())?,
    );
    if rows
        .next()
        .map_err(|e| format!("local-standing-row:{e}"))?
        .is_some()
    {
        return Err("local-standing-ambiguous".to_owned());
    }
    let (id, revision, state, issued, expires, revision_id, changed_at) = found;
    let identity = grant_identity(&GrantInput {
        operator,
        campaign: &request.issuance.key.campaign,
        occurrence: &request.issuance.key.occurrence,
        program: &request.issuance.program,
        work_schema: &request.issuance.work_schema,
        work: &request.issuance.work,
        subject: &request.issuance.subject,
        scope: &request.issuance.scope,
        issued_at_unix_ms: issued,
        expires_at_unix_ms: expires,
    })?;
    if identity != id {
        return Err("local-standing-grant-identity".to_owned());
    }
    if revision_identity(&id, revision, &state, changed_at) != revision_id {
        return Err("local-standing-revision-identity".to_owned());
    }
    let status = if state == "revoked" {
        ExecutionStandingStatusV1::Revoked
    } else if state == "superseded" {
        ExecutionStandingStatusV1::Superseded
    } else if request.now_unix_ms >= expires {
        ExecutionStandingStatusV1::Expired
    } else if request.now_unix_ms < issued {
        return Err("local-standing-future".to_owned());
    } else {
        ExecutionStandingStatusV1::Current
    };
    let current = currentness(
        &id,
        revision,
        &revision_id,
        &state,
        request.now_unix_ms,
        expires,
    );
    let resolution = hash_domain(
        "docket.governed-loop.local-standing-resolution/v1",
        format!(
            "{id}\0{revision}\0{current}\0{}\0{}",
            request.issuance.issuance, request.now_unix_ms
        )
        .as_bytes(),
    );
    Ok(ExecutionStandingResolutionV1 {
        schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
        resolution,
        currentness: current,
        execution_standing: id,
        issuance: request.issuance.issuance.clone(),
        campaign: request.issuance.key.campaign.clone(),
        occurrence: request.issuance.key.occurrence.clone(),
        subject: request.issuance.subject.clone(),
        scope: request.issuance.scope.clone(),
        status,
        resolved_at_unix_ms: request.now_unix_ms,
        expires_at_unix_ms: expires,
    })
}

pub fn inspect_snapshot(
    database: &Path,
    issuance: &str,
) -> Result<Option<LocalCustodySnapshotV1>, String> {
    require_digest(issuance, "issuance")?;
    let db = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|e| format!("local-standing-read-open:{e}"))?;
    db.query_row("SELECT execution_standing,revision,status,resolved_at,expires_at,currentness,resolution FROM governed_local_standing_snapshot WHERE issuance=?1",[issuance],|r|Ok(LocalCustodySnapshotV1{schema:"docket.governed-loop.local-standing-snapshot/v1".to_owned(),issuance:issuance.to_owned(),execution_standing:r.get(0)?,revision:r.get(1)?,status:r.get(2)?,resolved_at_unix_ms:r.get(3)?,expires_at_unix_ms:r.get(4)?,currentness:r.get(5)?,resolution:r.get(6)?})).optional().map_err(|e|format!("local-standing-inspect:{e}"))
}

fn file_digest(path: &Path, limit: u64) -> Result<String, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|e| format!("local-standing-pin-metadata:{e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err("local-standing-pin-file".to_owned());
    }
    let mut file = std::fs::File::open(path).map_err(|e| format!("local-standing-pin-open:{e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut read = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("local-standing-pin-read:{e}"))?;
        if n == 0 {
            break;
        }
        read += n as u64;
        if read > limit {
            return Err("local-standing-pin-size".to_owned());
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
/// Writes an immutable zero-argv launcher which captures and seals both deployment files
/// before invoking the resolver. The mutable ledger is named only inside the
/// measured config, never through ambient argv or environment.
pub fn write_zero_arg_launcher(
    resolver: &Path,
    config: &Path,
    python_interpreter: &Path,
    output: &Path,
) -> Result<(), String> {
    if !resolver.is_absolute()
        || !config.is_absolute()
        || !python_interpreter.is_absolute()
        || !output.is_absolute()
    {
        return Err("local-standing-pin-path-absolute".to_owned());
    }
    let rd = file_digest(resolver, 512 * 1024 * 1024)?;
    let cd = file_digest(config, 65_536)?;
    let _interpreter_digest = file_digest(python_interpreter, 128 * 1024 * 1024)?;
    let py = python_interpreter
        .to_str()
        .ok_or_else(|| "local-standing-pin-path-utf8".to_owned())?;
    if py.contains(char::is_whitespace) {
        return Err("local-standing-interpreter-path".to_owned());
    }
    let rp = serde_json::to_string(
        resolver
            .to_str()
            .ok_or_else(|| "local-standing-pin-path-utf8".to_owned())?,
    )
    .map_err(|e| e.to_string())?;
    let cp = serde_json::to_string(
        config
            .to_str()
            .ok_or_else(|| "local-standing-pin-path-utf8".to_owned())?,
    )
    .map_err(|e| e.to_string())?;
    let body = format!(
        r##"#!{py} -I
import fcntl,hashlib,os,stat,sys
if len(sys.argv)!=1: raise SystemExit("local standing launcher accepts no arguments")
def capture(path,want,maximum,name,executable):
 flags=os.O_RDONLY|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0); source=os.open(path,flags)
 meta=os.fstat(source)
 if not stat.S_ISREG(meta.st_mode) or (executable and meta.st_mode&0o111==0): raise SystemExit(name+" is not a suitable regular file")
 image=os.memfd_create(name,os.MFD_ALLOW_SEALING); h=hashlib.sha256(); total=0
 while True:
  block=os.read(source,65536)
  if not block: break
  total+=len(block)
  if total>maximum: raise SystemExit(name+" exceeds bounded size")
  h.update(block); view=memoryview(block)
  while view:
   written=os.write(image,view)
   if written<=0: raise SystemExit(name+" image write was incomplete")
   view=view[written:]
 os.close(source)
 if h.hexdigest()!=want: raise SystemExit(name+" digest mismatch")
 os.fchmod(image,0o500 if executable else 0o400)
 fcntl.fcntl(image,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SEAL)
 os.lseek(image,0,os.SEEK_SET); os.set_inheritable(image,True); return image
resolver=capture({rp},"{rd}",536870912,"docket-local-standing-resolver",True)
config=capture({cp},"{cd}",65536,"docket-local-standing-config",False)
program="/proc/self/fd/"+str(resolver); config_path="/proc/self/fd/"+str(config)
os.execve(program,[program,"--config",config_path],{{}})
"##
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(output)
        .map_err(|e| format!("local-standing-launcher-create:{e}"))?;
    file.write_all(body.as_bytes())
        .map_err(|e| format!("local-standing-launcher-write:{e}"))?;
    file.sync_all()
        .map_err(|e| format!("local-standing-launcher-sync:{e}"))
}

pub fn read_config(path: &Path) -> Result<LocalResolverConfigV1, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("local-standing-config-open:{e}"))?;
    let mut bytes = Vec::new();
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("local-standing-config-read:{e}"))?;
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err("local-standing-config-size".to_owned());
    }
    let config: LocalResolverConfigV1 =
        serde_json::from_slice(&bytes).map_err(|e| format!("local-standing-config:{e}"))?;
    if config.schema != "docket.governed-loop.local-standing-resolver-config/v1"
        || !config.state_database.is_absolute()
        || config.operator.is_empty()
        || config.operator.len() > 256
        || !config
            .operator
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'/'))
    {
        return Err("local-standing-config-invalid".to_owned());
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gwr_runtime::governed_loop::{
        AgIssuanceWireV1, OccurrenceKeyWireV1, STANDING_REQUEST_SCHEMA_V1,
    };
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn digest(label: &str) -> String {
        hash_domain("local-standing-test/v1", label.as_bytes())
    }
    fn database() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "docket-local-standing-{}-{}.sqlite",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn issuance() -> AgIssuanceWireV1 {
        let mut issuance = AgIssuanceWireV1 {
            schema: "ag.governed-loop.issuance/v1".into(),
            issuance: String::new(),
            key: OccurrenceKeyWireV1 {
                campaign: digest("campaign"),
                occurrence: "123e4567-e89b-42d3-a456-426614174000".into(),
            },
            program: digest("program"),
            proposal: digest("proposal"),
            work_schema: "maude.reviewed-local-copy/v1".into(),
            work: digest("work"),
            subject: digest("subject"),
            scope: digest("scope"),
            observation: digest("observation"),
            standing_resolution: digest("ag-standing"),
            mandate: digest("mandate"),
            spend: digest("spend"),
        };
        refresh_identity(&mut issuance);
        assert!(gwr_runtime::governed_loop::validate_issuance(&issuance).is_ok());
        issuance
    }
    fn refresh_identity(issuance: &mut AgIssuanceWireV1) {
        let basis = serde_json::json!({"key":{"campaign":issuance.key.campaign,"occurrence":issuance.key.occurrence},"mandate":issuance.mandate,"observation":issuance.observation,"program":issuance.program,"proposal":issuance.proposal,"scope":issuance.scope,"spend":issuance.spend,"standing_resolution":issuance.standing_resolution,"subject":issuance.subject,"work":issuance.work,"work_schema":issuance.work_schema});
        issuance.issuance = hash_domain(
            "ag.governed-loop.issuance/v1",
            &serde_json::to_vec(&basis).unwrap(),
        );
    }
    fn input<'a>(i: &'a AgIssuanceWireV1, issued: u64, expires: u64) -> GrantInput<'a> {
        GrantInput {
            operator: "operator-1",
            campaign: &i.key.campaign,
            occurrence: &i.key.occurrence,
            program: &i.program,
            work_schema: &i.work_schema,
            work: &i.work,
            subject: &i.subject,
            scope: &i.scope,
            issued_at_unix_ms: issued,
            expires_at_unix_ms: expires,
        }
    }
    fn request(i: AgIssuanceWireV1, now: u64) -> ExecutionStandingRequestV1 {
        ExecutionStandingRequestV1 {
            schema: STANDING_REQUEST_SCHEMA_V1.into(),
            issuance: i,
            now_unix_ms: now,
        }
    }

    #[test]
    fn current_then_revoked_preserves_distinct_immutable_revision() {
        let db = database();
        let i = issuance();
        let id = grant(&db, &input(&i, 1000, 1300)).unwrap();
        let current = resolve(&db, "operator-1", &request(i.clone(), 1100)).unwrap();
        assert_eq!(current.status, ExecutionStandingStatusV1::Current);
        assert_eq!(transition(&db, &id, "revoked", 1150).unwrap(), 2);
        let revoked = resolve(&db, "operator-1", &request(i, 1160)).unwrap();
        assert_eq!(revoked.status, ExecutionStandingStatusV1::Revoked);
        assert_ne!(current.currentness, revoked.currentness);
        let _ = std::fs::remove_file(db);
    }

    #[test]
    fn lifetime_and_exact_tuple_fail_closed() {
        let db = database();
        let i = issuance();
        grant(&db, &input(&i, 1000, 301000)).unwrap();
        let second = database();
        assert_eq!(
            grant(&second, &input(&i, 1000, 301001)).unwrap_err(),
            "local-standing-lifetime"
        );
        let mut wrong = i.clone();
        wrong.work = digest("other-work");
        refresh_identity(&mut wrong);
        assert!(gwr_runtime::governed_loop::validate_issuance(&wrong).is_ok());
        assert_eq!(
            resolve(&db, "operator-1", &request(wrong, 1100)).unwrap_err(),
            "local-standing-absent"
        );
        assert_eq!(
            resolve(&db, "operator-1", &request(i, 301000))
                .unwrap()
                .status,
            ExecutionStandingStatusV1::Expired
        );
        let _ = std::fs::remove_file(db);
        let _ = std::fs::remove_file(second);
    }

    #[test]
    fn duplicate_matching_grants_are_ambiguous() {
        let db = database();
        let i = issuance();
        grant(&db, &input(&i, 1000, 1250)).unwrap();
        grant(&db, &input(&i, 1001, 1251)).unwrap();
        assert_eq!(
            resolve(&db, "operator-1", &request(i, 1100)).unwrap_err(),
            "local-standing-ambiguous"
        );
        let _ = std::fs::remove_file(db);
    }

    #[test]
    fn concurrent_first_enrollment_fixes_one_operator() {
        let db = database();
        let i = issuance();
        let mut handles = Vec::new();
        for operator in ["operator-1", "operator-2"] {
            let db = db.clone();
            let i = i.clone();
            handles.push(std::thread::spawn(move || {
                let mut value = input(&i, 1000, 1300);
                value.operator = operator;
                grant(&db, &value)
            }));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|r| r.is_err()).count(), 1);
        let _ = std::fs::remove_file(db);
    }

    #[test]
    fn measured_launcher_refuses_path_replacement_and_content_mutation() {
        let python = std::fs::canonicalize("/usr/bin/python3").unwrap();
        let positive = database().with_extension("launcher-positive");
        std::fs::create_dir(&positive).unwrap();
        let resolver = positive.join("resolver");
        let config = positive.join("config");
        let launcher = positive.join("launcher");
        std::fs::write(&resolver, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&config, b"{}\n").unwrap();
        write_zero_arg_launcher(&resolver, &config, &python, &launcher).unwrap();
        assert!(Command::new(&launcher).status().unwrap().success());
        let _ = std::fs::remove_dir_all(positive);
        for target in ["resolver", "config"] {
            for replacement in [false, true] {
                let root = database().with_extension(format!("launcher-{target}-{replacement}"));
                std::fs::create_dir(&root).unwrap();
                let resolver = root.join("resolver");
                let config = root.join("config.json");
                let launcher = root.join("launcher");
                std::fs::write(&resolver, b"#!/bin/sh\nexit 0\n").unwrap();
                std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                std::fs::write(&config, b"{}\n").unwrap();
                write_zero_arg_launcher(&resolver, &config, &python, &launcher).unwrap();
                let selected = if target == "resolver" {
                    &resolver
                } else {
                    &config
                };
                if replacement {
                    let changed = root.join("changed");
                    std::fs::write(&changed, b"changed bytes\n").unwrap();
                    if target == "resolver" {
                        std::fs::set_permissions(&changed, std::fs::Permissions::from_mode(0o700))
                            .unwrap();
                    }
                    std::fs::rename(changed, selected).unwrap();
                } else {
                    std::fs::write(selected, b"changed bytes\n").unwrap();
                }
                assert!(!Command::new(&launcher).status().unwrap().success());
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }

    #[test]
    fn launcher_executes_sealed_captures_after_originals_mutate() {
        let python = std::fs::canonicalize("/usr/bin/python3").unwrap();
        let root = database().with_extension("launcher-sealed-consumption");
        std::fs::create_dir(&root).unwrap();
        let resolver = root.join("resolver");
        let config = root.join("config");
        let launcher = root.join("launcher");
        std::fs::write(&config, b"original-config\n").unwrap();
        let script=format!("#!/bin/sh\nprintf changed > '{}'\nprintf changed > '{}'\n[ \"$(cat \"$2\")\" = original-config ]\n",resolver.display(),config.display());
        std::fs::write(&resolver, script).unwrap();
        std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o700)).unwrap();
        write_zero_arg_launcher(&resolver, &config, &python, &launcher).unwrap();
        assert!(Command::new(&launcher).status().unwrap().success());
        assert_eq!(std::fs::read(&resolver).unwrap(), b"changed");
        assert_eq!(std::fs::read(&config).unwrap(), b"changed");
        let _ = std::fs::remove_dir_all(root);
    }
}
