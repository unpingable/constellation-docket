//! The operator docket CLI: the first usable governed-work workflow.
//!
//! Every command is a thin wrapper over the runtime services; nothing here
//! holds authority of its own. State lives under `--state <dir>`:
//! `state.sqlite`, `artifacts/`, `journals/`, `provenance/`, `standing.key`.

use gwr_core::campaign::adjudication::{AdjudicationVerdict, ResidualStatement};
use gwr_core::campaign::proposal::{CampaignStageProposal, RepairBasis, RepoPin, StageBasis};
use gwr_core::campaign::standing::{classify, ConsumptionState, ExecutionContext};
use gwr_core::campaign::{RepairScopeClass, ReviewRequirement, StageClass, WorkerRole};
use gwr_core::digest::Sha256Digest;
use gwr_core::domain::evidence::Claim;
use gwr_core::domain::standing::{StandingAct, StandingGrant, StandingScope};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::AttemptState;
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::preparation::{PreparationRun, PreparationStatus};
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::repository::{RepositoryAlias, RepositoryAliasKind, RepositoryRegistration};
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryLocator, WorkRequest};
use gwr_local::adapters::{FsArtifactStore, FsProvenanceSink, HashChainIds, SystemClock};
use gwr_local::broker::SubprocessGitBroker;
use gwr_local::campaign_export;
use gwr_local::capabilities::StandingTokenCodec;
use gwr_local::governed_loop;
use gwr_local::local_execution_standing::{self, GrantInput};
use gwr_local::providers::fake::{Script, ScriptedProvider};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::adapters::{Clock, IdSource};
use gwr_runtime::ports::labor_provider::BoundedAssignment;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::authz_request;
use gwr_runtime::services::authz_standing;
use gwr_runtime::services::campaign as campaign_svc;
use gwr_runtime::services::dispatch::{dispatch, DispatchOutcome};
use gwr_runtime::services::dossier;
use gwr_runtime::services::journal;
use gwr_runtime::services::list;
use gwr_runtime::services::preparation::{run_preparation, PreparationResult};
use gwr_runtime::services::ratification::ratify;
use gwr_runtime::services::reconcile::reconcile;
use gwr_runtime::services::reliance::{rely_review_queue, RelyError};
use gwr_runtime::services::reservation::reserve;
use std::io::Read as _;
use std::path::PathBuf;

/// Verifier-generation identity emitted into repair-authority artifacts:
/// adapter name and crate version. File-level metadata, not part of the
/// typed content address.
const VERIFIER_ID: &str = concat!("gwr-local ", env!("CARGO_PKG_VERSION"));

const ROOT_HELP: &str = "\
Docket governed-work runtime

Usage:
  docket <command> [options]
  docket --help
  docket -h

Put the command before its options. Every stateful command requires
--state <directory>; Docket creates an empty state directory on first use.
Repository paths are explicit absolute locators, never repository identity.

Repository identity:
  repository register         Mint or register an opaque RepositoryId
  repository relocate         Make a new absolute path the current locator
  repository alias            Retain a non-current path or remote alias
  repository show             Inspect a registration [--json]
  repository migrate-attempt  Explicitly bind one legacy work request
  continuity subject          Export the exact Docket-owned subject [--json]
  governed-loop inspect       Read one exact governed-loop issuance record
  governed-loop standing-grant | standing-revoke | standing-supersede

Governed workflow:
  request create
  prepare start | prepare poll
  candidate admit
  grant standing | ratify | reserve | dispatch
  observe | rely review-queue | reconcile
  recover fact | recover resolve

Authorization and evidence:
  authz request | authz accept
  governed-loop accept | reconcile-issuance | reconcile-attempt
  list [--json]
  show (--attempt <id> | --dispatch <id>) [--json]
  journal (--attempt <id> | --dispatch <id>) [--json]

Campaign-stage standing (S-2; a distinct domain from effect standing):
  campaign propose-stage    Record an exact stage proposal; prints its digest
  campaign admit            Issue standing for a recorded proposal
  campaign consume          Burn standing before the stage's effect runs
  campaign outcome          Record effect completion / the consuming receipt
  campaign adjudicate       Record a verdict (continue|exact-repair|refuse)
  campaign export-repair-authority   Emit the exact repair-authority artifact (read-only)
  campaign verify-repair-authority   Verify a repair-authority artifact (read-only)
  campaign show             Inspect proposals, standing, adjudications

Preparation providers:
  --provider fake  requires --fake-patch <file>
  --provider codex uses `codex` from PATH unless GWR_CODEX_BIN is set

Runtime environment:
  GWR_BROKER_BIN     explicit path to gwr-git-broker; otherwise a sibling
                     of the running docket executable is required
  GWR_WORKSPACE_ROOT writable parent for disposable provider workspaces;
                     defaults to the system temporary directory
  GWR_CODEX_BIN      optional codex executable override

Source installation and clean-state bootstrap:
  docs/governed-runtime/source-install-and-bootstrap.md
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("refused/error: {e}");
            std::process::exit(1);
        }
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn need(args: &[String], name: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("missing {name}"))
}

fn hex16s(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse16(s: &str) -> Result<[u8; 16], String> {
    let s = s.rsplit('-').next().unwrap_or(s);
    if s.len() != 32 {
        return Err(format!("bad id {s}"));
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "bad id")?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| "bad id")?;
    }
    Ok(out)
}

fn parse_repository_id(s: &str) -> Result<RepositoryId, String> {
    if s.len() != 37 || !s.starts_with("repo-") {
        return Err(
            "repository identity must be an opaque repo- followed by 32 lowercase hex digits; \
             paths, remotes, and Git object hashes are locators/content, not repository identity"
                .into(),
        );
    }
    if !s[5..]
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("repository identity contains non-lowercase-hex bytes".into());
    }
    Ok(RepositoryId::from_bytes(parse16(s)?))
}

fn require_absolute_path(raw: &str) -> Result<RepositoryLocator, String> {
    if !std::path::Path::new(raw).is_absolute() {
        return Err(
            "repository path locator must be explicit and absolute; cwd discovery is not \
             repository identity"
                .into(),
        );
    }
    Ok(RepositoryLocator::new(raw))
}

fn json_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn parse_digest(s: &str) -> Result<Sha256Digest, String> {
    if s.len() != 64 {
        return Err("bad digest".into());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "bad digest")?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| "bad digest")?;
    }
    Ok(Sha256Digest::from_bytes(out))
}

fn actor_id(name: &str) -> ActorId {
    let d = gwr_core::digest::Transcript::new("gwr:actor:v1")
        .text_field("name", name)
        .finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d.as_bytes()[..16]);
    ActorId::from_bytes(b)
}

/// All values of a repeated flag, in order.
fn flags(args: &[String], name: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| *a == name)
        .filter_map(|(i, _)| args.get(i + 1).cloned())
        .collect()
}

/// A repository pin as `locator:commit:tree`. Commit and tree are object ids
/// (no colons), so splitting from the right is unambiguous.
fn parse_pin(raw: &str) -> Result<RepoPin, String> {
    let (head, tree) = raw
        .rsplit_once(':')
        .ok_or("pin must be locator:commit:tree")?;
    let (locator, commit) = head
        .rsplit_once(':')
        .ok_or("pin must be locator:commit:tree")?;
    Ok(RepoPin {
        repository: RepositoryLocator::new(locator),
        commit: CommitHash::new(commit),
        tree: tree.to_string(),
    })
}

fn parse_review_requirement_flag(args: &[String], name: &str) -> Result<ReviewRequirement, String> {
    match flag(args, name).as_deref() {
        None | Some("not-required") => Ok(ReviewRequirement::NotRequired),
        Some("required") => Ok(ReviewRequirement::Required),
        Some(other) => Err(format!("unknown review requirement {other:?}")),
    }
}

fn consumption_state_tag(state: ConsumptionState) -> &'static str {
    match state {
        ConsumptionState::EffectNotBegun => "effect_not_begun",
        ConsumptionState::ConsumedOutcomeUnresolved => "consumed_outcome_unresolved",
        ConsumptionState::EffectCompletedReceiptMissing => "effect_completed_receipt_missing",
        ConsumptionState::EffectCompletedReceipted => "effect_completed_receipted",
    }
}

struct State {
    dir: PathBuf,
    store: SqliteStore,
    ids: HashChainIds,
    clock: SystemClock,
}

impl State {
    fn open(args: &[String]) -> Result<Self, String> {
        let dir = PathBuf::from(need(args, "--state")?);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let store = SqliteStore::open(&dir.join("state.sqlite")).map_err(|e| format!("{e:?}"))?;
        Ok(Self {
            dir,
            store,
            ids: HashChainIds::new(),
            clock: SystemClock,
        })
    }

    fn codec(&mut self) -> Result<StandingTokenCodec, String> {
        let key_path = self.dir.join("standing.key");
        let key: [u8; 32] = if key_path.exists() {
            let bytes = std::fs::read(&key_path).map_err(|e| e.to_string())?;
            bytes.try_into().map_err(|_| "bad standing.key")?
        } else {
            let mut key = [0u8; 32];
            key[..16].copy_from_slice(&self.ids.fresh16());
            key[16..].copy_from_slice(&self.ids.fresh16());
            std::fs::write(&key_path, key).map_err(|e| e.to_string())?;
            key
        };
        Ok(StandingTokenCodec::new(key))
    }

    fn broker(&self) -> SubprocessGitBroker {
        let bin = std::env::var("GWR_BROKER_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::current_exe()
                    .expect("current exe")
                    .with_file_name("gwr-git-broker")
            });
        SubprocessGitBroker::new(bin, self.dir.join("journals"), self.dir.join("artifacts"))
    }
}

/// Resolve the attempt a read command addresses, by exactly one of
/// `--attempt` or `--dispatch`. A dispatch identity resolves through the
/// recorded dispatch binding; an unknown, malformed, or ambiguous identifier
/// is a typed refusal, never a silent selection. (The schema makes a dispatch
/// identity bind at most one attempt: `dispatch.id` is the primary key and
/// `dispatch.attempt` is unique.)
fn resolve_attempt(st: &mut State, args: &[String]) -> Result<AttemptId, String> {
    match (flag(args, "--attempt"), flag(args, "--dispatch")) {
        (Some(_), Some(_)) => Err("give exactly one of --attempt or --dispatch, not both".into()),
        (None, None) => Err("missing --attempt or --dispatch".into()),
        (Some(a), None) => Ok(AttemptId::from_bytes(parse16(&a)?)),
        (None, Some(d)) => {
            let dispatch_id = DispatchId::from_bytes(parse16(&d)?);
            st.store
                .find_dispatch_attempt(dispatch_id)
                .map_err(|e| format!("{e:?}"))?
                .ok_or_else(|| format!("unknown dispatch identity {d}"))
        }
    }
}

/// A missing associated record is an ordinary absence on read paths; every
/// other store error is surfaced.
fn optional_read<T>(
    r: Result<T, gwr_runtime::ports::store::StoreError>,
) -> Result<Option<T>, String> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(gwr_runtime::ports::store::StoreError::NotFound) => Ok(None),
        Err(e) => Err(format!("{e:?}")),
    }
}

fn state_tag(state: &AttemptState) -> &'static str {
    match state {
        AttemptState::Prepared => "prepared",
        AttemptState::Ratified { .. } => "ratified",
        AttemptState::Reserved { .. } => "reserved",
        AttemptState::Dispatching { .. } => "dispatching",
        AttemptState::Committed { .. } => "committed",
        AttemptState::DispatchRefused { .. } => "dispatch_refused",
        AttemptState::Indeterminate { .. } => "indeterminate",
        AttemptState::CommittedViaRecovery { .. } => "committed_via_recovery",
        AttemptState::ProvenNotCommitted { .. } => "proven_not_committed",
    }
}

fn run(args: &[String]) -> Result<(), String> {
    if matches!(args, [arg] if arg == "--help" || arg == "-h") {
        print!("{ROOT_HELP}");
        return Ok(());
    }

    let cmd: Vec<&str> = args
        .iter()
        .take_while(|a| !a.starts_with("--"))
        .map(String::as_str)
        .collect();
    match cmd.as_slice() {
        ["governed-loop", "accept"] => {
            // The exact signed issuance arrives on stdin. Docket resolves its
            // own execution standing now, commits custody/attempt identity,
            // and only then delegates mechanics to the named executor.
            let st = State::open(args)?;
            let envelope = read_stdin_bounded()?;
            let trust = std::fs::read(need(args, "--trust")?)
                .map_err(|error| format!("reading governed-loop trust: {error}"))?;
            let local = has(args, "--require-local-standing-snapshot");
            let call = if local { governed_loop::accept_local } else { governed_loop::accept };
            let custody = call(
                &st.dir.join("state.sqlite"),
                &envelope,
                &trust,
                &PathBuf::from(need(args, "--standing-resolver")?),
                &PathBuf::from(need(args, "--executor")?),
                &PathBuf::from(need(args, "--executor-config")?),
            )?;
            println!(
                "{}",
                serde_json::to_string(&custody)
                    .map_err(|error| format!("governed custody response: {error}"))?
            );
            Ok(())
        }
        ["governed-loop", "standing-grant"] => {
            let st=State::open(args)?;
            let issued:u64=need(args,"--issued-at-unix-ms")?.parse().map_err(|_|"invalid issued time".to_owned())?;
            let expires:u64=need(args,"--expires-at-unix-ms")?.parse().map_err(|_|"invalid expiry".to_owned())?;
            let id=local_execution_standing::grant(&st.dir.join("state.sqlite"),&GrantInput{
                operator:&need(args,"--operator")?, campaign:&need(args,"--campaign")?,
                occurrence:&need(args,"--occurrence")?, program:&need(args,"--program")?,
                work_schema:&need(args,"--work-schema")?, work:&need(args,"--work")?,
                subject:&need(args,"--subject")?, scope:&need(args,"--scope")?,
                issued_at_unix_ms:issued, expires_at_unix_ms:expires,
            })?;
            println!("execution_standing: {id}"); Ok(())
        }
        ["governed-loop", action @ ("standing-revoke" | "standing-supersede")] => {
            let st=State::open(args)?;
            let at:u64=need(args,"--at-unix-ms")?.parse().map_err(|_|"invalid transition time".to_owned())?;
            let status=if *action=="standing-revoke"{"revoked"}else{"superseded"};
            let revision=local_execution_standing::transition(&st.dir.join("state.sqlite"),&need(args,"--execution-standing")?,status,at)?;
            println!("revision: {revision}"); Ok(())
        }
        ["governed-loop", "standing-snapshot"] => {
            let st=State::open(args)?;
            let snapshot=local_execution_standing::inspect_snapshot(&st.dir.join("state.sqlite"),&need(args,"--issuance")?)?;
            println!("{}",serde_json::to_string(&snapshot).map_err(|e|format!("local-standing-snapshot-json:{e}"))?);
            Ok(())
        }
        ["governed-loop", "standing-write-launcher"] => {
            local_execution_standing::write_zero_arg_launcher(
                &PathBuf::from(need(args,"--resolver")?),
                &PathBuf::from(need(args,"--config")?),
                &PathBuf::from(need(args,"--output")?),
            )?;
            Ok(())
        }
        ["governed-loop", "reconcile-issuance"] => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Request {
                issuance: String,
            }
            let st = State::open(args)?;
            let request: Request = serde_json::from_slice(&read_stdin_bounded()?)
                .map_err(|error| format!("governed reconciliation request: {error}"))?;
            let response = governed_loop::reconcile(
                &st.dir.join("state.sqlite"),
                &request.issuance,
                None,
                &PathBuf::from(need(args, "--executor")?),
                &PathBuf::from(need(args, "--executor-config")?),
            )?;
            println!(
                "{}",
                serde_json::to_string(&response)
                    .map_err(|error| format!("governed reconciliation response: {error}"))?
            );
            Ok(())
        }
        ["governed-loop", "reconcile-attempt"] => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Request {
                issuance: String,
                attempt: String,
            }
            let st = State::open(args)?;
            let request: Request = serde_json::from_slice(&read_stdin_bounded()?)
                .map_err(|error| format!("governed reconciliation request: {error}"))?;
            let response = governed_loop::reconcile(
                &st.dir.join("state.sqlite"),
                &request.issuance,
                Some(&request.attempt),
                &PathBuf::from(need(args, "--executor")?),
                &PathBuf::from(need(args, "--executor-config")?),
            )?;
            println!(
                "{}",
                serde_json::to_string(&response)
                    .map_err(|error| format!("governed reconciliation response: {error}"))?
            );
            Ok(())
        }
        ["governed-loop", "inspect"] => {
            let state = PathBuf::from(need(args, "--state")?);
            let issuance = need(args, "--issuance")?;
            let response = governed_loop::inspect(&state.join("state.sqlite"), &issuance)?;
            println!(
                "{}",
                serde_json::to_string(&response)
                    .map_err(|error| format!("governed inspection response: {error}"))?
            );
            Ok(())
        }
        ["repository", "register"] => {
            let mut st = State::open(args)?;
            let path = require_absolute_path(&need(args, "--repo")?)?;
            let repository_id = match flag(args, "--repository-id") {
                Some(raw) => parse_repository_id(&raw)?,
                None => RepositoryId::from_bytes(st.ids.fresh16()),
            };
            let now = st.clock.now();
            st.store
                .register_repository(&RepositoryRegistration {
                    id: repository_id,
                    registered_at: now,
                    aliases: vec![RepositoryAlias {
                        kind: RepositoryAliasKind::Path,
                        locator: path.clone(),
                        registered_at: now,
                        current: true,
                    }],
                })
                .map_err(|e| format!("{e:?}"))?;
            println!("repository_id: {repository_id}");
            println!("path_locator: {}", path.as_str());
            println!("note: path is an operational alias, not repository identity");
            println!(
                "migration: existing attempts remain unbound until `repository migrate-attempt`"
            );
            Ok(())
        }
        ["repository", "migrate-attempt"] => {
            let mut st = State::open(args)?;
            let repository_id = parse_repository_id(&need(args, "--repository-id")?)?;
            let attempt_id = resolve_attempt(&mut st, args)?;
            let projected = st
                .store
                .get_attempt(attempt_id)
                .map_err(|e| format!("{e:?}"))?;
            let registration = st
                .store
                .get_repository(repository_id)
                .map_err(|_| format!("repository {repository_id} is not registered"))?;
            if !registration.has_path(&projected.attempt.repository) {
                return Err(format!(
                    "attempt path {} is not an explicitly retained locator for \
                     {repository_id}; refusing to infer or launder repository identity",
                    projected.attempt.repository.as_str()
                ));
            }
            st.store
                .bind_work_request_repository(projected.attempt.work_request, repository_id)
                .map_err(|e| format!("{e:?}"))?;
            println!("repository_id: {repository_id}");
            println!("attempt: {}", hex16s(attempt_id.as_bytes()));
            println!("path_locator: {}", projected.attempt.repository.as_str());
            println!(
                "note: selected legacy work request is now explicitly bound; path remains a locator"
            );
            Ok(())
        }
        ["repository", "relocate"] => {
            let mut st = State::open(args)?;
            let repository_id = parse_repository_id(&need(args, "--repository-id")?)?;
            let path = require_absolute_path(&need(args, "--repo")?)?;
            st.store
                .add_repository_alias(
                    repository_id,
                    &RepositoryAlias {
                        kind: RepositoryAliasKind::Path,
                        locator: path.clone(),
                        registered_at: st.clock.now(),
                        current: true,
                    },
                )
                .map_err(|e| format!("{e:?}"))?;
            println!("repository_id: {repository_id}");
            println!("current_path_locator: {}", path.as_str());
            println!("note: prior path aliases were retained; logical identity did not change");
            Ok(())
        }
        ["repository", "alias"] => {
            let mut st = State::open(args)?;
            let repository_id = parse_repository_id(&need(args, "--repository-id")?)?;
            let kind = match need(args, "--kind")?.as_str() {
                "path" => RepositoryAliasKind::Path,
                "remote" => RepositoryAliasKind::Remote,
                other => return Err(format!("unknown alias kind {other:?}; use path or remote")),
            };
            let raw = need(args, "--value")?;
            let locator = match kind {
                RepositoryAliasKind::Path => require_absolute_path(&raw)?,
                RepositoryAliasKind::Remote if raw.is_empty() => {
                    return Err("remote alias must not be empty".into())
                }
                RepositoryAliasKind::Remote => RepositoryLocator::new(raw),
            };
            st.store
                .add_repository_alias(
                    repository_id,
                    &RepositoryAlias {
                        kind,
                        locator: locator.clone(),
                        registered_at: st.clock.now(),
                        current: false,
                    },
                )
                .map_err(|e| format!("{e:?}"))?;
            println!("repository_id: {repository_id}");
            println!("alias_kind: {}", kind.tag());
            println!("alias: {}", locator.as_str());
            println!("note: alias registration does not derive or change logical identity");
            Ok(())
        }
        ["repository", "show"] => {
            let mut st = State::open(args)?;
            let repository_id = parse_repository_id(&need(args, "--repository-id")?)?;
            let registration = st
                .store
                .get_repository(repository_id)
                .map_err(|e| format!("{e:?}"))?;
            if has(args, "--json") {
                let aliases = registration
                    .aliases
                    .iter()
                    .map(|a| {
                        format!(
                            "{{\"kind\":{},\"locator\":{},\"registered_at_ms\":{},\
                             \"current\":{}}}",
                            json_quote(a.kind.tag()),
                            json_quote(a.locator.as_str()),
                            a.registered_at.0,
                            a.current
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "{{\"schema\":\"gwr:repository-registration:v0\",\
                     \"repository_id\":{},\"registered_at_ms\":{},\"aliases\":[{}],\
                     \"does_not_establish\":[\"a path or remote alias is repository identity\",\
                     \"Git supplies a canonical repository identity\"]}}",
                    json_quote(&repository_id.to_string()),
                    registration.registered_at.0,
                    aliases
                );
            } else {
                println!("repository_id: {repository_id}");
                for alias in registration.aliases {
                    println!(
                        "alias: {} {} current={}",
                        alias.kind.tag(),
                        alias.locator.as_str(),
                        alias.current
                    );
                }
            }
            Ok(())
        }
        ["request", "create"] => {
            let mut st = State::open(args)?;
            let target = need(args, "--target-ref")?;
            // Effect-class boundary: the runtime admits exactly one effect
            // class, and a target that is not a Git ref name is not a proposal
            // in any admitted class. Refused here — before a request exists,
            // before any provider runs, before any standing or reservation —
            // not eleven steps later as a mechanical Git refusal.
            GitRefEffect::validate_target_ref(&target).map_err(|e| format!("{e:?}"))?;
            let repository_id = parse_repository_id(&need(args, "--repository-id")?)?;
            let repository = require_absolute_path(&need(args, "--repo")?)?;
            let registration = st.store.get_repository(repository_id).map_err(|_| {
                format!(
                    "repository {repository_id} is not registered; run `docket repository \
                         register` rather than deriving identity from --repo"
                )
            })?;
            if registration.current_path() != Some(&repository) {
                return Err(format!(
                    "path {} is not the current explicitly registered path locator for \
                     {repository_id}; historical paths remain aliases but do not select \
                     repository identity or authorize execution",
                    repository.as_str()
                ));
            }
            let wr = WorkRequest {
                id: WorkRequestId::from_bytes(st.ids.fresh16()),
                repository_id: Some(repository_id),
                repository,
                target_ref: RefName::new(target),
                goal: need(args, "--goal")?,
                created_at: st.clock.now(),
            };
            st.store
                .create_work_request(&wr)
                .map_err(|e| format!("{e:?}"))?;
            println!("work_request: {}", hex16s(wr.id.as_bytes()));
            Ok(())
        }
        ["prepare", "start"] => {
            let mut st = State::open(args)?;
            let request = WorkRequestId::from_bytes(parse16(&need(args, "--request")?)?);
            let wr = st
                .store
                .get_work_request(request)
                .map_err(|e| format!("{e:?}"))?;
            // A stored request predating the effect-class boundary may carry
            // an inexpressible target. Provider labor is spent only on work in
            // an admitted class, so it is (re)checked before the provider runs.
            GitRefEffect::validate_target_ref(wr.target_ref.as_str())
                .map_err(|e| format!("{e:?}"))?;
            let deadline_ms: u64 = flag(args, "--deadline-ms")
                .map(|s| s.parse().unwrap_or(600_000))
                .unwrap_or(600_000);
            let now = st.clock.now();
            let run = PreparationRun {
                id: PreparationRunId::from_bytes(st.ids.fresh16()),
                work_request: request,
                started_at: now,
                deadline: ClockReading(now.0 + deadline_ms),
                status: PreparationStatus::Running,
            };
            st.store
                .create_preparation_run(&run)
                .map_err(|e| format!("{e:?}"))?;
            let basis = flag(args, "--basis").unwrap_or_default();
            // The provider workspace lives OUTSIDE the state directory, and is
            // per-run. It previously sat at <state>/workspace -- one level below
            // standing.key and state.sqlite -- and was handed to the provider as
            // its working directory, so a provider that merely read `..` had the
            // signing key and the governed store. Relocation removes the ambient
            // path; it is not by itself an isolation boundary (see
            // docs/governed-runtime/open-defects.md).
            let workspace = std::env::var_os("GWR_WORKSPACE_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join(format!("gwr-workspace-{}", hex16s(run.id.as_bytes())));
            let assignment = BoundedAssignment {
                preparation_run: run.id,
                goal: wr.goal.clone(),
                basis: CommitHash::new(basis.clone()),
                workspace: workspace.clone(),
                deadline: run.deadline,
            };
            let mut artifacts = FsArtifactStore::new(st.dir.join("artifacts"))?;
            let mut provenance = FsProvenanceSink::new(st.dir.join("provenance"))?;
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let mut provider: Box<dyn gwr_runtime::ports::labor_provider::LaborProvider> =
                match flag(args, "--provider").as_deref() {
                    Some("codex") => {
                        gwr_local::providers::codex::populate_workspace(
                            wr.repository.as_str(),
                            &basis,
                            &workspace,
                        )?;
                        let mut p = gwr_local::providers::codex::CodexExecProvider::new();
                        if let Some(bin) = std::env::var_os("GWR_CODEX_BIN") {
                            p.codex_bin = PathBuf::from(bin);
                        }
                        if let Some(t) = flag(args, "--timeout-ms") {
                            p.timeout = std::time::Duration::from_millis(
                                t.parse().map_err(|_| "bad --timeout-ms")?,
                            );
                        }
                        Box::new(p)
                    }
                    _ => {
                        let patch_file = need(args, "--fake-patch")?;
                        let patch = std::fs::read(&patch_file).map_err(|e| e.to_string())?;
                        Box::new(ScriptedProvider::new(Script::Produce {
                            patch,
                            reported_digest: None,
                        }))
                    }
                };
            let result = run_preparation(
                &mut st.store,
                provider.as_mut(),
                &run,
                &assignment,
                &mut artifacts,
                &mut provenance,
                &clock,
                &mut ids,
            )
            .map_err(|e| format!("{e:?}"))?;
            println!("preparation_run: {}", hex16s(run.id.as_bytes()));
            match result {
                PreparationResult::CandidateIngested { artifact, .. } => {
                    println!("candidate: {}", hex16s(artifact.id.as_bytes()));
                    println!("candidate_digest: {}", artifact.content_digest.to_hex());
                }
                other => println!("outcome: {other:?}"),
            }
            Ok(())
        }
        ["prepare", "poll"] => {
            let mut st = State::open(args)?;
            let run = PreparationRunId::from_bytes(parse16(&need(args, "--run")?)?);
            let run = st
                .store
                .get_preparation_run(run)
                .map_err(|e| format!("{e:?}"))?;
            println!("status: {:?}", run.status);
            Ok(())
        }
        ["candidate", "admit"] => {
            let mut st = State::open(args)?;
            let request = WorkRequestId::from_bytes(parse16(&need(args, "--request")?)?);
            let wr = st
                .store
                .get_work_request(request)
                .map_err(|e| format!("{e:?}"))?;
            let candidate = CandidateArtifactId::from_bytes(parse16(&need(args, "--candidate")?)?);
            let cand = st
                .store
                .get_candidate(candidate)
                .map_err(|e| format!("{e:?}"))?;
            let basis = CommitHash::new(need(args, "--basis")?);
            let allow: Vec<String> = args
                .iter()
                .enumerate()
                .filter(|(_, a)| *a == "--allow")
                .filter_map(|(i, _)| args.get(i + 1).cloned())
                .collect();
            let observe_cmd = need(args, "--observe")?;
            // An observation plan is fixed at admission and can never be edited,
            // so an empty one would mint an attempt that is committable but
            // permanently unobservable. Refuse at the input boundary.
            if observe_cmd.split_whitespace().next().is_none() {
                return Err("--observe names no command".into());
            }
            let effect = GitRefEffect {
                target_ref: wr.target_ref.clone(),
                expected_basis: basis.clone(),
                patch_digest: cand.content_digest,
                allowed_paths: allow,
            };
            // Effect-class boundary: an attempt is minted only for a proposal
            // fully expressible in the one admitted class. A refusal here
            // creates no attempt, so nothing downstream — standing,
            // reservation, dispatch, broker — can ever see the proposal.
            effect.validate().map_err(|e| format!("{e:?}"))?;
            let attempt = PreparedAttempt::admit(
                AttemptId::from_bytes(st.ids.fresh16()),
                request,
                candidate,
                wr.repository.clone(),
                basis,
                cand.content_digest,
                effect,
                ObservationPlan {
                    argv: observe_cmd.split_whitespace().map(String::from).collect(),
                    environment_description: "operator workstation".into(),
                },
                st.clock.now(),
            );
            st.store
                .admit_attempt(&attempt)
                .map_err(|e| format!("{e:?}"))?;
            println!("attempt: {}", hex16s(attempt.attempt_id.as_bytes()));
            println!(
                "prepared_attempt_digest: {}",
                attempt.prepared_attempt_digest.to_hex()
            );
            Ok(())
        }
        ["grant", "standing"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let projected = st
                .store
                .get_attempt(attempt)
                .map_err(|e| format!("{e:?}"))?;
            let act = match flag(args, "--act").as_deref() {
                Some("resolve-recovery") => StandingAct::ResolveRecovery,
                _ => StandingAct::Ratify,
            };
            let ttl: u64 = flag(args, "--ttl-ms")
                .map(|s| s.parse().unwrap_or(3_600_000))
                .unwrap_or(3_600_000);
            let grant = StandingGrant::issue(
                StandingGrantId::from_bytes(st.ids.fresh16()),
                StandingScope {
                    actor: actor_id(&need(args, "--actor")?),
                    act,
                    repository: projected.attempt.repository.clone(),
                    attempt_digest: projected.attempt.prepared_attempt_digest,
                },
                ClockReading(st.clock.now().0 + ttl),
            );
            st.store
                .create_standing_grant(&grant)
                .map_err(|e| format!("{e:?}"))?;
            let token = st.codec()?.issue(&grant);
            println!("grant: {}", hex16s(grant.id().as_bytes()));
            println!("token: {token}");
            Ok(())
        }
        ["ratify"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let token = need(args, "--token")?;
            let verified = st
                .codec()?
                .verify(&token)
                .map_err(|e| format!("token integrity: {e:?}"))?;
            let digest = parse_digest(&need(args, "--digest")?)?;
            let basis = CommitHash::new(need(args, "--basis")?);
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let receipt = ratify(
                &mut st.store,
                attempt,
                verified.id(),
                actor_id(&need(args, "--actor")?),
                digest,
                basis,
                &clock,
                &mut ids,
            )
            .map_err(|e| format!("{e:?}"))?;
            println!("ratification: {}", hex16s(receipt.ratification.as_bytes()));
            Ok(())
        }
        ["reserve"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let ttl: u64 = flag(args, "--ttl-ms")
                .map(|s| s.parse().unwrap_or(3_600_000))
                .unwrap_or(3_600_000);
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let claim = reserve(&mut st.store, attempt, ttl, &clock, &mut ids)
                .map_err(|e| format!("{e:?}"))?;
            println!("reservation: {}", hex16s(claim.id().as_bytes()));
            Ok(())
        }
        ["dispatch"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let mut broker = st.broker();
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let outcome = dispatch(&mut st.store, attempt, &mut broker, &clock, &mut ids)
                .map_err(|e| format!("{e:?}"))?;
            match outcome {
                DispatchOutcome::Committed(c) => {
                    println!("outcome: committed");
                    println!("result_commit: {}", c.result_commit.as_str());
                }
                DispatchOutcome::Refused(r) => {
                    println!("outcome: dispatch_refused");
                    println!("ground: {:?}", r.ground);
                }
                DispatchOutcome::Indeterminate(_) => {
                    println!("outcome: indeterminate");
                    println!("note: only recovery evidence plus recovery standing resolves this");
                }
                DispatchOutcome::AlreadyDispatched { state } => {
                    println!("outcome: already_dispatched");
                    println!("state: {}", state_tag(&state));
                }
            }
            Ok(())
        }
        ["observe"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let record = gwr_local::observe::observe(&mut st.store, attempt, &clock, &mut ids)
                .map_err(|e| format!("{e:?}"))?;
            println!("observation: {}", hex16s(record.id.as_bytes()));
            println!("exit_status: {}", record.exit_status);
            Ok(())
        }
        ["rely", "review-queue"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let observation = ObservationId::from_bytes(parse16(&need(args, "--observation")?)?);
            let claim = match need(args, "--claim")?.as_str() {
                "effect-and-command" => Claim::ExactResultCommitProducedAndCommandExitedZero,
                "patch-correct" => Claim::PatchIsCorrect,
                "task-complete" => Claim::TaskIsComplete,
                "safe-to-merge" => Claim::SafeToMerge,
                "obligation-discharged" => Claim::ObligationDischarged,
                "work-closed" => Claim::WorkMayBeClosed,
                other => return Err(format!("unknown claim {other}")),
            };
            let clock = SystemClock;
            match rely_review_queue(&mut st.store, attempt, observation, claim, &clock) {
                Ok(adm) => {
                    println!("reliance: admitted");
                    println!("result_commit: {}", adm.result_commit.as_str());
                    Ok(())
                }
                Err(RelyError::Refused(refusal)) => {
                    println!("reliance: refused");
                    println!("refusal: {refusal:?}");
                    Ok(())
                }
                Err(e) => Err(format!("{e:?}")),
            }
        }
        ["reconcile"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let rec = reconcile(&mut st.store, attempt, &clock, &mut ids)
                .map_err(|e| format!("{e:?}"))?;
            println!("reconciled: {}", hex16s(rec.attempt.as_bytes()));
            for ob in st
                .store
                .get_residual_obligations(attempt)
                .map_err(|e| format!("{e:?}"))?
            {
                println!("retained_obligation: {:?}", ob.kind);
            }
            Ok(())
        }
        ["recover", "fact"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let journal_dir = st.dir.join("journals");
            let fact = gwr_local::recover::produce_fact(
                &mut st.store,
                attempt,
                &journal_dir,
                &clock,
                &mut ids,
            )
            .map_err(|e| format!("{e:?}"))?;
            println!("recovery_fact: {}", hex16s(fact.id.as_bytes()));
            println!("observed_ref: {}", fact.observed_ref.as_str());
            match &fact.expected_result_commit {
                Some(c) => println!("expected_result_commit: {}", c.as_str()),
                None => println!("expected_result_commit: unknown"),
            }
            Ok(())
        }
        ["recover", "resolve"] => {
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let fact = RecoveryFactId::from_bytes(parse16(&need(args, "--fact")?)?);
            let token = need(args, "--token")?;
            let verified = st
                .codec()?
                .verify(&token)
                .map_err(|e| format!("token integrity: {e:?}"))?;
            let clock = SystemClock;
            let mut ids = HashChainIds::new();
            let mut evidence =
                gwr_local::recover::GitRecoveryEvidence::new(st.dir.join("journals"));
            let resolution = gwr_runtime::services::recovery::resolve(
                &mut st.store,
                attempt,
                fact,
                verified.id(),
                actor_id(&need(args, "--actor")?),
                &mut evidence,
                &clock,
                &mut ids,
            )
            .map_err(|e| format!("{e:?}"))?;
            println!("resolution: {:?}", resolution.verdict);
            Ok(())
        }
        ["authz", "request"] => {
            // Export the canonical authorization-request projection for an
            // exact prepared attempt. This mints nothing and grants nothing:
            // it is testimony about a proposal, for an upstream office to
            // decide on.
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let actor = need(args, "--actor")?;
            let r = authz_request::assemble(&mut st.store, attempt, &actor)
                .map_err(|e| format!("{e:?}"))?;
            if has(args, "--json") {
                println!("{}", authz_request::render_json(&r));
            } else {
                print!("{}", authz_request::render_text(&r));
            }
            Ok(())
        }
        ["authz", "accept"] => {
            // Verify an authenticated upstream issuance against this runtime's
            // stored prepared attempt and, only then, mint local standing.
            // Docket does not re-decide the upstream policy question; it checks
            // authenticity, freshness, and exact binding.
            let mut st = State::open(args)?;
            let attempt = AttemptId::from_bytes(parse16(&need(args, "--attempt")?)?);
            let issuance_bytes = std::fs::read(need(args, "--issuance")?)
                .map_err(|e| format!("reading issuance: {e}"))?;
            let trust_bytes = std::fs::read(
                flag(args, "--trust")
                    .unwrap_or_else(|| st.dir.join("authz-issuers.json").display().to_string()),
            )
            .map_err(|e| format!("reading issuer trust configuration: {e}"))?;
            let trust = gwr_local::authz_intake::IssuerTrustConfig::parse(&trust_bytes)
                .map_err(|e| format!("refused: {e}"))?;
            let projected = st
                .store
                .get_attempt(attempt)
                .map_err(|e| format!("{e:?}"))?;
            let now = st.clock.now();
            let verified = gwr_local::authz_intake::verify_issuance(
                &issuance_bytes,
                &projected.attempt,
                attempt,
                &trust,
                now,
            )
            .map_err(|e| format!("refused: {e}"))?;
            // Optional loop closure: if the caller still holds the exact request
            // bytes it exported, confirm the issuance names them.
            if let Some(path) = flag(args, "--request") {
                let request_bytes =
                    std::fs::read(&path).map_err(|e| format!("reading request: {e}"))?;
                gwr_local::authz_intake::confirm_request_bytes(&verified, &request_bytes)
                    .map_err(|e| format!("refused: {e}"))?;
                println!("request_bytes_confirmed: true");
            }
            let act = match flag(args, "--act").as_deref() {
                Some("resolve-recovery") => StandingAct::ResolveRecovery,
                _ => StandingAct::Ratify,
            };
            let ttl: u64 = flag(args, "--ttl-ms")
                .map(|s| s.parse().unwrap_or(3_600_000))
                .unwrap_or(3_600_000);
            let grant = authz_standing::mint_from_issuance(
                &mut st.store,
                &verified.accepted,
                actor_id(&verified.accepted.requested_actor),
                act,
                StandingGrantId::from_bytes(st.ids.fresh16()),
                now,
                ttl,
            )
            .map_err(|e| format!("refused: {e:?}"))?;
            let token = st.codec()?.issue(&grant);
            println!("issuance_accepted: {}", verified.accepted.issuance_id);
            println!("authorization_source: upstream");
            println!("grant: {}", hex16s(grant.id().as_bytes()));
            println!("token: {token}");
            println!(
                "note: the issuance is the recorded basis for this grant; it is not \
                 authority and was never presented to the broker"
            );
            Ok(())
        }
        ["campaign", "propose-stage"] => {
            // Record an exact stage proposal. The stage class fixes the role
            // and effect class; the never-admitted classes refuse here, by
            // name, before anything is created.
            let mut st = State::open(args)?;
            let class =
                StageClass::admit_tag(&need(args, "--class")?).map_err(|e| format!("{e:?}"))?;
            let now = st.clock.now();
            let ttl: u64 = flag(args, "--ttl-ms")
                .map(|s| s.parse().unwrap_or(3_600_000))
                .unwrap_or(3_600_000);
            let basis = match (flag(args, "--basis-root"), flag(args, "--basis-stage")) {
                (Some(identity), None) => StageBasis::RootAuthorization { identity },
                (None, Some(stage)) => StageBasis::PredecessorStage {
                    stage,
                    adjudication_digest: parse_digest(&need(args, "--basis-adjudication")?)?,
                },
                _ => {
                    return Err("give exactly one of --basis-root or --basis-stage with \
                         --basis-adjudication"
                        .into())
                }
            };
            let pins = flags(args, "--pin")
                .iter()
                .map(|p| parse_pin(p))
                .collect::<Result<Vec<_>, _>>()?;
            let repair = if class.is_repair() {
                Some(RepairBasis {
                    original_stage: need(args, "--repair-original-stage")?,
                    rejected_review_receipt: parse_digest(&need(args, "--repair-receipt")?)?,
                    finding_ids: flags(args, "--repair-finding"),
                    scope_class: RepairScopeClass::from_tag(&need(args, "--repair-scope")?)
                        .ok_or("unknown repair scope class")?,
                    nonclaims: flags(args, "--repair-nonclaim"),
                    review_requirement: parse_review_requirement_flag(args, "--repair-review")?,
                })
            } else {
                None
            };
            let proposal = CampaignStageProposal::propose(
                need(args, "--upstream-digest")?,
                need(args, "--campaign")?,
                need(args, "--stage")?,
                class,
                class.required_role(),
                class.required_effect_class(),
                basis,
                pins,
                flags(args, "--allow"),
                need(args, "--evidence-contract")?,
                need(args, "--handoff-schema")?,
                ClockReading(now.0 + ttl),
                need(args, "--nonce")?,
                flag(args, "--worktree").unwrap_or_default(),
                parse_review_requirement_flag(args, "--review")?,
                flags(args, "--nonclaim"),
                repair,
                now,
            )
            .map_err(|e| format!("{e:?}"))?;
            let digest = campaign_svc::propose_stage(&mut st.store, &proposal)
                .map_err(|e| format!("{e:?}"))?;
            println!("proposal: {}", digest.to_hex());
            println!("note: recording a proposal creates no standing; `campaign admit` does");
            Ok(())
        }
        ["campaign", "admit"] => {
            let mut st = State::open(args)?;
            let digest = parse_digest(&need(args, "--proposal")?)?;
            let standing = campaign_svc::admit(&mut st.store, &digest, st.clock.now())
                .map_err(|e| format!("{e:?}"))?;
            println!("standing: {}", standing.digest().to_hex());
            println!("role: {}", standing.role().tag());
            println!("effect_class: {}", standing.effect_class().tag());
            Ok(())
        }
        ["campaign", "consume"] => {
            // Burn-before-effect: the consumption is durable before the
            // caller runs any effect. A second consumption hits the
            // crash-recovery classification and refuses.
            let mut st = State::open(args)?;
            let standing = parse_digest(&need(args, "--standing")?)?;
            let role = WorkerRole::from_tag(&need(args, "--role")?)
                .ok_or("unknown role; use operator, reviewer, or repair")?;
            let context = ExecutionContext {
                campaign: need(args, "--campaign")?,
                stage: need(args, "--stage")?,
                role,
                proposal_digest: parse_digest(&need(args, "--proposal")?)?,
            };
            let record = campaign_svc::consume(&mut st.store, &standing, &context, st.clock.now())
                .map_err(|e| format!("{e:?}"))?;
            println!("consumption: {}", record.digest.to_hex());
            println!("note: the burn is durable; the stage's effect may now run exactly once");
            Ok(())
        }
        ["campaign", "outcome"] => {
            let mut st = State::open(args)?;
            let standing = parse_digest(&need(args, "--standing")?)?;
            match flag(args, "--receipt") {
                Some(r) => {
                    let receipt = parse_digest(&r)?;
                    campaign_svc::record_receipt(&mut st.store, &standing, &receipt)
                        .map_err(|e| format!("{e:?}"))?;
                    println!("outcome: effect_completed_receipted");
                    println!("receipt: {}", receipt.to_hex());
                }
                None => {
                    campaign_svc::record_effect_completed(&mut st.store, &standing)
                        .map_err(|e| format!("{e:?}"))?;
                    println!("outcome: effect_completed_receipt_missing");
                    println!("note: ambiguous states refuse re-execution; never guess and re-run");
                }
            }
            Ok(())
        }
        ["campaign", "adjudicate"] => {
            let mut st = State::open(args)?;
            let verdict = match need(args, "--verdict")?.as_str() {
                "continue" => AdjudicationVerdict::Continue,
                "exact-repair" => AdjudicationVerdict::ExactRepair,
                "refuse" => AdjudicationVerdict::Refuse,
                other => {
                    return Err(format!(
                        "unknown verdict {other:?}; use continue, exact-repair, or refuse"
                    ))
                }
            };
            let residuals = flags(args, "--residual")
                .iter()
                .map(|r| {
                    let (kind, statement) =
                        r.split_once('=').ok_or("residual must be kind=statement")?;
                    Ok(ResidualStatement {
                        kind: kind.to_string(),
                        statement: statement.to_string(),
                    })
                })
                .collect::<Result<Vec<_>, &str>>()?;
            let receipt = campaign_svc::adjudicate(
                &mut st.store,
                &need(args, "--campaign")?,
                &need(args, "--stage")?,
                &parse_digest(&need(args, "--review-receipt")?)?,
                verdict,
                &need(args, "--adjudicator")?,
                flags(args, "--finding"),
                residuals,
                st.clock.now(),
            )
            .map_err(|e| format!("{e:?}"))?;
            println!("adjudication: {}", receipt.digest.to_hex());
            println!("verdict: {}", receipt.verdict.tag());
            for r in &receipt.residuals {
                println!("residual_obligation: {}: {}", r.kind, r.statement);
            }
            Ok(())
        }
        ["campaign", "export-repair-authority"] => {
            // Read-only P1 export: the exact Docket authority for one repair
            // stage's execution, as canonical JSON. No campaign state is
            // created or altered; the law (chain, supersession, expiry,
            // subset) is re-verified at export time.
            let mut st = State::open(args)?;
            let standing = parse_digest(&need(args, "--standing")?)?;
            let bundle = campaign_svc::export_repair_authority(
                &mut st.store,
                &standing,
                st.clock.now(),
                VERIFIER_ID,
            )
            .map_err(|e| format!("{e:?}"))?;
            let json = campaign_export::render(&bundle);
            match flag(args, "--out") {
                Some(path) => {
                    std::fs::write(&path, &json).map_err(|e| e.to_string())?;
                    let file_digest = campaign_export::sha256_hex(json.as_bytes());
                    std::fs::write(format!("{path}.sha256"), format!("{file_digest}\n"))
                        .map_err(|e| e.to_string())?;
                    println!("repair_authority_file: {path}");
                    println!("file_sha256: {file_digest}");
                }
                None => print!("{json}"),
            }
            println!("repair_authority: {}", bundle.digest.to_hex());
            println!("note: read-only export; no campaign state was created or altered");
            Ok(())
        }
        ["campaign", "verify-repair-authority"] => {
            // Read-only P1 verification: the artifact must parse, its typed
            // digest must recompute, and it must equal — field for field,
            // including exact burn state — the authority Docket re-derives
            // now. A stale, substituted, corrupted, or foreign artifact
            // refuses. No campaign state is created or altered.
            let mut st = State::open(args)?;
            let raw =
                std::fs::read_to_string(need(args, "--bundle")?).map_err(|e| e.to_string())?;
            let bundle = campaign_export::parse(&raw)?;
            if let Some(expect) = flag(args, "--expect-standing") {
                let expect = parse_digest(&expect)?;
                if bundle.standing != expect {
                    return Err(format!(
                        "Refusal(RepairAuthorityMismatch {{ field: \"standing\" }}): \
                         expected {expect}, artifact binds {}",
                        bundle.standing.to_hex()
                    ));
                }
            }
            campaign_svc::verify_repair_authority(
                &mut st.store,
                &bundle,
                st.clock.now(),
                VERIFIER_ID,
            )
            .map_err(|e| format!("{e:?}"))?;
            println!("verification: ok");
            println!("repair_authority: {}", bundle.digest.to_hex());
            println!("standing: {}", bundle.standing.to_hex());
            println!("adjudication: {}", bundle.adjudication.to_hex());
            Ok(())
        }
        ["campaign", "show"] => {
            // Read-only: no proposal, standing, consumption, or adjudication
            // is created or altered by this verb.
            let mut st = State::open(args)?;
            if let Some(p) = flag(args, "--proposal") {
                let digest = parse_digest(&p)?;
                let proposal = st
                    .store
                    .get_campaign_proposal(&digest)
                    .map_err(|e| format!("{e:?}"))?
                    .ok_or_else(|| format!("unknown proposal {p}"))?;
                println!("proposal: {}", proposal.digest.to_hex());
                println!("upstream_digest: {}", proposal.upstream_digest);
                println!("campaign: {}", proposal.campaign);
                println!("stage: {}", proposal.stage);
                println!("stage_class: {}", proposal.stage_class.tag());
                println!("role: {}", proposal.role.tag());
                println!("effect_class: {}", proposal.effect_class.tag());
                println!("expires_at_ms: {}", proposal.expires_at.0);
                println!("nonce: {}", proposal.nonce);
                for pin in &proposal.repositories {
                    println!(
                        "repository: {} commit={} tree={}",
                        pin.repository.as_str(),
                        pin.commit.as_str(),
                        pin.tree
                    );
                }
                for path in &proposal.allowed_paths {
                    println!("allowed_path: {path}");
                }
                for nonclaim in &proposal.nonclaims {
                    println!("nonclaim: {nonclaim}");
                }
            } else if let Some(s) = flag(args, "--standing") {
                let digest = parse_digest(&s)?;
                let standing = st
                    .store
                    .get_campaign_standing(&digest)
                    .map_err(|e| format!("{e:?}"))?
                    .ok_or_else(|| format!("unknown standing {s}"))?;
                println!("standing: {}", standing.digest().to_hex());
                println!("proposal: {}", standing.proposal_digest().to_hex());
                println!("upstream_digest: {}", standing.upstream_digest());
                println!("campaign: {}", standing.campaign());
                println!("stage: {}", standing.stage());
                println!("stage_class: {}", standing.stage_class().tag());
                println!("role: {}", standing.role().tag());
                println!("effect_class: {}", standing.effect_class().tag());
                println!("expires_at_ms: {}", standing.expires_at().0);
                println!("nonce: {}", standing.nonce());
                let consumption = st
                    .store
                    .get_campaign_consumption(&standing.digest())
                    .map_err(|e| format!("{e:?}"))?;
                println!(
                    "consumption_state: {}",
                    consumption_state_tag(classify(consumption.as_ref()))
                );
                if let Some(c) = &consumption {
                    println!("consumption: {}", c.digest.to_hex());
                    if let Some(r) = &c.receipt {
                        println!("receipt: {}", r.to_hex());
                    }
                }
            } else if has(args, "--adjudications") {
                let campaign = need(args, "--campaign")?;
                let stage = need(args, "--stage")?;
                for a in st
                    .store
                    .get_campaign_adjudications(&campaign, &stage)
                    .map_err(|e| format!("{e:?}"))?
                {
                    println!("adjudication: {}", a.digest.to_hex());
                    println!("verdict: {}", a.verdict.tag());
                    println!("review_receipt: {}", a.review_receipt.to_hex());
                    for f in &a.findings {
                        println!("finding: {f}");
                    }
                }
                for r in st
                    .store
                    .get_campaign_residuals(&campaign, &stage)
                    .map_err(|e| format!("{e:?}"))?
                {
                    println!("residual_obligation: {}: {}", r.kind, r.statement);
                }
            } else {
                return Err("give --proposal <digest>, --standing <digest>, or \
                     --adjudications with --campaign and --stage"
                    .into());
            }
            Ok(())
        }
        ["docket", "list"] | ["list"] => {
            let mut st = State::open(args)?;
            // One canonical list model sources both renderings; the human
            // table truncates long values, the JSON carries them complete.
            let rows = list::assemble_list(&mut st.store).map_err(|e| format!("{e:?}"))?;
            if has(args, "--json") {
                println!("{}", list::render_list_json(&rows));
            } else {
                print!("{}", list::render_list_text(&rows));
            }
            Ok(())
        }
        ["docket", "show"] | ["show"] => {
            let mut st = State::open(args)?;
            let attempt = resolve_attempt(&mut st, args)?;
            // One canonical read model sources both surfaces; the human and
            // JSON renderings are pure functions of the same assembled value.
            let d = dossier::assemble(&mut st.store, attempt).map_err(|e| format!("{e:?}"))?;
            if has(args, "--json") {
                println!("{}", dossier::render_json(&d));
            } else {
                print!("{}", dossier::render_text(&d));
            }
            Ok(())
        }
        ["continuity", "subject"] => {
            let mut st = State::open(args)?;
            let attempt = resolve_attempt(&mut st, args)?;
            let d = dossier::assemble(&mut st.store, attempt).map_err(|e| format!("{e:?}"))?;
            let repository_id = d.repository_id.ok_or_else(|| {
                format!(
                    "legacy dossier has no explicitly registered RepositoryId for path {}; \
                     register or migrate the locator explicitly; refusing path-derived identity",
                    d.attempt.repository.as_str()
                )
            })?;
            let subject = d.ref_continuity_subject.as_ref().ok_or_else(|| {
                "no exact ref-continuity subject: the attempt has no full committed result \
                 bound to its governed target ref"
                    .to_string()
            })?;
            let commitment = d
                .execution
                .commitment
                .as_ref()
                .ok_or_else(|| "attempt carries no commitment".to_string())?;
            if has(args, "--json") {
                println!(
                    "{{\"schema\":\"gwr:ref-continuity-operation:v0\",\
                     \"subject\":{},\"repository_id\":{},\"target_ref\":{},\
                     \"result_commit\":{},\"docket_attempt\":{},\"dossier_version\":{},\
                     \"prepared_attempt_digest\":{},\
                     \"repository_locator\":{{\"kind\":\"path\",\"value\":{}}},\
                     \"establishes\":\"Docket supplied the complete logical subject and its \
                     exact recorded components\",\
                     \"does_not_establish\":[\"the result commit remains incorporated now\",\
                     \"the repository locator is logical identity\",\
                     \"Continuity has committed or relied on this assumption\"]}}",
                    json_quote(subject.as_str()),
                    json_quote(&repository_id.to_string()),
                    json_quote(d.attempt.effect.target_ref.as_str()),
                    json_quote(commitment.result_commit.as_str()),
                    json_quote(&hex16s(d.attempt.attempt_id.as_bytes())),
                    d.version,
                    json_quote(&d.attempt.prepared_attempt_digest.to_hex()),
                    json_quote(d.attempt.repository.as_str()),
                );
            } else {
                println!("subject: {}", subject.as_str());
                println!("repository_id: {repository_id}");
                println!("target_ref: {}", d.attempt.effect.target_ref.as_str());
                println!("result_commit: {}", commitment.result_commit.as_str());
                println!(
                    "docket_attempt: {}",
                    hex16s(d.attempt.attempt_id.as_bytes())
                );
                println!("dossier_version: {}", d.version);
                println!(
                    "prepared_attempt_digest: {}",
                    d.attempt.prepared_attempt_digest.to_hex()
                );
                println!(
                    "repository_locator: {} (operational alias; not identity)",
                    d.attempt.repository.as_str()
                );
            }
            Ok(())
        }
        ["docket", "journal"] | ["journal"] => {
            let mut st = State::open(args)?;
            let attempt = resolve_attempt(&mut st, args)?;
            // Resolve through the recorded dispatch binding, derive the
            // expected digest from the persisted outcome records, and load
            // only the journal the store records for that dispatch. The pure
            // inspection verifies before a byte of content is rendered.
            let dispatch_id = st
                .store
                .find_attempt_dispatch(attempt)
                .map_err(|e| format!("{e:?}"))?;
            let commitment = optional_read(st.store.get_commitment(attempt))?;
            let refusal = st
                .store
                .get_dispatch_refusal(attempt)
                .map_err(|e| format!("{e:?}"))?;
            let indeterminate = optional_read(st.store.get_indeterminate(attempt))?;
            let expectation = journal::expectation(
                dispatch_id.is_some(),
                commitment.as_ref(),
                refusal.as_ref(),
                indeterminate.as_ref(),
            );
            let bytes = dispatch_id.and_then(|d| {
                std::fs::read(
                    st.dir
                        .join("journals")
                        .join(format!("{}.journal", hex16s(d.as_bytes()))),
                )
                .ok()
            });
            let view = journal::inspect(attempt, dispatch_id, expectation, bytes.as_deref());
            if has(args, "--json") {
                println!("{}", journal::render_journal_json(&view));
            } else {
                print!("{}", journal::render_journal_text(&view));
            }
            Ok(())
        }
        _ => Err(format!(
            "unknown command {cmd:?}; commands: repository register, repository relocate, \
             repository alias, repository show, repository migrate-attempt, request create, \
             prepare start, prepare poll, \
             candidate admit, grant standing, ratify, reserve, dispatch, observe, \
             rely review-queue, reconcile, recover fact, recover resolve, authz request, \
             authz accept, governed-loop accept, governed-loop reconcile-issuance, \
             governed-loop reconcile-attempt, governed-loop inspect, docket list, docket show, docket journal, continuity subject, \
             campaign propose-stage, campaign admit, campaign consume, campaign outcome, \
             campaign adjudicate, campaign export-repair-authority, \
             campaign verify-repair-authority, campaign show"
        )),
    }
}

fn read_stdin_bounded() -> Result<Vec<u8>, String> {
    const LIMIT: u64 = 1_048_576;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading governed-loop stdin: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > LIMIT {
        return Err("governed-loop stdin is empty or exceeds 1 MiB".to_owned());
    }
    Ok(bytes)
}
