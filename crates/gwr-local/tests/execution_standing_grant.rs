use gwr_local::execution_standing::OwnerTrust;
use gwr_local::execution_standing_grant::{
    derive_standing, sha256_digest, GrantEnrollmentV1, GrantUseV1, OwnerStandingGrantV1,
    GRANT_ENROLLMENT_SCHEMA_V1, GRANT_SCHEMA_V1,
};
use gwr_runtime::governed_loop::{
    hash_domain, make_custody, validate_standing, AgIssuanceWireV1, ExecutionStandingRequestV1,
    ExecutionStandingStatusV1, OccurrenceKeyWireV1, AG_ISSUANCE_SCHEMA_V1,
    STANDING_REQUEST_SCHEMA_V1,
};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
const WORK_SCHEMA: &str = "ag-effectd.docket-executor-systemd-work/v2";
const NOT_BEFORE: u64 = 1_000;
const EXPIRES: u64 = 100_000;
const TTL: u64 = 5_000;

fn d(label: &str) -> String {
    hash_domain("docket-grant-test/v1", label.as_bytes())
}

struct Env {
    root: PathBuf,
    trust: OwnerTrust,
    grant_path: PathBuf,
    marker: PathBuf,
    journal: PathBuf,
    grant: OwnerStandingGrantV1,
    enrollment: GrantEnrollmentV1,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn mkdir(path: &Path, mode: u32) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn env(max_uses: u32) -> Env {
    let root = std::env::temp_dir().join(format!(
        "docket-grant-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    mkdir(&root, 0o755);
    mkdir(&root.join("etc"), 0o755);
    mkdir(&root.join("uses"), 0o700);
    let uid = std::fs::metadata(&root).unwrap().uid();
    let grant = OwnerStandingGrantV1 {
        schema: GRANT_SCHEMA_V1.into(),
        grant_id: "labelwatch-attention-canary/1".into(),
        principal: "labelwatch-owner".into(),
        subject: d("subject"),
        scope: d("scope"),
        work_schema: WORK_SCHEMA.into(),
        not_before_unix_ms: NOT_BEFORE,
        expires_at_unix_ms: EXPIRES,
        max_uses,
        standing_ttl_ms: TTL,
        revocation_marker: root.join("etc/grant.revoked"),
        use_journal: root.join("uses"),
    };
    let mut env = Env {
        trust: OwnerTrust::anchored_for_tests(uid, &root),
        grant_path: root.join("etc/grant.json"),
        marker: root.join("etc/grant.revoked"),
        journal: root.join("uses"),
        enrollment: GrantEnrollmentV1 {
            schema: GRANT_ENROLLMENT_SCHEMA_V1.into(),
            principal: "labelwatch-owner".into(),
            grant: root.join("etc/grant.json"),
            grant_sha256: String::new(),
        },
        grant,
        root,
    };
    install_grant(&mut env);
    env
}

/// Owner enrollment: write the grant 0644 and pin its exact bytes.
fn install_grant(env: &mut Env) {
    let bytes = serde_json::to_vec_pretty(&env.grant).unwrap();
    let _ = std::fs::remove_file(&env.grant_path);
    std::fs::write(&env.grant_path, &bytes).unwrap();
    std::fs::set_permissions(&env.grant_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    env.enrollment.grant_sha256 = sha256_digest(&bytes);
}

fn issuance_with(n: u32, subject: &str, scope: &str, work_schema: &str) -> AgIssuanceWireV1 {
    let mut issuance = AgIssuanceWireV1 {
        schema: AG_ISSUANCE_SCHEMA_V1.into(),
        issuance: String::new(),
        key: OccurrenceKeyWireV1 {
            campaign: d("campaign"),
            occurrence: format!("00000000-0000-0000-0000-{n:012}"),
        },
        program: d("program"),
        proposal: d(&format!("proposal-{n}")),
        work_schema: work_schema.into(),
        work: d("work"),
        subject: subject.into(),
        scope: scope.into(),
        observation: d(&format!("observation-{n}")),
        standing_resolution: d(&format!("ag-standing-{n}")),
        mandate: d("mandate"),
        spend: d(&format!("spend-{n}")),
    };
    let basis = serde_json::json!({
        "key": {"campaign": issuance.key.campaign, "occurrence": issuance.key.occurrence},
        "mandate": issuance.mandate,
        "observation": issuance.observation,
        "program": issuance.program,
        "proposal": issuance.proposal,
        "scope": issuance.scope,
        "spend": issuance.spend,
        "standing_resolution": issuance.standing_resolution,
        "subject": issuance.subject,
        "work": issuance.work,
        "work_schema": issuance.work_schema,
    });
    issuance.issuance = hash_domain(
        "ag.governed-loop.issuance/v1",
        &serde_json::to_vec(&basis).unwrap(),
    );
    issuance
}

fn issuance(n: u32) -> AgIssuanceWireV1 {
    issuance_with(n, &d("subject"), &d("scope"), WORK_SCHEMA)
}

fn request(issuance: &AgIssuanceWireV1, now: u64) -> ExecutionStandingRequestV1 {
    ExecutionStandingRequestV1 {
        schema: STANDING_REQUEST_SCHEMA_V1.into(),
        issuance: issuance.clone(),
        now_unix_ms: now,
    }
}

fn derive(
    env: &Env,
    n: u32,
    now: u64,
) -> Result<gwr_runtime::governed_loop::ExecutionStandingResolutionV1, String> {
    derive_standing(&env.enrollment, &env.trust, &request(&issuance(n), now))
}

fn entries(env: &Env) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&env.journal)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn entry_path(env: &Env, index: u32) -> PathBuf {
    env.journal.join(format!("use-{index:06}.json"))
}

fn rewrite(path: &Path, bytes: &[u8]) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).unwrap();
}

#[test]
fn derives_one_exactly_bound_current_standing_and_journals_the_use() {
    let env = env(1);
    let issued = issuance(1);
    let now = 2_000;
    let standing = derive_standing(&env.enrollment, &env.trust, &request(&issued, now)).unwrap();
    assert_eq!(standing.status, ExecutionStandingStatusV1::Current);
    assert_eq!(standing.issuance, issued.issuance);
    assert_eq!(standing.campaign, issued.key.campaign);
    assert_eq!(standing.occurrence, issued.key.occurrence);
    assert_eq!(standing.subject, issued.subject);
    assert_eq!(standing.scope, issued.scope);
    assert_eq!(standing.resolved_at_unix_ms, now);
    assert_eq!(standing.expires_at_unix_ms, now + TTL);
    // H(grant ‖ issuance): the grant's exact pinned digest and this issuance.
    let basis = serde_json::to_vec(&serde_json::json!({
        "grant": env.enrollment.grant_sha256,
        "issuance": issued.issuance,
    }))
    .unwrap();
    assert_eq!(
        standing.execution_standing,
        hash_domain("docket.grant-execution-standing/v1", &basis)
    );
    validate_standing(&issued, &standing, now).unwrap();
    let custody = make_custody(&issued, &standing, now).unwrap();
    assert_ne!(custody.execution_standing, custody.ag_spend);

    assert_eq!(entries(&env), ["use-000001.json"]);
    let meta = std::fs::metadata(entry_path(&env, 1)).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o444);
    let entry: GrantUseV1 =
        serde_json::from_slice(&std::fs::read(entry_path(&env, 1)).unwrap()).unwrap();
    assert_eq!(entry.use_index, 1);
    assert_eq!(entry.previous, None);
    assert_eq!(entry.grant, env.enrollment.grant_sha256);
    assert_eq!(entry.issuance, issued.issuance);

    // The derived standing never validates for any other issuance.
    let other = issuance(2);
    assert_eq!(
        validate_standing(&other, &standing, now).unwrap_err(),
        "governed-execution-standing-binding-mismatch"
    );
    // The grant itself is never written by derivation.
    let grant_bytes = std::fs::read(&env.grant_path).unwrap();
    assert_eq!(sha256_digest(&grant_bytes), env.enrollment.grant_sha256);
}

#[test]
fn same_issuance_rederives_identically_without_consuming_another_use() {
    let env = env(1);
    let first = derive(&env, 1, 2_000).unwrap();
    let again = derive(&env, 1, 2_500).unwrap();
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&again).unwrap()
    );
    assert_eq!(entries(&env), ["use-000001.json"]);
    // The re-derived answer still expires with the first derivation's ttl.
    assert_eq!(
        derive(&env, 1, 2_000 + TTL).unwrap_err(),
        "governed-execution-standing-not-current"
    );
}

#[test]
fn second_issuance_within_max_uses_then_exhaustion_refuses() {
    let env = env(2);
    let first = derive(&env, 1, 2_000).unwrap();
    let second = derive(&env, 2, 3_000).unwrap();
    assert_ne!(first.execution_standing, second.execution_standing);
    assert_ne!(first.currentness, second.currentness);
    let entry1 = std::fs::read(entry_path(&env, 1)).unwrap();
    let entry2: GrantUseV1 =
        serde_json::from_slice(&std::fs::read(entry_path(&env, 2)).unwrap()).unwrap();
    assert_eq!(entry2.use_index, 2);
    assert_eq!(entry2.previous, Some(sha256_digest(&entry1)));

    assert_eq!(
        derive(&env, 3, 3_500).unwrap_err(),
        "execution-standing-grant-exhausted"
    );
    assert_eq!(entries(&env).len(), 2);
    // Already-journaled issuances still re-derive after exhaustion.
    assert_eq!(derive(&env, 2, 3_500).unwrap(), second);
}

#[test]
fn concurrent_new_issuances_never_exceed_max_uses() {
    let env = env(3);
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (1..=12)
            .map(|n| {
                let env = &env;
                scope.spawn(move || derive(env, n, 2_000))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
    assert!(results
        .iter()
        .filter_map(|r| r.as_ref().err())
        .all(|e| e == "execution-standing-grant-exhausted"));
    assert_eq!(entries(&env).len(), 3);
}

#[test]
fn revoked_grant_refuses_new_and_journaled_issuances() {
    let env = env(2);
    derive(&env, 1, 2_000).unwrap();
    std::fs::write(&env.marker, b"revoked by owner\n").unwrap();
    assert_eq!(
        derive(&env, 1, 2_100).unwrap_err(),
        "execution-standing-grant-revoked"
    );
    assert_eq!(
        derive(&env, 2, 2_100).unwrap_err(),
        "execution-standing-grant-revoked"
    );
    assert_eq!(entries(&env).len(), 1);
    // Any object at the reference revokes, including a dangling symlink.
    std::fs::remove_file(&env.marker).unwrap();
    std::os::unix::fs::symlink("/nonexistent", &env.marker).unwrap();
    assert_eq!(
        derive(&env, 2, 2_100).unwrap_err(),
        "execution-standing-grant-revoked"
    );
}

#[test]
fn revocation_reference_in_untrusted_directory_refuses() {
    let mut env = env(1);
    mkdir(&env.root.join("open"), 0o777);
    env.grant.revocation_marker = env.root.join("open/grant.revoked");
    install_grant(&mut env);
    assert_eq!(
        derive(&env, 1, 2_000).unwrap_err(),
        "execution-standing-grant-revocation-reference"
    );
}

#[test]
fn validity_window_refuses_not_yet_valid_and_expired() {
    let env = env(3);
    assert_eq!(
        derive(&env, 1, NOT_BEFORE - 1).unwrap_err(),
        "execution-standing-grant-not-yet-valid"
    );
    assert_eq!(
        derive(&env, 1, EXPIRES).unwrap_err(),
        "execution-standing-grant-expired"
    );
    assert!(entries(&env).is_empty());
    // Within the window; the answer never outlives the grant.
    let late = derive(&env, 1, EXPIRES - 10).unwrap();
    assert_eq!(late.expires_at_unix_ms, EXPIRES);
    assert_eq!(
        derive(&env, 1, EXPIRES).unwrap_err(),
        "execution-standing-grant-expired"
    );
    assert_eq!(
        derive(&env, 2, 500).unwrap_err(),
        "execution-standing-grant-not-yet-valid"
    );
}

#[test]
fn subject_scope_and_work_schema_must_equal_the_grant() {
    let env = env(3);
    for (issued, error) in [
        (
            issuance_with(1, &d("other-subject"), &d("scope"), WORK_SCHEMA),
            "execution-standing-grant-subject-mismatch",
        ),
        (
            issuance_with(1, &d("subject"), &d("other-scope"), WORK_SCHEMA),
            "execution-standing-grant-scope-mismatch",
        ),
        (
            issuance_with(
                1,
                &d("subject"),
                &d("scope"),
                "ag-effectd.managed-file-work/v2",
            ),
            "execution-standing-grant-work-schema-mismatch",
        ),
    ] {
        assert_eq!(
            derive_standing(&env.enrollment, &env.trust, &request(&issued, 2_000)).unwrap_err(),
            error
        );
    }
    assert!(entries(&env).is_empty());
    // A forged issuance identity is refused before any grant use.
    let mut forged = issuance(1);
    forged.spend = d("other-spend");
    assert!(derive_standing(&env.enrollment, &env.trust, &request(&forged, 2_000)).is_err());
    assert!(entries(&env).is_empty());
}

#[test]
fn tampered_or_unprotected_grant_refuses() {
    let mut env = env(1);
    // Enlarging the grant without the owner's new pin is a digest mismatch.
    let mut enlarged = env.grant.clone();
    enlarged.max_uses = 1_000;
    std::fs::write(
        &env.grant_path,
        serde_json::to_vec_pretty(&enlarged).unwrap(),
    )
    .unwrap();
    assert_eq!(
        derive(&env, 1, 2_000).unwrap_err(),
        "execution-standing-grant-digest-mismatch"
    );
    install_grant(&mut env);
    let mut pin = env.enrollment.clone();
    pin.grant_sha256 = d("not-the-grant");
    assert_eq!(
        derive_standing(&pin, &env.trust, &request(&issuance(1), 2_000)).unwrap_err(),
        "execution-standing-grant-digest-mismatch"
    );
    pin.grant_sha256 = "sha256:short".into();
    assert_eq!(
        derive_standing(&pin, &env.trust, &request(&issuance(1), 2_000)).unwrap_err(),
        "execution-standing-grant-enrollment"
    );
    let mut principal = env.enrollment.clone();
    principal.principal = "someone-else".into();
    assert_eq!(
        derive_standing(&principal, &env.trust, &request(&issuance(1), 2_000)).unwrap_err(),
        "execution-standing-grant-document"
    );
    // A grant writable by group/other is not owner-controlled.
    std::fs::set_permissions(&env.grant_path, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert_eq!(
        derive(&env, 1, 2_000).unwrap_err(),
        "execution-standing-owner-file"
    );
    std::fs::set_permissions(&env.grant_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    // A writable grant directory or a symlinked grant is refused.
    std::fs::set_permissions(env.root.join("etc"), std::fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        derive(&env, 1, 2_000).unwrap_err(),
        "execution-standing-owner-directory"
    );
    std::fs::set_permissions(env.root.join("etc"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let link = env.root.join("etc/grant-link.json");
    std::os::unix::fs::symlink(&env.grant_path, &link).unwrap();
    let mut linked = env.enrollment.clone();
    linked.grant = link;
    assert!(derive_standing(&linked, &env.trust, &request(&issuance(1), 2_000)).is_err());
    // Out-of-bounds grant documents are refused even when pinned.
    let changes: [fn(&mut OwnerStandingGrantV1); 5] = [
        |g: &mut OwnerStandingGrantV1| g.max_uses = 0,
        |g: &mut OwnerStandingGrantV1| g.standing_ttl_ms = 0,
        |g: &mut OwnerStandingGrantV1| g.expires_at_unix_ms = g.not_before_unix_ms,
        |g: &mut OwnerStandingGrantV1| g.subject = "attention-canary.service".into(),
        |g: &mut OwnerStandingGrantV1| g.schema = "docket.owner-execution-standing-grant/v0".into(),
    ];
    for change in changes {
        let original = env.grant.clone();
        change(&mut env.grant);
        install_grant(&mut env);
        assert_eq!(
            derive(&env, 1, 2_000).unwrap_err(),
            "execution-standing-grant-document"
        );
        env.grant = original;
        install_grant(&mut env);
    }
    assert!(entries(&env).is_empty());
    derive(&env, 1, 2_000).unwrap();
}

#[test]
fn journal_tampering_fails_closed() {
    let env = env(3);
    derive(&env, 1, 2_000).unwrap();
    derive(&env, 2, 2_100).unwrap();
    let one = std::fs::read(entry_path(&env, 1)).unwrap();
    let two = std::fs::read(entry_path(&env, 2)).unwrap();
    let restore = |env: &Env| {
        for name in entries(env) {
            std::fs::remove_file(env.journal.join(name)).unwrap();
        }
        for (index, bytes) in [(1, &one), (2, &two)] {
            std::fs::write(entry_path(env, index), bytes).unwrap();
            std::fs::set_permissions(
                entry_path(env, index),
                std::fs::Permissions::from_mode(0o444),
            )
            .unwrap();
        }
        derive(env, 1, 2_200).unwrap();
    };
    let expect = |env: &Env, error: &str| {
        assert_eq!(derive(env, 1, 2_200).unwrap_err(), error);
        assert_eq!(derive(env, 3, 2_200).unwrap_err(), error);
    };

    // Rewriting an earlier use (here: re-dating it) breaks the hash chain.
    let mut changed: GrantUseV1 = serde_json::from_slice(&one).unwrap();
    changed.derived_at_unix_ms = 1_500;
    rewrite(&entry_path(&env, 1), &serde_json::to_vec(&changed).unwrap());
    expect(&env, "execution-standing-grant-journal-entry-binding");
    restore(&env);

    // A use rewritten to repeat another issuance is refused.
    let mut changed: GrantUseV1 = serde_json::from_slice(&two).unwrap();
    changed.issuance = issuance(1).issuance;
    rewrite(&entry_path(&env, 2), &serde_json::to_vec(&changed).unwrap());
    expect(&env, "execution-standing-grant-journal-entry-binding");
    restore(&env);

    // Deleting an earlier use to free a slot leaves a gap.
    std::fs::remove_file(entry_path(&env, 1)).unwrap();
    expect(&env, "execution-standing-grant-journal-gap");
    restore(&env);

    // Unexpected or out-of-range names, garbage and noncanonical bytes.
    std::fs::write(env.journal.join("note.txt"), b"x").unwrap();
    expect(&env, "execution-standing-grant-journal-unexpected-entry");
    restore(&env);
    std::fs::write(entry_path(&env, 9), b"x").unwrap();
    expect(&env, "execution-standing-grant-journal-unexpected-entry");
    restore(&env);
    rewrite(&entry_path(&env, 2), b"{\"schema\":");
    expect(&env, "execution-standing-grant-journal-entry-document");
    restore(&env);
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<GrantUseV1>(&two).unwrap()).unwrap();
    rewrite(&entry_path(&env, 2), &pretty);
    expect(&env, "execution-standing-grant-journal-entry-noncanonical");
    restore(&env);

    // Entries and the journal directory must stay owner-only writable.
    std::fs::set_permissions(entry_path(&env, 2), std::fs::Permissions::from_mode(0o666)).unwrap();
    expect(&env, "execution-standing-grant-journal-entry-owner");
    restore(&env);
    std::fs::remove_file(entry_path(&env, 2)).unwrap();
    std::os::unix::fs::symlink(entry_path(&env, 1), entry_path(&env, 2)).unwrap();
    expect(&env, "execution-standing-grant-journal-entry-owner");
    restore(&env);
    std::fs::set_permissions(&env.journal, std::fs::Permissions::from_mode(0o770)).unwrap();
    expect(&env, "execution-standing-grant-journal-directory");
    std::fs::set_permissions(&env.journal, std::fs::Permissions::from_mode(0o700)).unwrap();
    derive(&env, 1, 2_200).unwrap();
    assert_eq!(entries(&env).len(), 2);
}

#[test]
fn journal_belongs_to_one_exact_grant() {
    let mut env = env(1);
    derive(&env, 1, 2_000).unwrap();
    // The owner re-enrolls an enlarged grant but reuses the old journal.
    env.grant.max_uses = 5;
    install_grant(&mut env);
    assert_eq!(
        derive(&env, 2, 2_100).unwrap_err(),
        "execution-standing-grant-journal-foreign-grant"
    );
    // A missing journal directory refuses rather than counting from zero.
    let mut env = self::env(1);
    env.grant.use_journal = env.root.join("missing");
    install_grant(&mut env);
    assert_eq!(
        derive(&env, 1, 2_000).unwrap_err(),
        "execution-standing-grant-journal-directory"
    );
}

#[test]
fn clock_regression_against_the_journal_refuses_a_new_use() {
    let env = env(3);
    derive(&env, 1, 5_000).unwrap();
    assert_eq!(
        derive(&env, 2, 4_000).unwrap_err(),
        "execution-standing-grant-clock-regression"
    );
}

#[test]
fn grant_resolver_cli_refuses_without_enrollment_or_with_arguments() {
    let bin = env!("CARGO_BIN_EXE_docket-standing-grant-resolver");
    let out = std::process::Command::new(bin)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("execution-standing refused: "));
    let out = std::process::Command::new(bin)
        .arg("--grant=/tmp/anything")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "execution-standing refused: standing-resolver-takes-no-arguments\n"
    );
}
