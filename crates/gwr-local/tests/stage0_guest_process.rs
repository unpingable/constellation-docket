use gwr_local::stage0_guest::protocol::{
    read_frame, transcript_digest, validate_hello, validate_operation_response, write_frame,
    GuestOutcomeV1, GuestRequestV1, GuestResponseV1, OperationV1, WorkBindingV1, GUEST_PROTOCOL_V1,
    STAGE0_WORK_SCHEMA_V1,
};
use gwr_local::stage0_guest::proxy::{
    decode_outer_dispatch, decode_outer_outcome, encode_outer_outcome, CONFIG_SCHEMA_V1,
    SIMULATOR_BINARY_NAME,
};
use gwr_local::{governed_loop, store::SqliteStore};
use gwr_runtime::governed_loop::{
    digest_json_string, hash_domain, AgIssuanceWireV1, AgIssuerTrustConfigV1,
    ExecutionStandingResolutionV1, ExecutionStandingStatusV1,
    ExecutorDispatchWireV1, ExecutorOutcomeWireV1, GovernedRecordStatusV1,
    IssuanceAuthenticationWireV1, OccurrenceKeyWireV1, SignedIssuanceEnvelopeWireV1,
    TrustedAgIssuerV1, AG_ISSUANCE_SCHEMA_V1, SIGNED_ISSUANCE_SCHEMA_V1,
    STANDING_RESOLUTION_SCHEMA_V1,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const PROXY: &str = env!("CARGO_BIN_EXE_docket-stage0-host-proxy");
const SIMULATOR: &str = env!("CARGO_BIN_EXE_docket-stage0-simulated-guest");
const SIGNATURE_PREFIX_V1: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v1\0";

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = PathBuf::from(format!(
            "/tmp/docket-stage0-process-test-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn private_dir(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        if self.0.starts_with("/tmp/docket-stage0-process-test-") {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn digest(label: &str) -> String {
    transcript_digest("stage0-process-test/v1", &[label.as_bytes()])
}

fn binding(label: &str, work: &str, subject: &str, scope: &str) -> WorkBindingV1 {
    WorkBindingV1 {
        attempt: digest(&format!("{label}-attempt")),
        marker: digest(&format!("{label}-marker")),
        work_schema: STAGE0_WORK_SCHEMA_V1.to_owned(),
        work: work.to_owned(),
        subject: subject.to_owned(),
        scope: scope.to_owned(),
    }
}

struct GuestCall {
    status: ExitStatus,
    response: Option<GuestResponseV1>,
    stderr: Vec<u8>,
}

fn guest_call(
    state: &Path,
    operation: OperationV1,
    binding: &WorkBindingV1,
    fault: Option<&str>,
) -> GuestCall {
    let session = digest(&format!(
        "session-{}",
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut command = Command::new(SIMULATOR);
    command
        .arg(state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(fault) = fault {
        command.env("DOCKET_STAGE0_FAULT", fault);
    }
    let mut child = command.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    write_frame(&mut input, &GuestRequestV1::hello(session.clone())).unwrap();
    let hello: GuestResponseV1 = read_frame(&mut output).unwrap();
    let simulator_build =
        gwr_local::stage0_guest::proxy::measure_executable(Path::new(SIMULATOR)).unwrap();
    validate_hello(&hello, &session, &simulator_build).unwrap();
    write_frame(
        &mut input,
        &GuestRequestV1::operation(operation, session.clone(), binding),
    )
    .unwrap();
    let response: Option<GuestResponseV1> = read_frame(&mut output).ok();
    drop(input);
    let status = child.wait().unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    if let Some(response) = &response {
        validate_operation_response(response.clone(), operation, &session, binding).unwrap();
    }
    GuestCall {
        status,
        response,
        stderr,
    }
}

fn response_result(response: GuestResponseV1) -> (GuestOutcomeV1, String) {
    match response {
        GuestResponseV1::Execute {
            outcome, receipt, ..
        }
        | GuestResponseV1::Reconcile {
            outcome, receipt, ..
        } => (outcome, receipt),
        GuestResponseV1::Hello { .. } => panic!("unexpected hello"),
    }
}

#[test]
fn simulator_process_fault_matrix_and_restart_reconciliation() {
    let root = TestRoot::new();
    let subject = digest("subject");
    let scope = digest("scope");
    let work = digest("work");

    let before_state = root.private_dir("before");
    let before = binding("before", &work, &subject, &scope);
    let died = guest_call(
        &before_state,
        OperationV1::Execute,
        &before,
        Some("before_reservation"),
    );
    assert_eq!(died.status.code(), Some(86));
    assert!(died.response.is_none());
    let missing = guest_call(&before_state, OperationV1::Reconcile, &before, None);
    assert!(!missing.status.success());
    assert!(missing.response.is_none());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("missing-attempt"));
    assert!(!before_state.join("result.cell").exists());

    let reserved_state = root.private_dir("reserved");
    let reserved = binding("reserved", &work, &subject, &scope);
    assert_eq!(
        guest_call(
            &reserved_state,
            OperationV1::Execute,
            &reserved,
            Some("after_reservation"),
        )
        .status
        .code(),
        Some(86)
    );
    let failure = guest_call(&reserved_state, OperationV1::Reconcile, &reserved, None);
    assert!(failure.status.success());
    assert_eq!(
        response_result(failure.response.unwrap()).0,
        GuestOutcomeV1::Failure
    );
    assert!(!reserved_state.join("result.cell").exists());

    let effected_state = root.private_dir("effected");
    let effected = binding("effected", &work, &subject, &scope);
    assert_eq!(
        guest_call(
            &effected_state,
            OperationV1::Execute,
            &effected,
            Some("after_effect"),
        )
        .status
        .code(),
        Some(86)
    );
    let cell = std::fs::read(effected_state.join("result.cell")).unwrap();
    let success = guest_call(&effected_state, OperationV1::Reconcile, &effected, None);
    assert_eq!(
        response_result(success.response.unwrap()).0,
        GuestOutcomeV1::Success
    );
    assert_eq!(
        std::fs::read(effected_state.join("result.cell")).unwrap(),
        cell
    );

    let committed_state = root.private_dir("committed");
    let committed = binding("committed", &work, &subject, &scope);
    assert_eq!(
        guest_call(
            &committed_state,
            OperationV1::Execute,
            &committed,
            Some("after_commit"),
        )
        .status
        .code(),
        Some(86)
    );
    let reconciled = guest_call(&committed_state, OperationV1::Reconcile, &committed, None);
    let replayed = guest_call(&committed_state, OperationV1::Execute, &committed, None);
    assert_eq!(
        response_result(reconciled.response.unwrap()),
        response_result(replayed.response.unwrap())
    );
}

fn write_config(path: &Path, state: &Path, subject: &str, scope: &str) {
    let value = serde_json::json!({
        "schema": CONFIG_SCHEMA_V1,
        "scope": scope,
        "state_directory": state,
        "subject": subject,
    });
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn run_proxy(executable: &Path, arguments: &[&str], stdin: Option<&[u8]>) -> std::process::Output {
    let mut child = Command::new(executable)
        .args(arguments)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(stdin) = stdin {
        child.stdin.take().unwrap().write_all(stdin).unwrap();
    }
    child.wait_with_output().unwrap()
}

fn plan_id(proxy: &Path, config: &Path) -> String {
    let output = run_proxy(proxy, &["plan-id", config.to_str().unwrap()], None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end()
        .to_owned()
}

fn proxy_fixture(root: &TestRoot) -> (PathBuf, PathBuf, PathBuf, String, String, String) {
    let bin = root.private_dir("bin");
    let proxy = bin.join("docket-stage0-host-proxy");
    let simulator = bin.join(SIMULATOR_BINARY_NAME);
    std::fs::copy(PROXY, &proxy).unwrap();
    std::fs::copy(SIMULATOR, &simulator).unwrap();
    std::fs::set_permissions(&proxy, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&simulator, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.private_dir("guest-state");
    let subject = digest("proxy-subject");
    let scope = digest("proxy-scope");
    let config = root.path().join("proxy-config.json");
    write_config(&config, &state, &subject, &scope);
    (
        proxy,
        simulator,
        config,
        subject,
        scope,
        state.to_string_lossy().into_owned(),
    )
}

#[test]
fn proxy_conforms_to_outer_v1_and_terminal_replay_is_identical() {
    let root = TestRoot::new();
    let (proxy, _simulator, config, subject, scope, _) = proxy_fixture(&root);
    let plan = plan_id(&proxy, &config);
    let binding = binding("proxy", &plan, &subject, &scope);
    let dispatch = ExecutorDispatchWireV1 {
        attempt: binding.attempt,
        marker: binding.marker,
        work_schema: binding.work_schema,
        work: binding.work,
        subject: binding.subject,
        scope: binding.scope,
    };
    let dispatch_bytes = serde_json::to_vec(&dispatch).unwrap();
    let executed = run_proxy(
        &proxy,
        &["execute", config.to_str().unwrap()],
        Some(&dispatch_bytes),
    );
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    let execute_outcome: ExecutorOutcomeWireV1 = serde_json::from_slice(&executed.stdout).unwrap();
    let reconciled = run_proxy(
        &proxy,
        &["reconcile", config.to_str().unwrap()],
        Some(&dispatch_bytes),
    );
    assert!(reconciled.status.success());
    let reconcile_outcome: ExecutorOutcomeWireV1 =
        serde_json::from_slice(&reconciled.stdout).unwrap();
    assert_eq!(reconcile_outcome, execute_outcome);
    assert_eq!(
        executed.stdout,
        serde_json::to_vec(&serde_json::json!({
            "attempt": execute_outcome.attempt,
            "marker": execute_outcome.marker,
            "outcome": "success",
            "receipt": execute_outcome.receipt,
        }))
        .unwrap()
        .into_iter()
        .chain(*b"\n")
        .collect::<Vec<_>>()
    );
}

#[test]
fn canonical_c1_executor_transport_corpus_passes_unchanged() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../conformance/executor-transport-v1/corpus.json"
    ))
    .unwrap();
    assert_eq!(corpus["transport"], "docket.governed-executor-transport/v1");
    assert_eq!(corpus["max_document_bytes"], 1_048_576);
    for case in corpus["decode_cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap().as_bytes();
        let accepted = match case["kind"].as_str().unwrap() {
            "dispatch" => decode_outer_dispatch(input).map(|dispatch| {
                serde_json::to_vec(&serde_json::to_value(dispatch).unwrap()).unwrap()
            }),
            "outcome" => decode_outer_outcome(input).and_then(|outcome| {
                let mut encoded = encode_outer_outcome(&outcome)?;
                encoded.pop();
                Ok(encoded)
            }),
            other => panic!("unknown C1 corpus kind {other}"),
        };
        assert_eq!(
            accepted.is_ok(),
            case["expect"] == "accept",
            "C1 corpus case {}",
            case["id"]
        );
        if let (Ok(actual), Some(expected)) = (accepted, case["canonical_output"].as_str()) {
            assert_eq!(actual, expected.as_bytes(), "C1 corpus case {}", case["id"]);
        }
    }
}

#[test]
fn oversized_outer_dispatch_refuses_without_mechanics() {
    let root = TestRoot::new();
    let (proxy, _simulator, config, _subject, _scope, _) = proxy_fixture(&root);
    let oversized = vec![b'x'; 1_048_577];
    let result = run_proxy(
        &proxy,
        &["execute", config.to_str().unwrap()],
        Some(&oversized),
    );
    assert!(!result.status.success());
    assert!(!root.path().join("guest-state/result.cell").exists());
}
#[test]
fn plan_id_binds_both_builds_protocol_and_static_configuration() {
    let root = TestRoot::new();
    let (proxy, simulator, config, subject, scope, state) = proxy_fixture(&root);
    let original = plan_id(&proxy, &config);

    write_config(
        &config,
        Path::new(&state),
        &digest("changed-subject"),
        &scope,
    );
    assert_ne!(plan_id(&proxy, &config), original);
    write_config(&config, Path::new(&state), &subject, &scope);

    let mut file = OpenOptions::new().append(true).open(&simulator).unwrap();
    file.write_all(b"stage0-build-substitution").unwrap();
    drop(file);
    assert_ne!(plan_id(&proxy, &config), original);
}

#[test]
fn current_docket_refuses_unenrolled_stage0_proxy_before_guest_effect() {
    let root = TestRoot::new();
    let (proxy, simulator, config, subject, scope, _) = proxy_fixture(&root);
    let plan = plan_id(&proxy, &config);
    let database = root.path().join("docket.sqlite");
    drop(SqliteStore::open(&database).unwrap());

    let mut issuance = AgIssuanceWireV1 {
        schema: AG_ISSUANCE_SCHEMA_V1.to_owned(),
        issuance: digest("placeholder"),
        key: OccurrenceKeyWireV1 {
            campaign: digest("campaign"),
            occurrence: "00000000-0000-0000-0000-000000000001".to_owned(),
        },
        program: digest("program"),
        proposal: digest("proposal"),
        work_schema: STAGE0_WORK_SCHEMA_V1.to_owned(),
        work: plan,
        subject,
        scope,
        observation: digest("observation"),
        standing_resolution: digest("ag-standing-resolution"),
        mandate: digest("mandate"),
        spend: digest("ag-spend"),
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
    let body = serde_json::to_vec(&serde_json::to_value(&issuance).unwrap()).unwrap();
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let mut signed = SIGNATURE_PREFIX_V1.to_vec();
    signed.extend_from_slice(&body);
    let public_key = b64_encode(key.public_key().as_ref());
    let envelope = SignedIssuanceEnvelopeWireV1 {
        schema: SIGNED_ISSUANCE_SCHEMA_V1.to_owned(),
        body_b64: b64_encode(&body),
        authentication: IssuanceAuthenticationWireV1 {
            issuer_principal: "ag.stage0.test".to_owned(),
            signer_key_id: "stage0-test-key".to_owned(),
            signer_public_key: public_key.clone(),
            signature: b64_encode(key.sign(&signed).as_ref()),
        },
    };
    let trust = serde_json::to_vec(&AgIssuerTrustConfigV1 {
        issuers: vec![TrustedAgIssuerV1 {
            issuer_principal: "ag.stage0.test".to_owned(),
            key_id: "stage0-test-key".to_owned(),
            public_key,
        }],
    })
    .unwrap();
    let attempt =
        digest_json_string("ag.governed-loop.docket-attempt/v1", &issuance.issuance).unwrap();
    let standing = ExecutionStandingResolutionV1 {
        schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
        resolution: digest("docket-standing-resolution"),
        currentness: digest("docket-standing-currentness"),
        execution_standing: digest("docket-standing"),
        issuance: issuance.issuance.clone(),
        campaign: issuance.key.campaign.clone(),
        occurrence: issuance.key.occurrence.clone(),
        subject: issuance.subject.clone(),
        scope: issuance.scope.clone(),
        status: ExecutionStandingStatusV1::Current,
        resolved_at_unix_ms: 0,
        expires_at_unix_ms: i64::MAX as u64,
    };
    let resolver = root.path().join("standing-resolver.py");
    let standing_json = serde_json::to_string(&standing).unwrap();
    std::fs::write(
        &resolver,
        format!(
            "#!/usr/bin/python3\nimport sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(b'{standing_json}')\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o700)).unwrap();

    let envelope_path = root.path().join("issuance.json");
    let trust_path = root.path().join("trust.json");
    std::fs::write(&envelope_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    std::fs::write(&trust_path, &trust).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "docket_transport_refusal_child", "--nocapture"])
        .env("DOCKET_STAGE0_DOCKET_CHILD", "1")
        .env("DOCKET_STAGE0_FAULT", "after_commit")
        .env("DOCKET_STAGE0_CHILD_DATABASE", &database)
        .env("DOCKET_STAGE0_CHILD_ENVELOPE", &envelope_path)
        .env("DOCKET_STAGE0_CHILD_TRUST", &trust_path)
        .env("DOCKET_STAGE0_CHILD_RESOLVER", &resolver)
        .env("DOCKET_STAGE0_CHILD_PROXY", &proxy)
        .env("DOCKET_STAGE0_CHILD_CONFIG", &config)
        .env("DOCKET_STAGE0_CHILD_ISSUANCE", &issuance.issuance)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "child stdout={} stderr={}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let inspection = governed_loop::inspect(&database, &issuance.issuance).unwrap();
    let record = inspection.record.unwrap();
    assert_eq!(record.status, GovernedRecordStatusV1::Indeterminate);
    assert!(record.settlement.is_none());
    // Current Docket carries the signed V2 dispatch. This experimental inner
    // transport is not enrolled for that envelope and must refuse before any
    // guest effect. Do not restore an obsolete production V1 dispatch path.
    assert!(!root.path().join("guest-state/result.cell").exists());
}

#[test]
fn docket_transport_refusal_child() {
    if std::env::var("DOCKET_STAGE0_DOCKET_CHILD").as_deref() != Ok("1") {
        return;
    }
    let path = |name: &str| PathBuf::from(std::env::var(name).unwrap());
    let database = path("DOCKET_STAGE0_CHILD_DATABASE");
    let envelope = std::fs::read(path("DOCKET_STAGE0_CHILD_ENVELOPE")).unwrap();
    let trust = std::fs::read(path("DOCKET_STAGE0_CHILD_TRUST")).unwrap();
    let resolver = path("DOCKET_STAGE0_CHILD_RESOLVER");
    let proxy = path("DOCKET_STAGE0_CHILD_PROXY");
    let config = path("DOCKET_STAGE0_CHILD_CONFIG");
    let issuance = std::env::var("DOCKET_STAGE0_CHILD_ISSUANCE").unwrap();
    let custody =
        governed_loop::accept(&database, &envelope, &trust, &resolver, &proxy, &config).unwrap();
    let inspection = governed_loop::inspect(&database, &issuance).unwrap();
    assert_eq!(
        inspection.record.unwrap().status,
        GovernedRecordStatusV1::Indeterminate
    );
    assert!(custody.attempt.starts_with("sha256:"));
}

fn b64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (chunk.get(1).copied().map_or(0, u32::from) << 8)
            | chunk.get(2).copied().map_or(0, u32::from);
        output.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((value >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(value & 0x3f) as usize] as char);
        }
    }
    output
}

#[test]
fn protocol_identity_and_binary_names_are_fixed() {
    assert_eq!(GUEST_PROTOCOL_V1, "docket.experimental.host-guest-pipe/v1");
    assert_eq!(SIMULATOR_BINARY_NAME, "docket-stage0-simulated-guest");
    assert_eq!(
        STAGE0_WORK_SCHEMA_V1,
        "docket.experimental.fixed-result-cell-work/v1"
    );
}
