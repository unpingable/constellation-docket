//! Narrow persistent-session wrapper around the qualified Stage-1B VM executor.

use crate::stage0_guest::protocol::{
    transcript_digest, GuestOutcomeV1, OperationV1, WorkBindingV1, STAGE0_WORK_SCHEMA_V1,
};
use crate::stage0_guest::proxy::{decode_outer_dispatch, encode_outer_outcome, measure_executable};
use crate::stage1b_vm::{load_context, VmContextV1, VmProcessV1, DEFAULT_TIMEOUT};
use gwr_runtime::governed_loop::{
    require_digest, ExecutorDispatchWireV1, ExecutorOutcomeClassWireV1, ExecutorOutcomeWireV1,
    MAX_EXECUTOR_DOCUMENT_BYTES,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path};
use std::time::Duration;

pub const CONFIG_SCHEMA_V1: &str = "docket.experimental.vm-guest-session-config/v1";
pub const SESSION_PROTOCOL_V1: &str = "docket.experimental.vm-guest-session-wire/v1";
pub const BINDING_SCHEMA_V1: &str = "docket.experimental.vm-guest-session-binding/v1";
pub const QUALIFIED_ATTEMPT_BOUND: u64 = 8;
const MAX_SESSION_FRAME_BYTES: usize = MAX_EXECUTOR_DOCUMENT_BYTES + 4096;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfigV1 {
    pub schema: String,
    pub vm_config: String,
    pub session_socket: String,
    pub session_binding: String,
    pub max_attempts: u64,
}

#[derive(Clone, Debug)]
pub struct SessionContextV1 {
    pub config: SessionConfigV1,
    pub vm: VmContextV1,
    pub proxy_build: String,
    pub plan: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingV1 {
    pub schema: String,
    pub session: String,
    pub plan: String,
    pub proxy_build: String,
    pub server_pid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SessionOperationV1 {
    PlanId,
    Execute,
    Reconcile,
    Close,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionRequestV1 {
    schema: String,
    operation: SessionOperationV1,
    nonce: String,
    expected_session: String,
    client_build: String,
    dispatch: Option<ExecutorDispatchWireV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionResponseV1 {
    schema: String,
    operation: SessionOperationV1,
    nonce: String,
    session: String,
    plan: String,
    outcome: Option<ExecutorOutcomeWireV1>,
    refusal: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeenAttemptV1 {
    binding: WorkBindingV1,
}

pub fn run(arguments: &[String]) -> Result<(), String> {
    match arguments {
        [operation, config] if operation == "plan-id" => {
            println!(
                "{}",
                client_request(Path::new(config), SessionOperationV1::PlanId, None)?.plan
            );
            Ok(())
        }
        [operation, config] if operation == "execute" || operation == "reconcile" => {
            let dispatch = read_outer_dispatch()?;
            let operation = if operation == "execute" {
                SessionOperationV1::Execute
            } else {
                SessionOperationV1::Reconcile
            };
            let response = client_request(Path::new(config), operation, Some(dispatch))?;
            if let Some(refusal) = response.refusal {
                return Err(refusal);
            }
            let outcome = response
                .outcome
                .ok_or_else(|| "stage1d-session-outcome-missing".to_owned())?;
            std::io::stdout()
                .write_all(&encode_outer_outcome(&outcome)?)
                .map_err(|error| format!("stage1d-outer-stdout:{error}"))
        }
        [operation, config] if operation == "close" => {
            let response = client_request(Path::new(config), SessionOperationV1::Close, None)?;
            if let Some(refusal) = response.refusal {
                return Err(refusal);
            }
            Ok(())
        }
        [operation, config] if operation == "serve" => serve(Path::new(config), None),
        [operation, config, marker] if operation == "serve-qualification-cut" => {
            serve(Path::new(config), Some(Path::new(marker)))
        }
        _ => Err(
            "stage1d-usage: plan-id|execute|reconcile|close|serve CONFIG; serve-qualification-cut CONFIG MARKER"
                .to_owned(),
        ),
    }
}

pub fn load_session_context(config_path: &Path) -> Result<SessionContextV1, String> {
    let config = read_config(config_path)?;
    let vm = load_context(Path::new(&config.vm_config))?;
    let proxy_build = measure_executable(
        &std::env::current_exe().map_err(|error| format!("stage1d-current-exe:{error}"))?,
    )?;
    if proxy_build != vm.proxy_build {
        return Err("stage1d-proxy-measurement-ambiguity".to_owned());
    }
    let plan = transcript_digest(
        "vm-guest-stage1d-session-plan/v1",
        &[
            SESSION_PROTOCOL_V1.as_bytes(),
            STAGE0_WORK_SCHEMA_V1.as_bytes(),
            vm.plan.as_bytes(),
            proxy_build.as_bytes(),
            config.session_socket.as_bytes(),
            config.session_binding.as_bytes(),
            &config.max_attempts.to_be_bytes(),
            b"created/measured/running/closed",
            b"runtime-session-is-transport-only",
        ],
    );
    Ok(SessionContextV1 {
        config,
        vm,
        proxy_build,
        plan,
    })
}

pub fn read_runtime_binding(config_path: &Path) -> Result<RuntimeBindingV1, String> {
    let config = read_config(config_path)?;
    let bytes = read_bounded_regular(Path::new(&config.session_binding), 4096)?;
    decode_exact_json(&bytes, "stage1d-binding-json")
}

fn serve(config_path: &Path, qualification_marker: Option<&Path>) -> Result<(), String> {
    let context = load_session_context(config_path)?;
    let socket_path = Path::new(&context.config.session_socket);
    let binding_path = Path::new(&context.config.session_binding);
    require_absent(socket_path, "stage1d-session-socket-exists")?;
    require_absent(binding_path, "stage1d-session-binding-exists")?;
    let listener = UnixListener::bind(socket_path)
        .map_err(|error| format!("stage1d-session-listen:{error}"))?;
    let mut vm = match VmProcessV1::spawn(&context.vm, DEFAULT_TIMEOUT) {
        Ok(vm) => vm,
        Err(error) => {
            let _ = std::fs::remove_file(socket_path);
            return Err(error);
        }
    };
    let session = fresh_digest("vm-guest-stage1d-runtime-session/v1", &context.plan)?;
    let binding = RuntimeBindingV1 {
        schema: BINDING_SCHEMA_V1.to_owned(),
        session: session.clone(),
        plan: context.plan.clone(),
        proxy_build: context.proxy_build.clone(),
        server_pid: std::process::id(),
    };
    if let Err(error) = create_binding(binding_path, &binding) {
        vm.terminate();
        let _ = std::fs::remove_file(socket_path);
        return Err(error);
    }
    let result = serve_loop(&listener, &context, &session, &mut vm, qualification_marker);
    vm.terminate();
    remove_exact_binding(binding_path, &binding);
    let _ = std::fs::remove_file(socket_path);
    result
}

fn serve_loop(
    listener: &UnixListener,
    context: &SessionContextV1,
    session: &str,
    vm: &mut VmProcessV1,
    qualification_marker: Option<&Path>,
) -> Result<(), String> {
    let mut attempts: BTreeMap<String, SeenAttemptV1> = BTreeMap::new();
    let mut markers: BTreeMap<String, String> = BTreeMap::new();
    for accepted in listener.incoming() {
        let mut stream = accepted.map_err(|error| format!("stage1d-session-accept:{error}"))?;
        stream
            .set_read_timeout(Some(DEFAULT_TIMEOUT))
            .map_err(|error| format!("stage1d-session-read-timeout:{error}"))?;
        stream
            .set_write_timeout(Some(DEFAULT_TIMEOUT))
            .map_err(|error| format!("stage1d-session-write-timeout:{error}"))?;
        let request: SessionRequestV1 = read_frame(&mut stream)?;
        let response = handle_request(
            context,
            session,
            vm,
            &mut attempts,
            &mut markers,
            request,
            qualification_marker,
        )?;
        let terminal = response.operation == SessionOperationV1::Close
            || response.outcome.as_ref().is_some_and(|outcome| {
                outcome.outcome == ExecutorOutcomeClassWireV1::Indeterminate
            });
        write_frame(&mut stream, &response)?;
        if terminal {
            return Ok(());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_request(
    context: &SessionContextV1,
    session: &str,
    vm: &mut VmProcessV1,
    attempts: &mut BTreeMap<String, SeenAttemptV1>,
    markers: &mut BTreeMap<String, String>,
    request: SessionRequestV1,
    qualification_marker: Option<&Path>,
) -> Result<SessionResponseV1, String> {
    require_digest(&request.nonce, "stage1d request nonce")?;
    require_digest(&request.expected_session, "stage1d expected session")?;
    require_digest(&request.client_build, "stage1d client build")?;
    if request.schema != SESSION_PROTOCOL_V1
        || request.expected_session != session
        || request.client_build != context.proxy_build
    {
        return Ok(refusal_response(
            session,
            &context.plan,
            &request,
            "stage1d-session-identity-refusal",
        ));
    }
    if matches!(
        request.operation,
        SessionOperationV1::PlanId | SessionOperationV1::Close
    ) {
        if request.dispatch.is_some() {
            return Ok(refusal_response(
                session,
                &context.plan,
                &request,
                "stage1d-plan-id-dispatch-refusal",
            ));
        }
        return Ok(success_response(session, &context.plan, &request, None));
    }
    let dispatch = match request.dispatch.as_ref() {
        Some(dispatch) => dispatch,
        None => {
            return Ok(refusal_response(
                session,
                &context.plan,
                &request,
                "stage1d-operation-dispatch-missing",
            ));
        }
    };
    let binding = WorkBindingV1::from(dispatch);
    if let Err(error) = binding.validate() {
        return Ok(refusal_response(session, &context.plan, &request, &error));
    }
    if binding.work != context.plan
        || binding.subject != context.vm.config.subject
        || binding.scope != context.vm.config.scope
    {
        return Ok(refusal_response(
            session,
            &context.plan,
            &request,
            "stage1d-dispatch-plan-binding-refusal",
        ));
    }
    if let Some(seen) = attempts.get(&binding.attempt) {
        if seen.binding != binding {
            return Ok(refusal_response(
                session,
                &context.plan,
                &request,
                "stage1d-conflicting-attempt-refusal",
            ));
        }
    } else {
        if attempts.len() as u64 >= context.config.max_attempts {
            return Ok(refusal_response(
                session,
                &context.plan,
                &request,
                "stage1d-session-capacity-refusal",
            ));
        }
        if markers.contains_key(&binding.marker) {
            return Ok(refusal_response(
                session,
                &context.plan,
                &request,
                "stage1d-cross-attempt-marker-refusal",
            ));
        }
        markers.insert(binding.marker.clone(), binding.attempt.clone());
        attempts.insert(
            binding.attempt.clone(),
            SeenAttemptV1 {
                binding: binding.clone(),
            },
        );
    }
    let operation = match request.operation {
        SessionOperationV1::Execute => OperationV1::Execute,
        SessionOperationV1::Reconcile => OperationV1::Reconcile,
        SessionOperationV1::PlanId | SessionOperationV1::Close => unreachable!("handled above"),
    };
    let guest_session = fresh_digest("vm-guest-stage1d-guest-exchange/v1", session)?;
    vm.handshake(&guest_session, &context.vm.config.guest_build)?;
    vm.send_operation(operation, &guest_session, &binding)?;
    if let Some(marker) = qualification_marker {
        vm.await_qualification_cut()?;
        create_cut_marker(marker, session, &binding.attempt)?;
        loop {
            std::thread::sleep(Duration::from_secs(30));
        }
    }
    let (guest_outcome, guest_receipt) = vm.read_operation(operation, &guest_session, &binding)?;
    let outcome = make_outcome(context, binding, guest_outcome, &guest_receipt);
    Ok(success_response(
        session,
        &context.plan,
        &request,
        Some(outcome),
    ))
}

fn make_outcome(
    context: &SessionContextV1,
    binding: WorkBindingV1,
    guest_outcome: GuestOutcomeV1,
    guest_receipt: &str,
) -> ExecutorOutcomeWireV1 {
    let outcome_name: &[u8] = match guest_outcome {
        GuestOutcomeV1::Success => b"success",
        GuestOutcomeV1::Failure => b"failure",
        GuestOutcomeV1::Indeterminate => b"indeterminate",
    };
    let receipt = transcript_digest(
        "vm-persistent-session-mechanics-receipt/v1",
        &[
            context.plan.as_bytes(),
            context.vm.image_build.as_bytes(),
            context.vm.qemu_build.as_bytes(),
            binding.attempt.as_bytes(),
            binding.marker.as_bytes(),
            binding.work_schema.as_bytes(),
            binding.work.as_bytes(),
            binding.subject.as_bytes(),
            binding.scope.as_bytes(),
            outcome_name,
            guest_receipt.as_bytes(),
        ],
    );
    ExecutorOutcomeWireV1 {
        attempt: binding.attempt,
        marker: binding.marker,
        receipt,
        outcome: match guest_outcome {
            GuestOutcomeV1::Success => ExecutorOutcomeClassWireV1::Success,
            GuestOutcomeV1::Failure => ExecutorOutcomeClassWireV1::Failure,
            GuestOutcomeV1::Indeterminate => ExecutorOutcomeClassWireV1::Indeterminate,
        },
    }
}

fn client_request(
    config_path: &Path,
    operation: SessionOperationV1,
    dispatch: Option<ExecutorDispatchWireV1>,
) -> Result<SessionResponseV1, String> {
    let config = read_config(config_path)?;
    let binding_bytes = read_bounded_regular(Path::new(&config.session_binding), 4096)?;
    let binding: RuntimeBindingV1 = decode_exact_json(&binding_bytes, "stage1d-binding-json")?;
    if binding.schema != BINDING_SCHEMA_V1 {
        return Err("stage1d-binding-schema-refusal".to_owned());
    }
    for (digest, label) in [
        (&binding.session, "stage1d binding session"),
        (&binding.plan, "stage1d binding plan"),
        (&binding.proxy_build, "stage1d binding proxy build"),
    ] {
        require_digest(digest, label)?;
    }
    let client_build = measure_executable(
        &std::env::current_exe().map_err(|error| format!("stage1d-current-exe:{error}"))?,
    )?;
    if client_build != binding.proxy_build {
        return Err("stage1d-client-build-substitution".to_owned());
    }
    let request = SessionRequestV1 {
        schema: SESSION_PROTOCOL_V1.to_owned(),
        operation,
        nonce: fresh_digest("vm-guest-stage1d-client-nonce/v1", &binding.session)?,
        expected_session: binding.session.clone(),
        client_build,
        dispatch,
    };
    let mut stream = UnixStream::connect(Path::new(&config.session_socket))
        .map_err(|error| format!("stage1d-session-connect:{error}"))?;
    stream
        .set_read_timeout(Some(DEFAULT_TIMEOUT))
        .map_err(|error| format!("stage1d-client-read-timeout:{error}"))?;
    stream
        .set_write_timeout(Some(DEFAULT_TIMEOUT))
        .map_err(|error| format!("stage1d-client-write-timeout:{error}"))?;
    write_frame(&mut stream, &request)?;
    let response: SessionResponseV1 = read_frame(&mut stream)?;
    let payload_valid = match request.operation {
        SessionOperationV1::PlanId | SessionOperationV1::Close => {
            response.outcome.is_none() && response.refusal.is_none()
        }
        SessionOperationV1::Execute | SessionOperationV1::Reconcile => {
            response.outcome.is_some() != response.refusal.is_some()
        }
    };
    if response.schema != SESSION_PROTOCOL_V1
        || response.operation != request.operation
        || response.nonce != request.nonce
        || response.session != binding.session
        || response.plan != binding.plan
        || !payload_valid
    {
        return Err("stage1d-session-response-substitution".to_owned());
    }
    Ok(response)
}

fn success_response(
    session: &str,
    plan: &str,
    request: &SessionRequestV1,
    outcome: Option<ExecutorOutcomeWireV1>,
) -> SessionResponseV1 {
    SessionResponseV1 {
        schema: SESSION_PROTOCOL_V1.to_owned(),
        operation: request.operation,
        nonce: request.nonce.clone(),
        session: session.to_owned(),
        plan: plan.to_owned(),
        outcome,
        refusal: None,
    }
}

fn refusal_response(
    session: &str,
    plan: &str,
    request: &SessionRequestV1,
    refusal: &str,
) -> SessionResponseV1 {
    SessionResponseV1 {
        schema: SESSION_PROTOCOL_V1.to_owned(),
        operation: request.operation,
        nonce: request.nonce.clone(),
        session: session.to_owned(),
        plan: plan.to_owned(),
        outcome: None,
        refusal: Some(refusal.to_owned()),
    }
}

fn read_config(path: &Path) -> Result<SessionConfigV1, String> {
    let bytes = read_bounded_regular(path, MAX_EXECUTOR_DOCUMENT_BYTES as u64)?;
    let config: SessionConfigV1 =
        serde_json::from_slice(&bytes).map_err(|error| format!("stage1d-config-json:{error}"))?;
    if config.schema != CONFIG_SCHEMA_V1 || config.max_attempts != QUALIFIED_ATTEMPT_BOUND {
        return Err("stage1d-config-outside-qualified-profile".to_owned());
    }
    for value in [
        &config.vm_config,
        &config.session_socket,
        &config.session_binding,
    ] {
        validate_absolute_path(value)?;
    }
    if config.session_socket == config.session_binding {
        return Err("stage1d-config-path-alias".to_owned());
    }
    validate_private_parent(Path::new(&config.session_socket))?;
    validate_private_parent(Path::new(&config.session_binding))?;
    Ok(config)
}

fn validate_absolute_path(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if !path.is_absolute()
        || value.len() > 4096
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("stage1d-config-path".to_owned());
    }
    Ok(())
}

fn validate_private_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "stage1d-config-path-parent".to_owned())?;
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| format!("stage1d-config-parent-metadata:{error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err("stage1d-config-parent-not-private".to_owned());
    }
    Ok(())
}

fn require_absent(path: &Path, error: &str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(error.to_owned()),
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(cause) => Err(format!("{error}:{cause}")),
    }
}

fn create_binding(path: &Path, binding: &RuntimeBindingV1) -> Result<(), String> {
    let bytes = encode_exact_json(binding, "stage1d-binding-json")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("stage1d-binding-create:{error}"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("stage1d-binding-write:{error}"))
}

fn remove_exact_binding(path: &Path, expected: &RuntimeBindingV1) {
    let matches = read_bounded_regular(path, 4096)
        .and_then(|bytes| decode_exact_json::<RuntimeBindingV1>(&bytes, "stage1d-binding-json"))
        .is_ok_and(|binding| binding == *expected);
    if matches {
        let _ = std::fs::remove_file(path);
    }
}

fn create_cut_marker(path: &Path, session: &str, attempt: &str) -> Result<(), String> {
    validate_absolute_path(path.to_string_lossy().as_ref())?;
    validate_private_parent(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("stage1d-cut-marker-create:{error}"))?;
    file.write_all(format!("{session}\n{attempt}\n").as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("stage1d-cut-marker-write:{error}"))
}

fn fresh_digest(domain: &str, context: &str) -> Result<String, String> {
    let mut random = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "stage1d-random".to_owned())?;
    Ok(transcript_digest(
        domain,
        &[
            context.as_bytes(),
            &std::process::id().to_be_bytes(),
            &random,
        ],
    ))
}

fn read_outer_dispatch() -> Result<ExecutorDispatchWireV1, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_EXECUTOR_DOCUMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("stage1d-outer-stdin:{error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_EXECUTOR_DOCUMENT_BYTES {
        return Err("stage1d-outer-dispatch-size".to_owned());
    }
    decode_outer_dispatch(&bytes)
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), String> {
    let bytes = encode_exact_json(value, "stage1d-frame-json")?;
    if bytes.is_empty() || bytes.len() > MAX_SESSION_FRAME_BYTES {
        return Err("stage1d-frame-size".to_owned());
    }
    let length = u32::try_from(bytes.len()).map_err(|_| "stage1d-frame-size".to_owned())?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(&bytes))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("stage1d-frame-write:{error}"))
}

fn read_frame<T: DeserializeOwned + Serialize>(stream: &mut UnixStream) -> Result<T, String> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|error| format!("stage1d-frame-prefix:{error}"))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_SESSION_FRAME_BYTES {
        return Err("stage1d-frame-size".to_owned());
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| format!("stage1d-frame-read:{error}"))?;
    decode_exact_json(&bytes, "stage1d-frame-json")
}

fn encode_exact_json<T: Serialize>(value: &T, label: &str) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| format!("{label}:{error}"))
}

fn decode_exact_json<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    label: &str,
) -> Result<T, String> {
    let value: T = serde_json::from_slice(bytes).map_err(|error| format!("{label}:{error}"))?;
    if encode_exact_json(&value, label)? != bytes {
        return Err(format!("{label}-noncanonical"));
    }
    Ok(value)
}

fn read_bounded_regular(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("stage1d-file-metadata:{error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err("stage1d-file-not-bounded-regular-nonsymlink".to_owned());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("stage1d-file-open:{error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("stage1d-file-opened-metadata:{error}"))?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
    {
        return Err("stage1d-file-raced".to_owned());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("stage1d-file-read:{error}"))?;
    if bytes.len() as u64 != metadata.len() {
        return Err("stage1d-file-raced".to_owned());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_identity_is_distinct_from_stable_plan() {
        let plan = transcript_digest("test-plan/v1", &[b"fixed"]);
        let one = fresh_digest("test-session/v1", &plan).expect("session one");
        let two = fresh_digest("test-session/v1", &plan).expect("session two");
        assert_ne!(one, two);
    }

    #[test]
    fn wire_rejects_noncanonical_bytes() {
        let binding = RuntimeBindingV1 {
            schema: BINDING_SCHEMA_V1.to_owned(),
            session: transcript_digest("s", &[b"1"]),
            plan: transcript_digest("p", &[b"1"]),
            proxy_build: transcript_digest("b", &[b"1"]),
            server_pid: 1,
        };
        let mut bytes = encode_exact_json(&binding, "test").expect("encode");
        bytes.push(b'\n');
        assert!(decode_exact_json::<RuntimeBindingV1>(&bytes, "test").is_err());
    }
}
