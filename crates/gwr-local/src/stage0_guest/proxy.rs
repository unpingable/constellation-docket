//! Host proxy and simulated-guest process endpoints for Stage 0.

use super::protocol::{
    parse_hello, read_frame, require_eof, transcript_digest, validate_hello,
    validate_operation_response, write_frame, GuestOutcomeV1, GuestRequestV1, GuestResponseV1,
    OperationV1, WorkBindingV1, GUEST_PROTOCOL_V1, MAX_FRAME_BYTES, STAGE0_WORK_SCHEMA_V1,
};
use super::state::{self, FaultCutV1};
use gwr_runtime::governed_loop::{
    require_digest, ExecutorDispatchWireV1, ExecutorOutcomeClassWireV1, ExecutorOutcomeWireV1,
    MAX_EXECUTOR_DOCUMENT_BYTES,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

pub const CONFIG_SCHEMA_V1: &str = "docket.experimental.host-simulated-guest-config/v1";
pub const SIMULATOR_BINARY_NAME: &str = "docket-stage0-simulated-guest";
const MAX_BUILD_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfigV1 {
    pub schema: String,
    pub state_directory: String,
    pub subject: String,
    pub scope: String,
}

#[derive(Clone, Debug)]
pub struct ProxyContextV1 {
    pub config: ProxyConfigV1,
    pub proxy_build: String,
    pub simulator_build: String,
    pub simulator_program: PathBuf,
    pub plan: String,
}

pub fn run_proxy(arguments: &[String]) -> Result<(), String> {
    match arguments {
        [operation, config] if operation == "plan-id" => {
            let context = load_context(Path::new(config))?;
            println!("{}", context.plan);
            Ok(())
        }
        [operation, config] if operation == "execute" || operation == "reconcile" => {
            let context = load_context(Path::new(config))?;
            let dispatch: ExecutorDispatchWireV1 = read_outer_dispatch()?;
            let operation = if operation == "execute" {
                OperationV1::Execute
            } else {
                OperationV1::Reconcile
            };
            let outcome = execute_through_proxy(&context, operation, &dispatch)?;
            write_outer_outcome(&outcome)
        }
        _ => Err("stage0-proxy-usage: plan-id|execute|reconcile CONFIG".to_owned()),
    }
}

pub fn run_simulator(arguments: &[String]) -> Result<(), String> {
    let [state_directory] = arguments else {
        return Err("stage0-simulator-usage: STATE_DIRECTORY".to_owned());
    };
    let build = measure_executable(
        &std::env::current_exe()
            .map_err(|error| format!("stage0-simulator-current-exe:{error}"))?,
    )?;
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();

    let hello: GuestRequestV1 = read_frame(&mut input)?;
    let session = parse_hello(hello)?;
    write_frame(&mut output, &GuestResponseV1::hello(session.clone(), build))?;

    let request: GuestRequestV1 = read_frame(&mut input)?;
    let (operation, actual_session, sequence, binding) = request.operation_parts()?;
    if actual_session != session || sequence != 2 {
        return Err("stage0-request-stale-or-out-of-order".to_owned());
    }
    let result = match operation {
        OperationV1::Execute => state::execute(
            Path::new(state_directory),
            &binding,
            FaultCutV1::from_environment()?,
        ),
        OperationV1::Reconcile => state::reconcile(Path::new(state_directory), &binding),
    }?;
    write_frame(
        &mut output,
        &GuestResponseV1::operation(operation, session, &binding, result.outcome, result.receipt),
    )
}

pub fn is_injected_process_death(error: &str) -> bool {
    error.starts_with("stage0-injected-process-death:")
}

pub fn load_context(config_path: &Path) -> Result<ProxyContextV1, String> {
    let config_bytes = read_bounded_file(config_path, MAX_EXECUTOR_DOCUMENT_BYTES as u64)?;
    let config: ProxyConfigV1 = serde_json::from_slice(&config_bytes)
        .map_err(|error| format!("stage0-config-json:{error}"))?;
    validate_config(&config)?;

    let proxy_program =
        std::env::current_exe().map_err(|error| format!("stage0-proxy-current-exe:{error}"))?;
    let simulator_program = proxy_program
        .parent()
        .ok_or_else(|| "stage0-proxy-executable-parent".to_owned())?
        .join(SIMULATOR_BINARY_NAME);
    let proxy_build = measure_executable(&proxy_program)?;
    let simulator_build = measure_executable(&simulator_program)?;
    let frame_bound = (MAX_FRAME_BYTES as u64).to_be_bytes();
    let plan = transcript_digest(
        "host-simulated-guest-plan/v1",
        &[
            GUEST_PROTOCOL_V1.as_bytes(),
            STAGE0_WORK_SCHEMA_V1.as_bytes(),
            config.schema.as_bytes(),
            config.state_directory.as_bytes(),
            config.subject.as_bytes(),
            config.scope.as_bytes(),
            proxy_build.as_bytes(),
            simulator_build.as_bytes(),
            &frame_bound,
            b"fixed-result-cell/v1",
        ],
    );
    Ok(ProxyContextV1 {
        config,
        proxy_build,
        simulator_build,
        simulator_program,
        plan,
    })
}

pub fn execute_through_proxy(
    context: &ProxyContextV1,
    operation: OperationV1,
    dispatch: &ExecutorDispatchWireV1,
) -> Result<ExecutorOutcomeWireV1, String> {
    let binding = WorkBindingV1::from(dispatch);
    binding.validate()?;
    if binding.work != context.plan
        || binding.subject != context.config.subject
        || binding.scope != context.config.scope
    {
        return Err("stage0-dispatch-plan-binding-refusal".to_owned());
    }

    let (guest_outcome, guest_receipt) = invoke_guest(context, operation, &binding)?;
    let outcome_name: &[u8] = match guest_outcome {
        GuestOutcomeV1::Success => b"success",
        GuestOutcomeV1::Failure => b"failure",
        GuestOutcomeV1::Indeterminate => b"indeterminate",
    };
    let receipt = transcript_digest(
        "host-proxy-mechanics-receipt/v1",
        &[
            context.plan.as_bytes(),
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
    Ok(ExecutorOutcomeWireV1 {
        attempt: binding.attempt,
        marker: binding.marker,
        receipt,
        outcome: match guest_outcome {
            GuestOutcomeV1::Success => ExecutorOutcomeClassWireV1::Success,
            GuestOutcomeV1::Failure => ExecutorOutcomeClassWireV1::Failure,
            GuestOutcomeV1::Indeterminate => ExecutorOutcomeClassWireV1::Indeterminate,
        },
    })
}

fn invoke_guest(
    context: &ProxyContextV1,
    operation: OperationV1,
    binding: &WorkBindingV1,
) -> Result<(GuestOutcomeV1, String), String> {
    if measure_executable(&context.simulator_program)? != context.simulator_build {
        return Err("stage0-simulator-build-substitution".to_owned());
    }
    let session = fresh_session()?;
    let mut child = Command::new(&context.simulator_program)
        .arg(&context.config.state_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("stage0-simulator-spawn:{error}"))?;
    let mut child_input = child
        .stdin
        .take()
        .ok_or_else(|| "stage0-simulator-stdin".to_owned())?;
    let mut child_output = child
        .stdout
        .take()
        .ok_or_else(|| "stage0-simulator-stdout".to_owned())?;
    let child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| "stage0-simulator-stderr".to_owned())?;
    let stderr_reader = std::thread::spawn(move || read_bounded(child_stderr, 2048));

    let exchange = (|| {
        write_frame(&mut child_input, &GuestRequestV1::hello(session.clone()))?;
        let hello: GuestResponseV1 = read_frame(&mut child_output)?;
        validate_hello(&hello, &session, &context.simulator_build)?;
        write_frame(
            &mut child_input,
            &GuestRequestV1::operation(operation, session.clone(), binding),
        )?;
        let response: GuestResponseV1 = read_frame(&mut child_output)?;
        validate_operation_response(response, operation, &session, binding)
    })();
    drop(child_input);
    let eof = require_eof(&mut child_output);
    let status = child
        .wait()
        .map_err(|error| format!("stage0-simulator-wait:{error}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "stage0-simulator-stderr-reader-panicked".to_owned())??;
    if !status.success() {
        return Err(format!(
            "stage0-simulator-refused:{}",
            String::from_utf8_lossy(&stderr)
                .chars()
                .take(512)
                .collect::<String>()
        ));
    }
    let result = exchange?;
    eof?;
    Ok(result)
}

fn fresh_session() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "stage0-session-random".to_owned())?;
    Ok(transcript_digest("pipe-session/v1", &[&bytes]))
}

pub fn measure_executable(path: &Path) -> Result<String, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("stage0-build-metadata:{}:{error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_BUILD_BYTES
    {
        return Err("stage0-build-not-bounded-regular-nonsymlink".to_owned());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("stage0-build-open:{}:{error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("stage0-build-opened-metadata:{error}"))?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
    {
        return Err("stage0-build-file-raced".to_owned());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("stage0-build-read:{error}"))?;
    if bytes.len() as u64 != metadata.len() {
        return Err("stage0-build-file-raced".to_owned());
    }
    Ok(transcript_digest("executable-build-bytes/v1", &[&bytes]))
}

fn validate_config(config: &ProxyConfigV1) -> Result<(), String> {
    if config.schema != CONFIG_SCHEMA_V1 {
        return Err("stage0-config-schema".to_owned());
    }
    require_digest(&config.subject, "stage0 config subject")?;
    require_digest(&config.scope, "stage0 config scope")?;
    let path = Path::new(&config.state_directory);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        || config.state_directory.len() > 4096
    {
        return Err("stage0-config-state-directory".to_owned());
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("stage0-config-state-metadata:{error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err("stage0-config-state-not-private-directory".to_owned());
    }
    Ok(())
}

fn read_outer_dispatch() -> Result<ExecutorDispatchWireV1, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_EXECUTOR_DOCUMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("stage0-outer-stdin:{error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_EXECUTOR_DOCUMENT_BYTES {
        return Err("stage0-outer-dispatch-size".to_owned());
    }
    decode_outer_dispatch(&bytes)
}

fn write_outer_outcome(outcome: &ExecutorOutcomeWireV1) -> Result<(), String> {
    std::io::stdout()
        .write_all(&encode_outer_outcome(outcome)?)
        .map_err(|error| format!("stage0-outer-stdout:{error}"))
}

pub fn decode_outer_dispatch(bytes: &[u8]) -> Result<ExecutorDispatchWireV1, String> {
    let dispatch: ExecutorDispatchWireV1 = serde_json::from_slice(bytes)
        .map_err(|error| format!("stage0-outer-dispatch-json:{error}"))?;
    for (value, label) in [
        (&dispatch.attempt, "stage0 outer attempt"),
        (&dispatch.marker, "stage0 outer marker"),
        (&dispatch.work, "stage0 outer work"),
        (&dispatch.subject, "stage0 outer subject"),
        (&dispatch.scope, "stage0 outer scope"),
    ] {
        require_digest(value, label)?;
    }
    if dispatch.work_schema.is_empty()
        || dispatch.work_schema.len() > 128
        || !dispatch.work_schema.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
    {
        return Err("stage0-outer-work-schema".to_owned());
    }
    Ok(dispatch)
}

pub fn decode_outer_outcome(bytes: &[u8]) -> Result<ExecutorOutcomeWireV1, String> {
    let outcome: ExecutorOutcomeWireV1 = serde_json::from_slice(bytes)
        .map_err(|error| format!("stage0-outer-outcome-json:{error}"))?;
    for (value, label) in [
        (&outcome.attempt, "stage0 outer outcome attempt"),
        (&outcome.marker, "stage0 outer outcome marker"),
        (&outcome.receipt, "stage0 outer outcome receipt"),
    ] {
        require_digest(value, label)?;
    }
    Ok(outcome)
}

pub fn encode_outer_outcome(outcome: &ExecutorOutcomeWireV1) -> Result<Vec<u8>, String> {
    for (value, label) in [
        (&outcome.attempt, "stage0 outer outcome attempt"),
        (&outcome.marker, "stage0 outer outcome marker"),
        (&outcome.receipt, "stage0 outer outcome receipt"),
    ] {
        require_digest(value, label)?;
    }
    let class = match outcome.outcome {
        ExecutorOutcomeClassWireV1::Success => "success",
        ExecutorOutcomeClassWireV1::Failure => "failure",
        ExecutorOutcomeClassWireV1::Indeterminate => "indeterminate",
    };
    let value = serde_json::json!({
        "attempt": outcome.attempt,
        "marker": outcome.marker,
        "outcome": class,
        "receipt": outcome.receipt,
    });
    let mut bytes =
        serde_json::to_vec(&value).map_err(|error| format!("stage0-outer-outcome-json:{error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("stage0-config-metadata:{error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err("stage0-config-not-bounded-regular-nonsymlink".to_owned());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("stage0-config-open:{error}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("stage0-config-read:{error}"))?;
    Ok(bytes)
}

fn read_bounded<R: Read>(mut reader: R, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("stage0-bounded-read:{error}"))?;
    if bytes.len() > limit {
        return Err("stage0-bounded-read-overflow".to_owned());
    }
    Ok(bytes)
}
