//! Fixed-profile QEMU microvm transport for the experimental Stage-1B guest.

pub mod build;
pub mod device;

use crate::stage0_guest::protocol::{
    read_frame, transcript_digest, validate_hello, validate_operation_response, write_frame,
    GuestOutcomeV1, GuestRequestV1, GuestResponseV1, OperationV1, WorkBindingV1, GUEST_PROTOCOL_V1,
    MAX_FRAME_BYTES, STAGE0_WORK_SCHEMA_V1,
};
use crate::stage0_guest::proxy::{decode_outer_dispatch, encode_outer_outcome, measure_executable};
use crate::stage1b_vm::device::{inspect, BLOCK_BYTES, DEVICE_BYTES, DEVICE_FORMAT};
use gwr_runtime::governed_loop::{
    require_digest, ExecutorDispatchWireV1, ExecutorOutcomeClassWireV1, ExecutorOutcomeWireV1,
    MAX_EXECUTOR_DOCUMENT_BYTES,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const CONFIG_SCHEMA_V1: &str = "docket.experimental.vm-guest-persistent-config/v1";
pub const MACHINE: &str = "microvm";
pub const MACHINE_OPTIONS: &str =
    "microvm,pic=off,pit=off,rtc=off,acpi=off,pcie=off,usb=off,isa-serial=on,auto-kernel-cmdline=off";
pub const ACCELERATOR: &str = "tcg";
pub const CPU: &str = "qemu64";
pub const MEMORY_MIB: u64 = 16;
pub const VCPUS: u64 = 1;
pub const TRANSPORT: &str = "isa-serial-unix-stream";
pub const BOOT_READY: u8 = 0xa5;
pub const QUALIFICATION_CUT_READY: u8 = 0x5a;
pub const BLOCK_DEVICE: &str = "virtio-blk-device/legacy-mmio/v1";
pub const BLOCK_QUEUE_SIZE: u64 = 8;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmConfigV1 {
    pub schema: String,
    pub qemu_program: String,
    pub guest_image: String,
    pub guest_build: String,
    pub data_device: String,
    pub data_device_id: String,
    pub data_device_bytes: u64,
    pub block_bytes: u64,
    pub block_device: String,
    pub machine: String,
    pub accelerator: String,
    pub cpu: String,
    pub memory_mib: u64,
    pub vcpus: u64,
    pub transport: String,
    pub subject: String,
    pub scope: String,
}

#[derive(Clone, Debug)]
pub struct VmContextV1 {
    pub config: VmConfigV1,
    pub qemu_program: PathBuf,
    pub guest_image: PathBuf,
    pub data_device: PathBuf,
    pub data_backing: String,
    pub proxy_build: String,
    pub qemu_build: String,
    pub qemu_version: String,
    pub image_build: String,
    pub plan: String,
}

pub fn run_proxy(arguments: &[String]) -> Result<(), String> {
    match arguments {
        [operation, config] if operation == "plan-id" => {
            println!("{}", load_context(Path::new(config))?.plan);
            Ok(())
        }
        [operation, config] if operation == "execute" || operation == "reconcile" => {
            let context = load_context(Path::new(config))?;
            let dispatch = read_outer_dispatch()?;
            let operation = if operation == "execute" {
                OperationV1::Execute
            } else {
                OperationV1::Reconcile
            };
            let outcome = execute_through_proxy(&context, operation, &dispatch)?;
            std::io::stdout()
                .write_all(&encode_outer_outcome(&outcome)?)
                .map_err(|error| format!("stage1b-outer-stdout:{error}"))
        }
        _ => Err("stage1b-proxy-usage: plan-id|execute|reconcile CONFIG".to_owned()),
    }
}

pub fn load_context(config_path: &Path) -> Result<VmContextV1, String> {
    let bytes = read_bounded_file(config_path, MAX_EXECUTOR_DOCUMENT_BYTES as u64)?;
    let config: VmConfigV1 =
        serde_json::from_slice(&bytes).map_err(|error| format!("stage1b-config-json:{error}"))?;
    validate_config(&config)?;
    let qemu_program = PathBuf::from(&config.qemu_program);
    let guest_image = PathBuf::from(&config.guest_image);
    let data_device = PathBuf::from(&config.data_device);
    let proxy_program =
        std::env::current_exe().map_err(|error| format!("stage1b-proxy-current-exe:{error}"))?;
    let proxy_build = measure_executable(&proxy_program)?;
    let qemu_build = measure_executable(&qemu_program)?;
    let image_build = measure_executable(&guest_image)?;
    let device = inspect(&data_device)?;
    if device.id != config.data_device_id {
        return Err("stage1b-device-id-substitution".to_owned());
    }
    let qemu_version = qemu_version(&qemu_program)?;
    let frame_bound = (MAX_FRAME_BYTES as u64).to_be_bytes();
    let memory = MEMORY_MIB.to_be_bytes();
    let vcpus = VCPUS.to_be_bytes();
    let plan = transcript_digest(
        "vm-guest-stage1b-plan/v1",
        &[
            GUEST_PROTOCOL_V1.as_bytes(),
            STAGE0_WORK_SCHEMA_V1.as_bytes(),
            config.schema.as_bytes(),
            config.subject.as_bytes(),
            config.scope.as_bytes(),
            proxy_build.as_bytes(),
            image_build.as_bytes(),
            config.guest_build.as_bytes(),
            config.data_device_id.as_bytes(),
            device.backing.as_bytes(),
            qemu_build.as_bytes(),
            qemu_version.as_bytes(),
            MACHINE_OPTIONS.as_bytes(),
            ACCELERATOR.as_bytes(),
            CPU.as_bytes(),
            &memory,
            &vcpus,
            TRANSPORT.as_bytes(),
            b"transport-ready-byte/a5",
            b"qualification-cut-ready-byte/5a",
            BLOCK_DEVICE.as_bytes(),
            &BLOCK_QUEUE_SIZE.to_be_bytes(),
            &BLOCK_BYTES.to_be_bytes(),
            &DEVICE_BYTES.to_be_bytes(),
            DEVICE_FORMAT.as_bytes(),
            &frame_bound,
            b"persistent-raw-fixed-result-cell/v1",
        ],
    );
    Ok(VmContextV1 {
        config,
        qemu_program,
        guest_image,
        data_device,
        data_backing: device.backing,
        proxy_build,
        qemu_build,
        qemu_version,
        image_build,
        plan,
    })
}

pub fn execute_through_proxy(
    context: &VmContextV1,
    operation: OperationV1,
    dispatch: &ExecutorDispatchWireV1,
) -> Result<ExecutorOutcomeWireV1, String> {
    let binding = WorkBindingV1::from(dispatch);
    binding.validate()?;
    if binding.work != context.plan
        || binding.subject != context.config.subject
        || binding.scope != context.config.scope
    {
        return Err("stage1b-dispatch-plan-binding-refusal".to_owned());
    }
    let (guest_outcome, guest_receipt) = invoke_vm(context, operation, &binding)?;
    let outcome_name: &[u8] = match guest_outcome {
        GuestOutcomeV1::Success => b"success",
        GuestOutcomeV1::Failure => b"failure",
        GuestOutcomeV1::Indeterminate => b"indeterminate",
    };
    let receipt = transcript_digest(
        "vm-host-proxy-mechanics-receipt/v1",
        &[
            context.plan.as_bytes(),
            context.image_build.as_bytes(),
            context.qemu_build.as_bytes(),
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

fn invoke_vm(
    context: &VmContextV1,
    operation: OperationV1,
    binding: &WorkBindingV1,
) -> Result<(GuestOutcomeV1, String), String> {
    let mut vm = VmProcessV1::spawn(context, DEFAULT_TIMEOUT)?;
    let session = fresh_session()?;
    let result = (|| {
        vm.handshake(&session, &context.config.guest_build)?;
        vm.operation(operation, &session, binding)
    })();
    vm.terminate();
    result
}

pub struct VmProcessV1 {
    child: Child,
    input: UnixStream,
    responses: Receiver<Result<GuestResponseV1, String>>,
    qualification_cuts: Receiver<()>,
    reader: Option<JoinHandle<()>>,
    stderr: Option<ChildStderr>,
    transport_directory: PathBuf,
    timeout: Duration,
    terminated: bool,
}

impl VmProcessV1 {
    pub fn spawn(context: &VmContextV1, timeout: Duration) -> Result<Self, String> {
        if measure_executable(&context.qemu_program)? != context.qemu_build {
            return Err("stage1b-qemu-build-substitution".to_owned());
        }
        if measure_executable(&context.guest_image)? != context.image_build {
            return Err("stage1b-image-build-substitution".to_owned());
        }
        let device = inspect(&context.data_device)?;
        if device.id != context.config.data_device_id || device.backing != context.data_backing {
            return Err("stage1b-device-backing-substitution".to_owned());
        }
        let transport_directory = new_transport_directory()?;
        let socket = transport_directory.join("s");
        let child = Command::new(&context.qemu_program)
            .args(launch_arguments(
                &context.guest_image,
                &context.data_device,
                &socket,
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(error) => {
                let _ = std::fs::remove_dir(&transport_directory);
                return Err(format!("stage1b-qemu-spawn:{error}"));
            }
        };
        let input = match connect_transport(&mut child, &socket, timeout)
            .and_then(|stream| await_boot_ready(stream, timeout))
        {
            Ok(stream) => stream,
            Err(error) => {
                terminate_child(&mut child);
                let _ = std::fs::remove_file(&socket);
                let _ = std::fs::remove_dir(&transport_directory);
                return Err(error);
            }
        };
        let mut output = match input.try_clone() {
            Ok(output) => output,
            Err(error) => {
                terminate_child(&mut child);
                let _ = std::fs::remove_file(&socket);
                let _ = std::fs::remove_dir(&transport_directory);
                return Err(format!("stage1b-transport-clone:{error}"));
            }
        };
        let stderr = child.stderr.take();
        let (sender, responses) = mpsc::channel();
        let (cut_sender, qualification_cuts) = mpsc::channel();
        let reader = std::thread::spawn(move || loop {
            let mut first = [0_u8; 1];
            let response = match output.read_exact(&mut first) {
                Ok(()) if first[0] == QUALIFICATION_CUT_READY => {
                    if cut_sender.send(()).is_err() {
                        break;
                    }
                    continue;
                }
                Ok(()) => read_frame(&mut Cursor::new(first).chain(&mut output)),
                Err(error) => Err(format!("stage1b-frame-prefix:{error}")),
            };
            let terminal = response.is_err();
            if sender.send(response).is_err() || terminal {
                break;
            }
        });
        Ok(Self {
            child,
            input,
            responses,
            qualification_cuts,
            reader: Some(reader),
            stderr,
            transport_directory,
            timeout,
            terminated: false,
        })
    }

    pub fn handshake(&mut self, session: &str, guest_build: &str) -> Result<(), String> {
        write_frame(&mut self.input, &GuestRequestV1::hello(session.to_owned()))?;
        let response = self.read_response()?;
        validate_hello(&response, session, guest_build)
    }

    pub fn send_operation(
        &mut self,
        operation: OperationV1,
        session: &str,
        binding: &WorkBindingV1,
    ) -> Result<(), String> {
        write_frame(
            &mut self.input,
            &GuestRequestV1::operation(operation, session.to_owned(), binding),
        )
    }

    pub fn read_operation(
        &mut self,
        operation: OperationV1,
        session: &str,
        binding: &WorkBindingV1,
    ) -> Result<(GuestOutcomeV1, String), String> {
        let response = self.read_response()?;
        validate_operation_response(response, operation, session, binding)
    }

    pub fn operation(
        &mut self,
        operation: OperationV1,
        session: &str,
        binding: &WorkBindingV1,
    ) -> Result<(GuestOutcomeV1, String), String> {
        self.send_operation(operation, session, binding)?;
        self.read_operation(operation, session, binding)
    }

    pub fn write_raw_frame(&mut self, body: &[u8]) -> Result<(), String> {
        let length = u32::try_from(body.len()).map_err(|_| "stage1b-raw-frame-size".to_owned())?;
        self.input
            .write_all(&length.to_be_bytes())
            .and_then(|()| self.input.write_all(body))
            .and_then(|()| self.input.flush())
            .map_err(|error| format!("stage1b-raw-frame-write:{error}"))
    }

    pub fn write_raw_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.input
            .write_all(bytes)
            .and_then(|()| self.input.flush())
            .map_err(|error| format!("stage1b-raw-write:{error}"))
    }

    pub fn read_response(&mut self) -> Result<GuestResponseV1, String> {
        self.responses
            .recv_timeout(self.timeout)
            .map_err(|error| format!("stage1b-qemu-read-timeout:{error}"))?
    }

    pub fn await_qualification_cut(&mut self) -> Result<(), String> {
        self.qualification_cuts
            .recv_timeout(self.timeout)
            .map_err(|error| format!("stage1b-qualification-cut-timeout:{error}"))
    }

    pub fn terminate(&mut self) {
        if self.terminated {
            return;
        }
        self.terminated = true;
        terminate_child(&mut self.child);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let _ = std::fs::remove_file(self.transport_directory.join("s"));
        let _ = std::fs::remove_dir(&self.transport_directory);
    }

    pub fn stderr(&mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        if let Some(mut stderr) = self.stderr.take() {
            let _ = stderr.by_ref().take(4097).read_to_end(&mut bytes);
        }
        bytes.truncate(4096);
        bytes
    }
}

impl Drop for VmProcessV1 {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn new_transport_directory() -> Result<PathBuf, String> {
    let mut random = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "stage1b-transport-random".to_owned())?;
    let identity = transcript_digest(
        "stage1b-transport-directory/v1",
        &[&std::process::id().to_be_bytes(), &random],
    );
    let directory = PathBuf::from(format!(
        "/tmp/ds1b-{}-{}",
        std::process::id(),
        &identity[7..23]
    ));
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&directory)
        .map_err(|error| format!("stage1b-transport-directory:{error}"))?;
    Ok(directory)
}

fn connect_transport(
    child: &mut Child,
    socket: &Path,
    timeout: Duration,
) -> Result<UnixStream, String> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "stage1b-transport-timeout-overflow".to_owned())?;
    loop {
        match UnixStream::connect(socket) {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() >= deadline => {
                return Err(format!("stage1b-transport-connect-timeout:{error}"));
            }
            Err(_) => {}
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("stage1b-qemu-wait:{error}"))?
        {
            return Err(format!("stage1b-qemu-before-transport:{status}"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn await_boot_ready(mut stream: UnixStream, timeout: Duration) -> Result<UnixStream, String> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("stage1b-transport-ready-timeout:{error}"))?;
    let mut ready = [0_u8; 1];
    stream
        .read_exact(&mut ready)
        .map_err(|error| format!("stage1b-transport-ready-read:{error}"))?;
    if ready != [BOOT_READY] {
        return Err("stage1b-transport-ready-substitution".to_owned());
    }
    stream
        .set_read_timeout(None)
        .map_err(|error| format!("stage1b-transport-ready-reset:{error}"))?;
    Ok(stream)
}

fn terminate_child(child: &mut Child) {
    let group = format!("-{}", child.id());
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &group])
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

fn launch_arguments(image: &Path, data_device: &Path, socket: &Path) -> Vec<String> {
    vec![
        "-machine".to_owned(),
        MACHINE_OPTIONS.to_owned(),
        "-accel".to_owned(),
        ACCELERATOR.to_owned(),
        "-cpu".to_owned(),
        CPU.to_owned(),
        "-smp".to_owned(),
        VCPUS.to_string(),
        "-m".to_owned(),
        format!("{MEMORY_MIB}M"),
        "-nodefaults".to_owned(),
        "-no-reboot".to_owned(),
        "-display".to_owned(),
        "none".to_owned(),
        "-monitor".to_owned(),
        "none".to_owned(),
        "-chardev".to_owned(),
        format!(
            "socket,id=stage1b,path={},server=on,wait=on",
            socket.display()
        ),
        "-serial".to_owned(),
        "chardev:stage1b".to_owned(),
        "-drive".to_owned(),
        format!(
            "id=journal,file={},format=raw,if=none,cache=directsync,aio=threads",
            data_device.display()
        ),
        "-device".to_owned(),
        "virtio-blk-device,drive=journal,queue-size=8,num-queues=1,indirect_desc=off,event_idx=off,request-merging=off,discard=off,write-zeroes=off,scsi=off,config-wce=on,logical_block_size=512,physical_block_size=512".to_owned(),
        "-kernel".to_owned(),
        image.display().to_string(),
    ]
}

fn validate_config(config: &VmConfigV1) -> Result<(), String> {
    if config.schema != CONFIG_SCHEMA_V1
        || config.machine != MACHINE
        || config.accelerator != ACCELERATOR
        || config.cpu != CPU
        || config.memory_mib != MEMORY_MIB
        || config.vcpus != VCPUS
        || config.transport != TRANSPORT
        || config.data_device_bytes != DEVICE_BYTES
        || config.block_bytes != BLOCK_BYTES
        || config.block_device != BLOCK_DEVICE
    {
        return Err("stage1b-config-outside-qualified-profile".to_owned());
    }
    for (value, label) in [
        (&config.guest_build, "stage1b guest build"),
        (&config.data_device_id, "stage1b data device id"),
        (&config.subject, "stage1b subject"),
        (&config.scope, "stage1b scope"),
    ] {
        require_digest(value, label)?;
    }
    for path in [
        &config.qemu_program,
        &config.guest_image,
        &config.data_device,
    ] {
        let path = Path::new(path);
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || path.as_os_str().len() > 4096
        {
            return Err("stage1b-config-path".to_owned());
        }
    }
    Ok(())
}

fn qemu_version(program: &Path) -> Result<String, String> {
    let output = Command::new(program)
        .arg("--version")
        .output()
        .map_err(|error| format!("stage1b-qemu-version-spawn:{error}"))?;
    if !output.status.success() || output.stdout.is_empty() || output.stdout.len() > 4096 {
        return Err("stage1b-qemu-version-refusal".to_owned());
    }
    String::from_utf8(output.stdout).map_err(|_| "stage1b-qemu-version-utf8".to_owned())
}

fn fresh_session() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "stage1b-session-random".to_owned())?;
    Ok(transcript_digest("vm-serial-session/v1", &[&bytes]))
}

fn read_outer_dispatch() -> Result<ExecutorDispatchWireV1, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_EXECUTOR_DOCUMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("stage1b-outer-stdin:{error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_EXECUTOR_DOCUMENT_BYTES {
        return Err("stage1b-outer-dispatch-size".to_owned());
    }
    decode_outer_dispatch(&bytes)
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("stage1b-config-metadata:{error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err("stage1b-config-not-bounded-regular-nonsymlink".to_owned());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("stage1b-config-open:{error}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("stage1b-config-read:{error}"))?;
    Ok(bytes)
}
