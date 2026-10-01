//! Reproducible builder for the fixed freestanding Stage-1B guest image.

use crate::stage0_guest::protocol::transcript_digest;
use crate::stage0_guest::proxy::measure_executable;
use std::path::{Path, PathBuf};
use std::process::Command;

const GUEST_SOURCE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/stage1b-guest/guest.rs");
const LINKER_SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/stage1b-guest/guest.ld");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationFaultV1 {
    None,
    BeforeReservation,
    AfterReservation,
    AfterEffect,
    AfterCommit,
}

impl QualificationFaultV1 {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BeforeReservation => "before-reservation",
            Self::AfterReservation => "after-reservation",
            Self::AfterEffect => "after-effect",
            Self::AfterCommit => "after-commit",
        }
    }

    fn cfg(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::BeforeReservation => Some("stage1b_fault_before_reservation"),
            Self::AfterReservation => Some("stage1b_fault_after_reservation"),
            Self::AfterEffect => Some("stage1b_fault_after_effect"),
            Self::AfterCommit => Some("stage1b_fault_after_commit"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltGuestV1 {
    pub image: PathBuf,
    pub guest_build: String,
    pub image_build: String,
    pub rustc_identity: String,
    pub fault: QualificationFaultV1,
}

pub fn build_guest(output: &Path, fault: QualificationFaultV1) -> Result<BuiltGuestV1, String> {
    let source = std::fs::read(GUEST_SOURCE)
        .map_err(|error| format!("stage1b-guest-source-read:{error}"))?;
    let linker = std::fs::read(LINKER_SCRIPT)
        .map_err(|error| format!("stage1b-guest-linker-read:{error}"))?;
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let rustc_output = Command::new(&rustc)
        .args(["--version", "--verbose"])
        .output()
        .map_err(|error| format!("stage1b-rustc-version-spawn:{error}"))?;
    if !rustc_output.status.success() || rustc_output.stdout.len() > 4096 {
        return Err("stage1b-rustc-version-refusal".to_owned());
    }
    let rustc_identity = transcript_digest("stage1b-rustc-identity/v1", &[&rustc_output.stdout]);
    let guest_build = transcript_digest(
        "stage1b-guest-source-build/v1",
        &[
            &source,
            &linker,
            rustc_identity.as_bytes(),
            fault.name().as_bytes(),
            b"i686-unknown-linux-gnu",
            b"no_std;no_main;panic=abort;opt=s;static;kernel;overflow-checks;strip=symbols",
        ],
    );
    let parent = output
        .parent()
        .ok_or_else(|| "stage1b-guest-output-parent".to_owned())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("stage1b-guest-output-directory:{error}"))?;
    let mut command = Command::new(&rustc);
    command
        .arg(GUEST_SOURCE)
        .args([
            "--edition",
            "2021",
            "--target",
            "i686-unknown-linux-gnu",
            "--crate-type",
            "bin",
            "-C",
            "panic=abort",
            "-C",
            "opt-level=s",
            "-C",
            "relocation-model=static",
            "-C",
            "code-model=kernel",
            "-C",
            "overflow-checks=yes",
            "-C",
            "strip=symbols",
            "-C",
            "linker=ld",
            "-C",
            "default-linker-libraries=no",
            "-C",
        ])
        .arg(format!(
            "link-args=-m elf_i386 -T {LINKER_SCRIPT} --build-id=none -nostdlib"
        ))
        .args([
            "--check-cfg=cfg(stage1b_fault_before_reservation)",
            "--check-cfg=cfg(stage1b_fault_after_reservation)",
            "--check-cfg=cfg(stage1b_fault_after_effect)",
            "--check-cfg=cfg(stage1b_fault_after_commit)",
        ])
        .arg("-o")
        .arg(output)
        .env("DOCKET_STAGE1B_GUEST_BUILD", &guest_build);
    if let Some(cfg) = fault.cfg() {
        command.args(["--cfg", cfg]);
    }
    let built = command
        .output()
        .map_err(|error| format!("stage1b-rustc-spawn:{error}"))?;
    if !built.status.success() || !built.stderr.is_empty() {
        return Err(format!(
            "stage1b-rustc-refused:{}",
            String::from_utf8_lossy(&built.stderr)
                .chars()
                .take(4096)
                .collect::<String>()
        ));
    }
    validate_elf(output)?;
    let image_build = measure_executable(output)?;
    Ok(BuiltGuestV1 {
        image: output.to_path_buf(),
        guest_build,
        image_build,
        rustc_identity,
        fault,
    })
}

fn validate_elf(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| format!("stage1b-image-read:{error}"))?;
    if bytes.len() > 2 * 1024 * 1024
        || bytes.get(..7) != Some(b"\x7fELF\x01\x01\x01")
        || bytes.get(18..20) != Some(&[3, 0])
    {
        return Err("stage1b-image-not-bounded-elf32-i386".to_owned());
    }
    let header = 0x1badb002_u32.to_le_bytes();
    if !bytes[..bytes.len().min(8192)]
        .windows(header.len())
        .any(|window| window == header)
    {
        return Err("stage1b-image-missing-multiboot-header".to_owned());
    }
    Ok(())
}
