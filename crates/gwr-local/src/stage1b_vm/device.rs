use crate::stage0_guest::protocol::transcript_digest;
use gwr_runtime::governed_loop::require_digest;
use ring::rand::{SecureRandom, SystemRandom};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

pub const DEVICE_BYTES: u64 = 1024 * 1024;
pub const BLOCK_BYTES: u64 = 512;
pub const DEVICE_FORMAT: &str = "docket.experimental.vm-guest-raw-journal/v1";
const MAGIC: &[u8; 16] = b"DOCKET-S1B-RAW1!";
const HEADER_BYTES: usize = BLOCK_BYTES as usize;
const ID_START: usize = 32;
const ID_END: usize = ID_START + 71;
const CHECKSUM_END: usize = ID_END + 71;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceIdentityV1 {
    pub id: String,
    pub backing: String,
}

pub fn provision(path: &Path) -> Result<DeviceIdentityV1, String> {
    validate_path(path)?;
    let mut random = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "stage1b-device-random".to_owned())?;
    let id = transcript_digest("stage1b-device-id/v1", &[&random]);
    let mut header = [0_u8; HEADER_BYTES];
    header[..16].copy_from_slice(MAGIC);
    header[16..20].copy_from_slice(&1_u32.to_be_bytes());
    header[20..24].copy_from_slice(&(BLOCK_BYTES as u32).to_be_bytes());
    header[24..32].copy_from_slice(&DEVICE_BYTES.to_be_bytes());
    header[ID_START..ID_END].copy_from_slice(id.as_bytes());
    let checksum = transcript_digest("stage1b-device-superblock/v1", &[&header[..ID_END]]);
    header[ID_END..CHECKSUM_END].copy_from_slice(checksum.as_bytes());

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("stage1b-device-create:{error}"))?;
    file.set_len(DEVICE_BYTES)
        .map_err(|error| format!("stage1b-device-size:{error}"))?;
    file.write_all(&header)
        .map_err(|error| format!("stage1b-device-header-write:{error}"))?;
    file.sync_all()
        .map_err(|error| format!("stage1b-device-sync:{error}"))?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("stage1b-device-parent-sync:{error}"))?;
    }
    inspect(path)
}

pub fn inspect(path: &Path) -> Result<DeviceIdentityV1, String> {
    validate_path(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("stage1b-device-open:{error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("stage1b-device-metadata:{error}"))?;
    if !before.file_type().is_file() || before.len() != DEVICE_BYTES {
        return Err("stage1b-device-object".to_owned());
    }
    let mut header = [0_u8; HEADER_BYTES];
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut header))
        .map_err(|error| format!("stage1b-device-header-read:{error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("stage1b-device-metadata:{error}"))?;
    if before.dev() != after.dev() || before.ino() != after.ino() || before.len() != after.len() {
        return Err("stage1b-device-raced".to_owned());
    }
    validate_header(&header)?;
    let id = std::str::from_utf8(&header[ID_START..ID_END])
        .map_err(|_| "stage1b-device-id-utf8".to_owned())?
        .to_owned();
    let backing = transcript_digest(
        "stage1b-device-backing/v1",
        &[
            path.as_os_str().as_encoded_bytes(),
            &before.dev().to_be_bytes(),
            &before.ino().to_be_bytes(),
            &before.len().to_be_bytes(),
            id.as_bytes(),
            DEVICE_FORMAT.as_bytes(),
        ],
    );
    Ok(DeviceIdentityV1 { id, backing })
}

fn validate_header(header: &[u8; HEADER_BYTES]) -> Result<(), String> {
    if &header[..16] != MAGIC
        || header[16..20] != 1_u32.to_be_bytes()
        || header[20..24] != (BLOCK_BYTES as u32).to_be_bytes()
        || header[24..32] != DEVICE_BYTES.to_be_bytes()
        || header[CHECKSUM_END..].iter().any(|byte| *byte != 0)
    {
        return Err("stage1b-device-superblock".to_owned());
    }
    let id = std::str::from_utf8(&header[ID_START..ID_END])
        .map_err(|_| "stage1b-device-id-utf8".to_owned())?;
    require_digest(id, "stage1b device id").map_err(|_| "stage1b-device-id".to_owned())?;
    let expected = transcript_digest("stage1b-device-superblock/v1", &[&header[..ID_END]]);
    if header[ID_END..CHECKSUM_END] != *expected.as_bytes() {
        return Err("stage1b-device-superblock-checksum".to_owned());
    }
    Ok(())
}

fn validate_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.as_os_str().len() > 4096
    {
        return Err("stage1b-device-path".to_owned());
    }
    Ok(())
}
