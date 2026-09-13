//! Local implementations of the small neutral ports: system clock, identity
//! generation, filesystem artifact storage, and provenance sidecar files.

use gwr_core::digest::Sha256Digest;
use gwr_core::ids::PreparationRunId;
use gwr_core::work_request::ClockReading;
use gwr_runtime::ports::adapters::{ArtifactStore, Clock, IdSource, ProvenanceSink};
use gwr_runtime::ports::labor_provider::ProvenanceEntry;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_ID_SOURCE_INSTANCE: AtomicU64 = AtomicU64::new(0);

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> ClockReading {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_millis() as u64;
        ClockReading(ms)
    }
}

/// A fixed clock for tests and injection.
pub struct FixedClock(pub ClockReading);

impl Clock for FixedClock {
    fn now(&self) -> ClockReading {
        self.0
    }
}

/// Identity bytes from a hash chain over a process-unique seed and a counter.
pub struct HashChainIds {
    seed: [u8; 32],
    counter: u64,
}

impl HashChainIds {
    pub fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let instance = NEXT_ID_SOURCE_INSTANCE.fetch_add(1, Ordering::Relaxed);
        let seed = gwr_core::digest::Transcript::new("gwr:id-seed:v2")
            .text_field("nanos", &nanos.to_string())
            .text_field("pid", &std::process::id().to_string())
            .text_field("instance", &instance.to_string())
            .finalize();
        Self {
            seed: *seed.as_bytes(),
            counter: 0,
        }
    }
}

impl Default for HashChainIds {
    fn default() -> Self {
        Self::new()
    }
}

impl IdSource for HashChainIds {
    fn fresh16(&mut self) -> [u8; 16] {
        self.counter += 1;
        let digest = gwr_core::digest::Transcript::new("gwr:id:v1")
            .field("seed", &self.seed)
            .text_field("counter", &self.counter.to_string())
            .finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest.as_bytes()[..16]);
        out
    }
}

/// Content-addressed filesystem artifact storage.
pub struct FsArtifactStore {
    root: PathBuf,
}

impl FsArtifactStore {
    pub fn new(root: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        Ok(Self { root })
    }
}

impl ArtifactStore for FsArtifactStore {
    fn put(&mut self, bytes: &[u8]) -> Result<(Sha256Digest, u64), String> {
        let digest = Sha256Digest::of_bytes(bytes);
        let path = self.root.join(digest.to_hex());
        if !path.exists() {
            std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
        }
        Ok((digest, bytes.len() as u64))
    }

    fn get(&mut self, digest: &Sha256Digest) -> Result<Vec<u8>, String> {
        let path = self.root.join(digest.to_hex());
        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        // Verify on read: content addressing is a promise, not a convention.
        if &Sha256Digest::of_bytes(&bytes) != digest {
            return Err(format!("artifact {digest} corrupt on disk"));
        }
        Ok(bytes)
    }
}

/// Provenance sidecar files: one plain-text log per preparation run, outside
/// the core store entirely.
pub struct FsProvenanceSink {
    root: PathBuf,
}

impl FsProvenanceSink {
    pub fn new(root: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        Ok(Self { root })
    }

    pub fn read(&self, run: PreparationRunId) -> Result<String, String> {
        std::fs::read_to_string(self.root.join(format!("{run}.log"))).map_err(|e| e.to_string())
    }
}

impl ProvenanceSink for FsProvenanceSink {
    fn record(&mut self, run: PreparationRunId, entries: &[ProvenanceEntry]) -> Result<(), String> {
        let path = self.root.join(format!("{run}.log"));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        for entry in entries {
            writeln!(
                file,
                "{}\t{}",
                entry.label,
                entry.content.replace('\n', "\\n")
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier};

    #[test]
    fn concurrent_id_sources_have_distinct_first_identities() {
        const THREADS: usize = 64;
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    HashChainIds::new().fresh16()
                })
            })
            .collect();
        let identities: HashSet<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(identities.len(), THREADS);
    }
}
