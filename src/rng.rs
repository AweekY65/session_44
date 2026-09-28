//! Randomness sourcing.
//!
//! Production randomness comes exclusively from the kernel CSPRNG via
//! `/dev/urandom` on Unix and `BCryptGenRandom` on Windows. It never comes
//! from a network service. The [`Rng`] trait also allows deterministic,
//! reproducible randomness in tests.

use std::io::Read;

/// Fills a byte buffer with random bytes. Implementations MUST error rather
/// than return weak or short randomness.
pub trait Rng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), RngError>;
}

/// Kernel CSPRNG-backed randomness.
#[derive(Debug, Default)]
pub struct OsRng;

impl OsRng {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(unix)]
impl Rng for OsRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        let mut f = std::fs::File::open("/dev/urandom")
            .map_err(|e| RngError(format!("cannot open /dev/urandom: {e}")))?;
        // read_exact retries on EINTR/short reads and errors on EOF; a
        // correctly configured Unix system never hits EOF here.
        f.read_exact(dest)
            .map_err(|e| RngError(format!("failed reading /dev/urandom: {e}")))?;
        Ok(())
    }
}

#[cfg(windows)]
impl Rng for OsRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        // BCryptGenRandom from bcrypt.dll, system-preferred CSPRNG.
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                h_algorithm: isize,
                buffer: *mut u8,
                length: usize,
                flags: u32,
            ) -> i32;
        }
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;
        let status = unsafe {
            BCryptGenRandom(
                0,
                dest.as_mut_ptr(),
                dest.len(),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(RngError(format!("BCryptGenRandom failed: NTSTATUS 0x{status:08x}")))
        }
    }
}

#[cfg(not(any(unix, windows)))]
impl Rng for OsRng {
    fn fill(&mut self, _dest: &mut [u8]) -> Result<(), RngError> {
        Err(RngError("no secure OS RNG available on this platform".into()))
    }
}

/// Deterministic RNG used only by tests: expands a seed via SHA-256 in
/// counter mode so a single short seed yields arbitrary-length streams.
#[cfg(test)]
pub(crate) struct DeterministicRng {
    seed: Vec<u8>,
    counter: u64,
    block: [u8; 32],
    pos: usize,
}

#[cfg(test)]
impl DeterministicRng {
    pub(crate) fn new(seed: &[u8]) -> Self {
        let mut s = Self {
            seed: seed.to_vec(),
            counter: 0,
            block: [0u8; 32],
            pos: 32,
        };
        s.refill();
        s
    }

    fn refill(&mut self) {
        let mut h = crate::sha256::Sha256::new();
        h.update(b"local-sss deterministic test rng v1\0");
        h.update(&self.seed);
        h.update(&self.counter.to_be_bytes());
        self.block = h.finish();
        self.counter += 1;
        self.pos = 0;
    }
}

#[cfg(test)]
impl Rng for DeterministicRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        for b in dest.iter_mut() {
            if self.pos >= 32 {
                self.refill();
            }
            *b = self.block[self.pos];
            self.pos += 1;
        }
        Ok(())
    }
}

/// Error returned when secure randomness cannot be obtained.
#[derive(Debug)]
pub struct RngError(pub String);

impl std::fmt::Display for RngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RngError {}
