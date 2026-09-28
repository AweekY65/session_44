//! Cryptographically secure random bytes sourced exclusively from the
//! operating system's entropy facility. No network, no user-space PRNG
//! seeding files, no external services.

use std::fs::File;
use std::io::Read;

#[cfg(unix)]
pub fn fill(buf: &mut [u8]) -> Result<(), String> {
    // /dev/urandom is the CSPRNG output of the kernel; on Linux it is seeded
    // from the same entropy pool as getrandom(2) and never blocks once the
    // pool has been initialized, which is guaranteed by the time userspace
    // runs. Read in a loop in case of a short read or EINTR.
    let mut f = File::open("/dev/urandom")
        .map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
    let mut filled = 0;
    while filled < buf.len() {
        match f.read(&mut buf[filled..]) {
            Ok(0) => return Err("/dev/urandom returned unexpected EOF".into()),
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("reading /dev/urandom failed: {e}")),
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn fill(buf: &mut [u8]) -> Result<(), String> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            halgorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: usize,
            dw_flags: u32,
        ) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len(),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(format!("BCryptGenRandom failed with status 0x{status:08x}"))
    }
}

/// Convenience helper returning a fresh `len`-byte random buffer.
pub fn bytes(len: usize) -> Result<Vec<u8>, String> {
    let mut v = vec![0u8; len];
    fill(&mut v)?;
    Ok(v)
}
