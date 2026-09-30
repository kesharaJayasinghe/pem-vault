//! Process and memory hardening. Best effort: failures print a warning and never abort, and
//! nothing here needs `unsafe` (the `rustix` and `region` APIs used are safe).

use std::ops::Deref;
use std::sync::Once;

use zeroize::{Zeroize, Zeroizing};

/// Stops the process from writing core dumps, so a crash can't leave decrypted keys,
/// passphrases or tokens on disk. Call first thing in `main`.
///
/// - Unix: `setrlimit(RLIMIT_CORE, 0)` for both the soft and hard limit.
/// - Linux: also `prctl(PR_SET_DUMPABLE, 0)`, which additionally blocks `ptrace` attach and
///   `/proc/<pid>/mem` reads by other processes running as the same user.
pub fn disable_core_dumps() {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        let zero = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        if let Err(e) = setrlimit(Resource::Core, zero) {
            eprintln!(
                "[!] Could not disable core dumps ({e}); a crash could write key material to disk"
            );
        }
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        if let Err(e) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
            eprintln!("[!] Could not mark the process non-dumpable ({e})");
        }
    }
}

/// A secret held in zeroizing memory that is also locked into RAM (`mlock`/`VirtualLock`)
/// while alive, so the OS never writes it to swap or a hibernation file.
///
/// Locking is best effort: if it fails (e.g. Linux's `RLIMIT_MEMLOCK`), a warning is printed
/// once per process and the secret is still usable and still zeroized.
///
/// On drop the secret is wiped **before** its pages are unlocked and freed.
pub struct Locked<T: Zeroize + AsRef<[u8]>> {
    secret: Zeroizing<T>,
    guard: Option<region::LockGuard>,
}

impl<T: Zeroize + AsRef<[u8]>> Locked<T> {
    pub fn new(secret: Zeroizing<T>) -> Self {
        let bytes: &[u8] = (*secret).as_ref();
        let guard = if bytes.is_empty() {
            None
        } else {
            match region::lock(bytes.as_ptr(), bytes.len()) {
                Ok(guard) => Some(guard),
                Err(e) => {
                    warn_lock_failed(&e);
                    None
                }
            }
        };
        Self { secret, guard }
    }

    #[cfg(test)]
    fn is_locked(&self) -> bool {
        self.guard.is_some()
    }
}

impl<T: Zeroize + AsRef<[u8]>> Deref for Locked<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.secret
    }
}

impl<T: Zeroize + AsRef<[u8]>> Drop for Locked<T> {
    fn drop(&mut self) {
        // Order matters: wipe, then unlock while the pages are still allocated (unlocking
        // freed memory can fail), then let the field drop free the (now empty) buffer.
        self.secret.zeroize();
        self.guard = None;
    }
}

fn warn_lock_failed(error: &region::Error) {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "[!] Could not lock key material in memory ({error}); it could be written to swap. \
             On Linux, raise the limit with `ulimit -l`."
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn core_dumps_are_disabled() {
        use rustix::process::{Resource, getrlimit};
        disable_core_dumps();
        let limit = getrlimit(Resource::Core);
        assert_eq!(limit.current, Some(0));
        assert_eq!(limit.maximum, Some(0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_is_not_dumpable() {
        use rustix::process::{DumpableBehavior, dumpable_behavior};
        disable_core_dumps();
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
    }

    #[test]
    fn locked_bytes_are_readable_and_locked() {
        let secret = Locked::new(Zeroizing::new(b"-----BEGIN KEY-----".to_vec()));
        assert_eq!(secret.as_slice(), b"-----BEGIN KEY-----");
        // macOS has no default memlock limit; on Linux a small buffer fits the 64 KiB default.
        assert!(secret.is_locked());
    }

    #[test]
    fn locked_string_derefs() {
        let secret = Locked::new(Zeroizing::new(String::from("correct horse battery staple")));
        assert_eq!(secret.as_str(), "correct horse battery staple");
    }

    #[test]
    fn empty_secret_is_not_locked() {
        assert!(!Locked::new(Zeroizing::new(Vec::<u8>::new())).is_locked());
    }

    #[test]
    fn large_buffers_drop_cleanly() {
        // Large allocations are separately mmap'd; dropping must unlock before freeing, or
        // region's debug assertion fires on the failed munlock.
        for _ in 0..3 {
            drop(Locked::new(Zeroizing::new(vec![0xA5u8; 2 * 1024 * 1024])));
        }
    }
}
