//! bpf-profile global module.

use lazy_static::lazy_static;
use std::sync::atomic::{AtomicBool, Ordering};

lazy_static! {
    static ref VERBOSE: AtomicBool = AtomicBool::default();
}

/// Enable or disable verbose logging.
pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

/// Get verbose logging status.
pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}
