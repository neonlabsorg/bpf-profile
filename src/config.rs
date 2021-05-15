//! bpf-profile config module.

pub const FAILURE: i32 = 1;

pub const DEFAULT_CONFIG: &str = "bpf-profile.conf";

pub const FORMATS: &[&str] = &["callgrind"];
pub const DEFAULT_FORMAT: &str = "callgrind";

pub const GROUND_ZERO: Address = Address::MAX;

pub type Address = usize;
