//! bpf_profile config module.

pub const FAILURE: i32 = 1;

pub const DEFAULT_CONFIG: &str = "bpf_profile.conf";

pub const FORMATS: &[&str] = &["callgrind"];
pub const DEFAULT_FORMAT: &str = "callgrind";
