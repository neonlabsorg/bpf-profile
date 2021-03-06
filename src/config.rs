//! bpf-profile config module.

pub const FAILURE: i32 = 1;

pub const DEFAULT_CONFIG: &str = "bpf-profile.conf";

pub const FORMATS: &[&str] = &["callgrind"];
pub const DEFAULT_FORMAT: &str = "callgrind";

pub const DEFAULT_ASM: &str = "<none>";

pub const PADDING: &str = "        ";

pub type Cost = usize;
pub type Index = usize;
pub type Address = usize;
pub type ProgramCounter = usize;

pub const GROUND_ZERO: Address = Address::MAX;

#[cfg(not(test))]
pub type Map<K, V> = std::collections::HashMap<K, V>;

// Use less performant BTree in tests for deterministic sequences
#[cfg(test)]
pub type Map<K, V> = std::collections::BTreeMap<K, V>;
