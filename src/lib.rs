//! bpf-profile library.

#![deny(warnings)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod bpf;
pub mod calls;
pub mod error;
pub mod gen;
pub mod global;
pub mod resolver;
pub mod trace;

mod filebuf;

#[cfg(test)]
mod tests;

type Cost = u64;
type Index = usize;
type Address = usize;
type ProgramCounter = usize;

#[cfg(not(test))]
type Map<K, V> = std::collections::HashMap<K, V>;

// Use less performant BTree in tests for deterministic sequences
#[cfg(test)]
type Map<K, V> = std::collections::BTreeMap<K, V>;

const GROUND_ZERO: Address = Address::MAX;
const PADDING: &str = "        ";
const DEFAULT_ASM: &str = "<none>";
