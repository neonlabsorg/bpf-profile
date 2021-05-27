//! bpf-profile tests module.

use std::io::Cursor;

#[test]
fn header_missing() {
    let reader = Cursor::new(b"Lorem ipsum dolor sit amet");
    let r = crate::trace::contains_standard_header(reader);
    assert!(r.is_ok());
    assert!(!r.unwrap());
}

#[test]
fn header_ok() {
    let reader = Cursor::new(b"[Z TRACE bpf] BPF Program Instruction Trace:");
    let r = crate::trace::contains_standard_header(reader);
    assert!(r.is_ok());
    assert!(r.unwrap());
}
