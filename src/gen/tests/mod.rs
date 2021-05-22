//! bpf-profile generator tests module.

mod mock;

use crate::gen::{dump, trace};
use std::io::Cursor;
use std::path::Path;

#[test]
fn header_missing() {
    let reader = Cursor::new(b"Lorem ipsum dolor sit amet");
    let r = trace::contains_standard_header(reader);
    assert!(r.is_ok());
    assert!(!r.unwrap());
}

#[test]
fn header_ok() {
    let reader = Cursor::new(mock::SIMPLE_INPUT);
    let r = trace::contains_standard_header(reader);
    assert!(r.is_ok());
    assert!(r.unwrap());
}

#[test]
fn generate() {
    let dump = dump::Resolver::default();
    let reader = Cursor::new(mock::SIMPLE_INPUT);
    let prof = trace::Profile::new(dump);
    assert!(prof.is_ok());

    let mut prof = prof.unwrap();
    let r = trace::parse(reader, &mut prof);
    assert!(r.is_ok());

    let mut output = Vec::<u8>::new();
    let r = prof.write_callgrind(&mut output, Path::new("trace.asm"));
    assert!(r.is_ok());
    //dbg!(std::str::from_utf8(&output).unwrap());

    assert_eq!(output.len(), 249);
    assert_eq!(output, mock::SIMPLE_CALLGRIND);
}

#[test]
fn subsequence() {
    let r = find_subsequence(b"lorem ipsum dolor sit amet", b"dolor");
    assert!(r.is_some());
    assert_eq!(r.unwrap(), 12);
    let r = find_subsequence(b"lorem ipsum dolor sit amet", b"Terminator");
    assert!(r.is_none());
}

/// Searches (ineffectively) a subslice in another slice.
fn find_subsequence<T>(haystack: &[T], needle: &[T]) -> Option<usize>
where
    for<'a> &'a [T]: PartialEq,
{
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
