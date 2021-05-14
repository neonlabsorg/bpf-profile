//! bpf-profile generator tests module.

mod mock;

use crate::gen::{profile, trace};
use std::io::Cursor;

#[test]
fn header_missing() {
    let reader = Cursor::new(b"Lorem ipsum dolor sit amet");
    let r = trace::contains_standard_header_(reader);
    assert!(r.is_ok());
    assert!(!r.unwrap());
}

#[test]
fn header_ok() {
    let reader = Cursor::new(mock::GOOD_INPUT);
    let r = trace::contains_standard_header_(reader);
    assert!(r.is_ok());
    assert!(r.unwrap());
}

#[test]
fn generate() {
    let reader = Cursor::new(mock::GOOD_INPUT);
    let prof = profile::Profile::new("trace".into());
    assert!(prof.is_ok());

    let mut prof = prof.unwrap();
    let r = profile::parse_trace_file(reader, &mut prof);
    assert!(r.is_ok());

    let mut output = Vec::<u8>::new();
    let r = prof.write_callgrind(&mut output);
    assert!(r.is_ok());
    assert_eq!(output.len(), 206);
    //dbg!(std::str::from_utf8(&output).unwrap());
    // Functions may go in random order, so check each separately
    assert!(output.starts_with(mock::CALLGRIND_HEADER));
    assert!(find_subsequence(&output, mock::CALLGRIND_MAIN).is_some());
    assert!(find_subsequence(&output, mock::CALLGRIND_MAIN_FUNC1).is_some());
    assert!(find_subsequence(&output, mock::CALLGRIND_MAIN_FUNC2).is_some());
    assert!(find_subsequence(&output, mock::CALLGRIND_FUNC1).is_some());
    assert!(find_subsequence(&output, mock::CALLGRIND_FUNC2).is_some());
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
