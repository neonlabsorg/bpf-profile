//! bpf-profile generator tests module.

mod mock;

use crate::gen::{dump, trace};
use std::fs;
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
fn generate_integral() {
    let dump = dump::Resolver::default();
    let reader = Cursor::new(mock::SIMPLE_INPUT);
    let prof = trace::Profile::new(dump, None);
    assert!(prof.is_ok());

    let mut prof = prof.unwrap();
    let r = trace::parse(reader, &mut prof);
    assert!(r.is_ok());

    let mut output = Vec::<u8>::new();
    let r = prof.write_callgrind(&mut output, "<none>");
    assert!(r.is_ok());

    //==== do not delete ====================================
    //println!("{}", std::str::from_utf8(&output).unwrap());
    //=======================================================

    assert_eq!(output.len(), 301);
    assert_eq!(output, mock::SIMPLE_CALLGRIND_INTEGRAL);
}

#[test]
fn generate_line_by_line() {
    let dump = dump::Resolver::default();
    let reader = Cursor::new(mock::SIMPLE_INPUT);
    let asm_name = "/tmp/generate_line_by_line.asm".to_owned();
    let asm = Path::new(&asm_name);
    let prof = trace::Profile::new(dump, Some(&asm));
    assert!(prof.is_ok());

    let mut prof = prof.unwrap();
    let r = trace::parse(reader, &mut prof);
    assert!(r.is_ok());

    let mut output = Vec::<u8>::new();
    let r = prof.write_callgrind(&mut output, &asm_name);
    assert!(r.is_ok());

    //==== do not delete ====================================
    //println!("{}", std::str::from_utf8(&output).unwrap());
    //=======================================================

    assert_eq!(output.len(), 488);
    assert_eq!(output, mock::SIMPLE_CALLGRIND_LINE_BY_LINE);

    let asm = fs::read_to_string(&asm).unwrap();

    //==== do not delete ====================================
    println!("{}", asm);
    //=======================================================

    assert_eq!(asm.len(), 347);
    assert_eq!(asm, mock::SIMPLE_GENERATED_ASM);
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
