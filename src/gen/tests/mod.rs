//! bpf-profile-generate tests module.

use std::fs;
use std::io::Cursor;
use std::path::Path;

use crate::{DEFAULT_ASM, gen::trace, resolver};

mod mock;

#[test]
fn generate_integral() {
    let resv = resolver::Resolver::default();
    let reader = Cursor::new(mock::SIMPLE_INPUT);
    let prof = trace::Profile::new(resv, None);
    assert!(prof.is_ok());

    let mut prof = prof.unwrap();
    let r = trace::parse(reader, &mut prof);
    assert!(r.is_ok());

    let mut output = Vec::<u8>::new();
    let r = prof.write_callgrind(&mut output, DEFAULT_ASM);
    assert!(r.is_ok());

    //==== do not delete ====================================
    //println!("{}", std::str::from_utf8(&output).unwrap());
    //=======================================================

    assert_eq!(output.len(), 317);
    assert_eq!(output, mock::SIMPLE_CALLGRIND_INTEGRAL);
}

#[test]
fn generate_line_by_line() {
    let resv = resolver::Resolver::default();
    let reader = Cursor::new(mock::SIMPLE_INPUT);
    let asm_name = "/tmp/generate_line_by_line.asm".to_owned();
    let asm = Path::new(&asm_name);
    let prof = trace::Profile::new(resv, Some(asm));
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

    assert_eq!(output.len(), 504);
    assert_eq!(output, mock::SIMPLE_CALLGRIND_LINE_BY_LINE);

    let asm = fs::read(asm).unwrap();
    let asm = std::str::from_utf8(&asm).unwrap();

    //==== do not delete ====================================
    //println!("{}", &asm);
    //=======================================================

    assert_eq!(asm.len(), 487);
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
