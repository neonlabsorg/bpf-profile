//! bpf-profile generator mock module.

pub const CALLGRIND_HEADER: &[u8] = b"# callgrind format
version: 1
creator: bpf-profile
events: Instructions
totals: 25
fl=trace";

pub const CALLGRIND_MAIN: &[u8] = b"fn=main
0 6";

pub const CALLGRIND_MAIN_FUNC1: &[u8] = b"cfn=func1
calls=1 0
0 6";

pub const CALLGRIND_MAIN_FUNC2: &[u8] = b"cfn=func2
calls=3 0
0 8";

pub const CALLGRIND_FUNC1: &[u8] = b"fn=func1
0 3
cfn=func2
calls=2 0
0 3";

pub const CALLGRIND_FUNC2: &[u8] = b"fn=func2
0 11";

pub const GOOD_INPUT: &[u8] =
    b"[2021-05-12T07:48:07.945826240Z TRACE solana_bpf_loader_program] BPF Program Instruction Trace:
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: xxx
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: xxx
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call main
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: yyy
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call func1
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call func2
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call func2
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call func2
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call func2
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call func2
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: xxx
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: xxx
";
