//! bpf-profile generator mock module.

pub const SIMPLE_INPUT: &[u8] = b"[Z TRACE bpf] BPF Program Instruction Trace:
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: xxx
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: xxx
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call 1
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: yyy
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call 2
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call 3
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call 3
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call 3
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call 3
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: call 3
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: zzz
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: exit
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: xxx
0 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: xxx
";

pub const SIMPLE_CALLGRIND: &[u8] = b"# callgrind format
version: 1
creator: bpf-profile
events: Instructions
totals: 25
fl=trace

fn=function_0
0 6
cfn=function_1
calls=1 0
0 6
cfn=function_2
calls=3 0
0 8

fn=function_1
0 3
cfn=function_2
calls=2 0
0 3

fn=function_2
0 11
";
