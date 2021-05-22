//! bpf-profile generator mock module.

pub const SIMPLE_INPUT: &[u8] = b"
# The input contains 3 functions with addresses 0x100, 0x200, and 0x300.
# Function 0x100 calls 0x200 once and 0x300 3 times.
# Function 0x200 calls 0x200 2 times.
[Z TRACE bpf] BPF Program Instruction Trace:
 1 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 0: ...
 2 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 1: ...
 3 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 2: call 0x100
 4 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 3: xxx
 5 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 4: call 0x200
 6 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 20: yyy
 7 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 21: call 0x300
 8 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 30: zzz
 9 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 31: exit
10 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 22: call 0x300
11 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 30: zzz
12 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 31: exit
13 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 23: exit
14 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 5: call 0x300
15 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 30: zzz
16 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 31: exit
17 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 6: call 0x300
18 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 30: zzz
19 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 31: zzz
20 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 32: exit
21 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 7: call 0x300
22 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 30: zzz
23 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 31: zzz
24 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 32: zzz
25 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 33: exit
26 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 8: exit
27 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 9: ...
28 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 10: ...
";

pub const SIMPLE_CALLGRIND: &[u8] = b"# callgrind format
version: 1
creator: bpf-profile
events: Instructions
totals: 28
fl=\"trace.asm\"

fn=function_0
3 6
cfn=function_1
calls=1 20
3 8
cfn=function_2
calls=3 30
3 9

fn=function_1
20 4
cfn=function_2
calls=2 30
20 4

fn=function_2
30 13
";
