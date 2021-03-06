//! bpf-profile-generate mock module.

pub const SIMPLE_INPUT: &[u8] = b"
# The input contains 3 functions with addresses 0x100, 0x200, and 0x300.
# Function 0x100 calls 0x200 once and 0x300 3 times.
# Function 0x200 calls 0x200 2 times.
[Z TRACE bpf] BPF Program Instruction Trace:
 1 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 1: aaa
 2 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 2: bbb
 3 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 3: call 0x100
 4 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 4: xxx
 5 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 5: call 0x200
 6 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 20: yyy
 7 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 21: call 0x300
 8 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 30: zzz
 9 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 31: exit
10 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 22: call 0x300
11 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 30: zzz
12 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 31: exit
13 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 23: exit
14 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 6: call 0x300
15 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 30: zzz
16 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 31: exit
17 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 7: call 0x300
18 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 30: zzz
19 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 31: exit
20 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 8: call 0x300
21 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 30: zzz
22 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 31: exit
23 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 9: exit
24 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 10: ccc
25 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 11: ddd
";

pub const SIMPLE_CALLGRIND_INTEGRAL: &[u8] = b"# callgrind format
version: 1
creator: bpf-profile
positions: line
events: Instructions
totals: 25
fl=<none>

fn=function_0 (0x100)
4 6
cfn=function_1 (0x200)
calls=1 0x200
5 8
cfn=function_2 (0x300)
calls=3 0x300
6 6

fn=function_1 (0x200)
20 4
cfn=function_2 (0x300)
calls=2 0x300
21 4

fn=function_2 (0x300)
30 10
";

pub const SIMPLE_CALLGRIND_LINE_BY_LINE: &[u8] = b"# callgrind format
version: 1
creator: bpf-profile
positions: line
events: Instructions
totals: 25
fl=/tmp/generate_line_by_line.asm

fn=function_0 (0x100)
4 1
5 1
6 1
7 1
8 1
9 1
cfn=function_1 (0x200)
calls=1 0x200
5 8
cfn=function_2 (0x300)
calls=1 0x300
6 2
cfn=function_2 (0x300)
calls=1 0x300
7 2
cfn=function_2 (0x300)
calls=1 0x300
8 2

fn=function_1 (0x200)
20 1
21 1
22 1
23 1
cfn=function_2 (0x300)
calls=1 0x300
21 2
cfn=function_2 (0x300)
calls=1 0x300
22 2

fn=function_2 (0x300)
30 5
31 5
";

pub const SIMPLE_GENERATED_ASM: &str = r"1:        aaa
2:        bbb
3:        call function_0 (0x100)
4:        xxx        ; function_0 (0x100)
5:        call function_1 (0x200)
6:        call function_2 (0x300)
7:        call function_2 (0x300)
8:        call function_2 (0x300)
9:        exit
10:        ccc
11:        ddd








20:        yyy        ; function_1 (0x200)
21:        call function_2 (0x300)
22:        call function_2 (0x300)
23:        exit






30:        zzz        ; function_2 (0x300)
31:        exit
";
