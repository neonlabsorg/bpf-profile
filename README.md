# BPF trace-to-profile file converter

This program reads a trace file that contains the trace output of the BPF VM,
and generates a profile for tools like `callgrind_annotate` or `qcachegrind`.

To resolve names of functions this program may require a dump file containing
the instruction dump of the ELF.

You can create the dump file by passing the --dump flag to `cargo build-bpf`,
or directly:
```llvm-objdump -print-imm-hex --source --disassemble <ELF file path>```

You can create the trace file by running the *Solana* cluster under `RUST_LOG`:
```export RUST_LOG=solana_rbpf=trace```

Use the `bpf-profile help generate` command to list available options.

When a trace file is ready, use the following command:
```bpf-profile generate <trace file path> -o callgrind.out```
which should produce file containing something like
```
# callgrind format
events: Instructions

fl=file1.c
fn=main
16 20
cfn=func1
calls=1 50
16 400
cfi=file2.c
cfn=func2
calls=3 20
16 400

fn=func1
51 100
cfi=file2.c
cfn=func2
calls=2 20
51 300

fl=file2.c
fn=func2
20 700
```

That file can be loaded by standard tools `callgrind_annotate` and `QCacheGrind`
for analysis.
