## BPF trace to profile converter

This program reads a trace file that contains trace output from the BPF VM,
and generates a profile for tools like `callgrind_annotate` or `QCacheGrind`.

To resolve names of functions this program may require a dump file containing
the instruction dump of the ELF.

You can create the dump file by passing `--dump` flag to `cargo-build-bpf`.

You can create the trace file by running the *Solana* cluster under `RUST_LOG`:
```export RUST_LOG=solana_bpf_loader_program=trace```

Use the `bpf-profile help generate` command to list available options.

When the trace file is ready, use the following command:
```bpf-profile generate <trace file path> -d <dump file path> -o callgrind.out```
which should produce new file `callgrind.out` containing the profile data.
It can be read by any standard tool for analysis.

This program expects input files created with *Solana 1.6.x*. Other versions
of *Solana* may generate incompatible data.
