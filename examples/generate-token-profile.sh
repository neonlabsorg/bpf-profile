#!/usr/bin/env bash

trace=token.trace
dump=token.dump
out=/tmp/token.profile
asm=/tmp/token.asm

cargo run --release -- generate examples/$trace --dump examples/$dump --output $out --asm $asm
result=$?
if [ $result -ne 0 ]; then
    exit $result
fi

echo "Profile written to $out"
echo "Use:"
echo "    callgrind_annotate $out"
echo "or"
echo "    qcachegrind $out"
