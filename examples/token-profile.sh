#!/usr/bin/env bash

trace=token.trace
dump=token.dump
out=/tmp/token.profile

cargo run --release -- generate examples/$trace --dump examples/$dump --output $out
result=$?
if [ $result -ne 0 ]; then
    exit $result
fi

echo "Profile written to $out"
echo "Use:"
echo "    callgrind_annotate $out"
echo "or"
echo "    qcachegrind $out"
