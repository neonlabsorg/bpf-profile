#!/usr/bin/env bash

trace=memo.trace
dump=memo.dump
out=/tmp/memo.profile

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
