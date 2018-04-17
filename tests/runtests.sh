#!/bin/bash

# Run tests. Output is compared with expected.out

export TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

if [ "x$1" = "x--generate" ] ; then
    OUT=/dev/stdout
else
    OUT=${TMPDIR}/actual.out
fi

for f in $(ls tests/cfgs/*.cfg) ; do
    echo "* $f"
    python polly.py -g 10 -c ${f}
    echo ""
done > ${OUT}

if [ "x$1" = "x" ] ; then
    diff -u tests/output/expected.out ${OUT}
fi
