#!/bin/bash

# Run tests. Output is compared with expected.out

export TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

if [ "x$1" = "x--generate" ] ; then
    OUT=/dev/stdout
    GENONLY=1
else
    OUT=${TMPDIR}/actual.out
    GENONLY=0
fi

coverage erase
rm -rf htmlcov
rm -f /tmp/trash
for f in $(ls tests/cfgs/test-*.cfg) ; do
    echo "* $f"
    coverage run --append src/polly.py -g 5 -c ${f}
    echo ""
done > ${OUT}

if [ "x$GENONLY" = "x0" ] ; then
    echo '[Polly]
folder = polly
threshold = 0.25
nwords = 8192
verbose = INFO
punctuation = False
digits = False
upper = False
maxchars = 6
length = 4
logfile = /dev/null
picklefile = '${TMPDIR}/polly.cfg'
' > ${TMPDIR}/test.cfg

    echo flippant > /tmp/extra.words
    echo 'bad djm efore etty fter ginal ilt ong tle
    add /tmp/extra.words 1
    good polly.good
    dict american-english-large.txt
    option verbose debug
    option logfile /tmp/trash
    option digits false
    option length 7
    option editing-mode vi
    option bogus true
    option
    stat
    password 1
    ' | coverage run --append src/polly.py \
                 -c ${TMPDIR}/test.cfg > /dev/null

    echo 'read
    sleep 15
    exit
    ' | coverage run --concurrency=thread --append src/polly.py \
                 -c ${TMPDIR}/test.cfg > /dev/null
    coverage html
    trap "rm -f /tmp/extra.words" EXIT

    diff -u tests/output/expected.out ${OUT}
fi
