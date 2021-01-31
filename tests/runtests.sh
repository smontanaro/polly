#!/bin/bash

# Run tests. Output is compared with expected.out

# If TEST_CRED is set, server, user and password are grepped out of it
# and added to test.cfg. In that case, it is expected that the
# referenced IMAP account will have a test-polly folder/label. This is
# only used to exercise the read loop and increase coverage, so it's
# not strctly necessary.

export TMPDIR=$(mktemp -d)
# trap "rm -rf ${TMPDIR}" EXIT

if [ "x$1" = "x--generate" ] ; then
    OUT=/dev/stdout
    GENONLY=1
else
    OUT=${TMPDIR}/actual.out
    GENONLY=0
fi

coverage erase
rm -rf htmlcov
for f in $(ls tests/cfgs/test-*.cfg) ; do
    echo "* $f"
    coverage run --append src/polly.py -g 5 -c ${f}
    echo ""
done > ${OUT}

if [ "x$GENONLY" = "x0" ] ; then
    echo '[Polly]
verbose = trace
folder = test-polly
threshold = 0.25
nwords = 8192
punctuation = False
digits = False
upper = False
maxchars = 6
length = 4
logfile = /dev/null
picklefile = '${TMPDIR}'/polly.pkl
unittests = True
' > ${TMPDIR}/test.cfg

    if [ "x$TEST_CRED" != "x" ] ; then
        egrep '^ *(server|user|password) *=' $TEST_CRED >> ${TMPDIR}/test.cfg
    fi
    echo flippant > ${TMPDIR}/extra.words
    echo 'bad djm efore etty fter ginal ilt ong tle
    add '${TMPDIR}'/extra.words 1
    good polly.good
    dict american-english-large.txt
    option logfile /tmp/trash
    option digits false
    option length 7
    option editing-mode vi
    read
    sleep 5
    sleep 5
    sleep 5
    sleep 5
    sleep 5
    ' | coverage run --concurrency=thread --append src/polly.py -n \
                 -c ${TMPDIR}/test.cfg

    coverage html
    diff -u tests/output/expected.out ${OUT}
fi
