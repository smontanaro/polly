#!/bin/bash

# Run tests. Output is compared with expected.out

DOCOV=0
TMPDIR=

while getopts 'cet' OPTION; do
    case "$OPTION" in
        t)
            export TMPDIR=$(mktemp -d)
            trap "rm -rf ${TMPDIR}" EXIT
            ;;
        c)
            DOCOV=1
            ;;
        e)
            ERASECOV=1
            ;;
    esac
done
shift "$(($OPTIND -1))"

if [ "x$TMPDIR" = "x" ] ; then
    export TMPDIR=/tmp
fi

OUT=${TMPDIR}/actual.out

if [ "x$DOCOV" = "x1" ] ; then
    PYTHON='coverage run --concurrency=thread --append'
else
    PYTHON='python'
fi

if [ "x$ERASECOV" = "x1" ] ; then
    coverage erase
    rm -rf htmlcov
fi
for f in tests/cfgs/test-*.cfg ; do
    echo "* $f"
    ${PYTHON} -m polly.polly -g 5 -c ${f}
    echo ""
done > ${OUT}

cat <<EOF > ${TMPDIR}/test.cfg
[Polly]
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
picklefile = ${TMPDIR}/polly.pkl
unittests = True
EOF

if [ "x$TEST_CRED" != "x" ] ; then
    egrep '^ *(server|user|password) *=' $TEST_CRED >> ${TMPDIR}/test.cfg
fi

echo flippant > ${TMPDIR}/extra.words
cat <<EOF > ${TMPDIR}/test.cmds
option logfile /tmp/trash
option logfile ${TMPDIR}/test-run-bz2.log.bz2
option logfile ${TMPDIR}/test-run-gz.log.gz
option logfile /tmp/trash
bad djm efore etty fter ginal ilt ong tle
add ${TMPDIR}/extra.words 1
good polly.good
trim 10
rebuild
dict missing.txt
dict american-english-large.txt
option digits false
option length 7
option editing-mode vi
option verbose info
password
read
sleep 2.2
option verbose trace
sleep 2.2
option verbose debug
sleep 2.2
option verbose warning
sleep 2.2
option verbose trace
sleep 2.2
option verbose info
stat
tribble
fail

exit
EOF

${PYTHON} -m polly.polly -n -c ${TMPDIR}/test.cfg < ${TMPDIR}/test.cmds

if [ "x$DOCOV" = "x1" ] ; then
    coverage html
fi
diff -u tests/output/expected.out ${OUT}
