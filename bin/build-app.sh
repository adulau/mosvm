#!/bin/sh

STUB=$1
PROG=$2
OUTP=$3

if [ x$USE_GUILE != x ]; then
    DO_SCHEME="guile --debug -l lib/run-guile.scm -e guile-main -s"
elif [ x$USE_MZSCHEME != x ]; then
    DO_SCHEME="mzscheme -M errortrace -f lib/run-mzscheme.scm -C"
else
    echo "You must either define USE_GUILE or USE_MZSCHEME prior to invoking"
    echo "build-app.sh"
    exit 1
fi

DEPS=`$DO_SCHEME bin/manifest.ms $PROG`
DEPS_MO=""
echo $DEPS

for DEP in $DEPS; do
    DEP_MS=$DEP.ms
    DEP_MO=$DEP.mo
    if [ ! -s $DEP_MO ]||[ $DEP_MS -nt $DEP_MO ]; then
        $DO_SCHEME bin/mosc.ms $DEP || exit 1
    fi
    DEPS_MO="$DEPS_MO $DEP_MO"
done

./build/bin/glue $STUB $DEPS_MO $OUTP && chmod 0755 $OUTP || exit 2
