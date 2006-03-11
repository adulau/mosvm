#!/bin/sh

STUB=$1
PROG=$2
OUTP=$3

if [ x$USE_GUILE != x ]; then
    DO_SCHEME="guile --debug -l lib/run-guile.scm -e guile-main -s"
elif [ x$USE_MZSCHEME != x ]; then
    DO_SCHEME="mzscheme -M errortrace -f lib/run-mzscheme.scm -C"
else
    echo "You must define USE_GUILE, USE_MZSCHEME or MOSC prior to invoking"
    echo "build-app.sh"
    exit 1
fi

LIBS=`ls lib/*.ms`
LIBS_MO=""

for LIB_MS in $LIBS; do
    LIB=lib/`basename $LIB_MS .ms`
    LIB_MS=$LIB.ms
    LIB_MO=$LIB.mo
    if [ ! -s $LIB_MO ]||[ $LIB_MS -nt $LIB_MO ]; then
        echo "Compiling $LIB_MS to $LIB_MO.."
        $DO_SCHEME bin/mosc.ms $LIB || exit 1
    fi
    LIBS_MO="$LIBS_MO $LIB_MO"
done
