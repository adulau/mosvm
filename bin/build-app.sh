#!/bin/sh
BIN=`dirname $0`
LIB=`dirname $BIN`/lib
STUB=$1
PROG=$2
OUTP=$3

if [ x$USE_GUILE != x ]; then
    DO_SCHEME="guile --debug -l $LIB/run-guile.scm -e guile-main -s"
elif [ x$USE_MZSCHEME != x ]; then
    DO_SCHEME="mzscheme -M errortrace -f $LIB/run-mzscheme.scm -C"
else
    echo "You must define USE_GUILE, USE_MZSCHEME or MOSC prior to invoking"
    echo "build-app.sh"
    exit 1
fi

DEPS=`$DO_SCHEME $BIN/manifest.ms $PROG`
echo $DEPS
DEPS_MO=""
RE_GLUE=""

for DEP in $DEPS; do
    DEP_MS=$DEP.ms
    DEP_MO=$DEP.mo
    if [ ! -s $DEP_MO ]||[ $DEP_MS -nt $DEP_MO ]; then
        echo "Compiling $DEP_MS to $DEP_MO.."
        $DO_SCHEME $BIN/mosc.ms $DEP || exit 1
        RE_GLUE="yes"
    fi
    DEPS_MO="$DEPS_MO $DEP_MO"
done

./$BIN/glue $STUB $DEPS_MO $OUTP && chmod 0755 $OUTP || exit 2
