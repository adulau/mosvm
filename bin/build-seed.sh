#!/bin/sh

# Check for MOSVM.

if [ x$USE_GUILE != x ]; then
    DO_SCHEME="guile --debug -l lib/run-guile.scm -e guile-main -s"
elif [ x$USE_MZSCHEME != x ]; then
    DO_SCHEME="mzscheme -M errortrace -f lib/run-mzscheme.scm -C"
else
    echo "You must either define USE_GUILE or USE_MZSCHEME prior to invoking"
    echo "build-seed.sh"
    exit 1
fi

DEPS=`$DO_SCHEME bin/manifest.ms bin/mosc`
echo $DEPS

for DEP in $DEPS; do
    DEP_MS=$DEP.ms
    DEP_MO=$DEP.mo
    if [ ! -s $DEP_MO ]||[ $DEP_MS -nt $DEP_MO ]; then
        $DO_SCHEME bin/mosc.ms $DEP || exit 1
    fi
done
