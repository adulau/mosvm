#!/bin/sh

BIN=`dirname $0`
BASE=`dirname $BIN`
LIB=$BASE/lib
STUB=$1
PROG=$2
OUTP=$3

if [ x$USE_MOSVM != x ]; then
    DO_SCHEME="bin/mosvm "
elif [ x$USE_GUILE != x ]; then
    DO_SCHEME="guile --debug -l $LIB/run-guile.scm -e guile-main -s"
elif [ x$USE_MZSCHEME != x ]; then
    DO_SCHEME="mzscheme -M errortrace -f $LIB/run-mzscheme.scm -C"
elif [ x$IN_BOOTSTRAP != x ]; then
    echo "In bootstrap mode -- attempting to build application using intermediate"
    echo "files, instead of a scheme evaluator."
else
    echo "You must define USE_GUILE, USE_MZSCHEME or USE_MOSVM prior to "
    echo "invoking build-app.sh -- a scheme or mosquito evaluator is "
    echo "required for analyzing dependencies of the application."
    exit 1
fi

PROG_MF=$PROG.mf
PROG_MS=$PROG.ms

# This will not catch all possible changes that would require a manifest 
# rebuild; but inter-module imports are generally stable and the really-clean 
# target purges all manifests.

if [ ! -s $PROG_MF ]||[ $PROG_MS -nt $PROG_MF ]; then
    if [ "x$DO_SCHEME" = x ]; then
        echo "A scheme evaluator is required, but was not supplied; aborting."
        exit 1;
    fi

    DEPS="`cd $BASE && $DO_SCHEME $BIN/manifest.ms $PROG`"
    echo $DEPS >$PROG_MF
else
    DEPS=`cat $PROG_MF`
fi

DEPS_MO=""
RE_GLUE=""

if [ ! -s $OUTP ]||[ $STUB -nt $OUTP ]; then
    RE_GLUE="yes"
fi

for DEP in $DEPS; do
    DEP_MS=$DEP.ms
    DEP_MO=$DEP.mo
    DEP_MA=$DEP.ma
    DEPS_MO="$DEPS_MO $DEP_MO"

    if [ ! -s $DEP_MO ]||[ $DEP_MS -nt $DEP_MO ]; then
        if [ x$USE_MOSC != x ]; then
            echo "Compiling $DEP_MS to $DEP_MO.."
            cd $BASE && bin/mosc $DEP_MS
        else
            if [ $DEP_MS -nt x$DEP_MA ]; then
                if [ "x$DO_SCHEME" = x ]; then
                    echo "Cannot bootstrap; $DEP_MS is newer than $DEP_MA."
                    exit 1
                fi

                echo "Compiling $DEP_MS to $DEP_MA.."
                cd $BASE && $DO_SCHEME bin/mosc.scm $DEP_MS || exit 1
            fi
            echo "Assembling $DEP_MA to $DEP_MO.."
            cd $BASE && $BIN/mosasm $DEP_MA $DEP_MO || exit 1
        fi

        RE_GLUE="yes"
    elif [ x$RE_GLUE = x ]&&[ $DEP_MO -nt $OUTP ]; then
        RE_GLUE="yes"
    fi
done

if [ x$RE_GLUE != x ]; then
    $BIN/mosld $STUB $DEPS_MO $OUTP && chmod 0755 $OUTP || exit 2
fi
