#!/bin/sh
BIN=`dirname $0`
LIBDIR=$1
MOSC=$BIN/mosc
LIBS=`ls $LIBDIR/*.ms`
LIBS_MO=""

for LIB_MS in $LIBS; do
    LIB=$LIBDIR/`basename $LIB_MS .ms`
    LIB_MS=$LIB.ms
    LIB_MO=$LIB.mo
    if [ ! -s $LIB_MO ]||[ $LIB_MS -nt $LIB_MO ]; then
        echo "Compiling $LIB_MS to $LIB_MO.."
        $MOSC $LIB || exit 1
    fi
done

touch $LIBDIR
