#!/bin/sh

BIN=`dirname $0`
BASE=`dirname $BIN`
LIB=$BASE/lib
FILE=$1

DO_SCHEME="guile --debug -l $LIB/run-guile.scm -e guile-main -s"
cd $BASE && $DO_SCHEME $BIN/mosc.ms $FILE || exit 1

