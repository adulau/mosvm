#!/bin/sh

OS=`uname`

if [ x$OS = xMINGW32_NT-5.1 ]; then
    OS=Windows
elif [ x$OS = xCYGWIN_NT-5.1 ]; then
    OS=Windows
fi

echo "Welcome to Situation."
echo "    This script will construct a site configuration module that, when "
echo "    employed by MOSVM, contains information about where to find additional "
echo "    modules, and where to place the mosvm interpreter and ancilliary "
echo "    tools."
echo 

echo "Step 1: The Base Directory"
echo "    This directory will provide a default location for other Situation"
echo "    questions.  If you plan on setting each location individually, you"
echo "    should just accept the default value, by hitting enter."
echo "    "

if [ x$OS = Windows ]; then
    basedir_default="C:\\Program Files\\MOSVM"
else
    basedir_default="/usr/local"
fi

IFS=:::NONESUCH::: read basedir?"    Base Directory ($basedir_default): "
[ x$basedir = x ] && basedir=$basedir_default

echo

echo "Step 2: The Modules Directory"
echo "    This directory will contain the external modules that accompany MOSVM,"
echo "    including the MOSVM compiler, HTTP server, and other functionality. By"
echo "    default, this is a subdirectory of the Base Directory.  It is possible"
echo "    to configure MOSVM to use additional directories for external modules,"
echo "    but this directory will be checked if those directories do not contain"
echo "    a requested module."
echo

if [ x$OS = Windows ]; then
    moddir_default="$basedir\\lib"
else
    moddir_default="$basedir/lib/mosvm"
fi

IFS=:::NONESUCH::: read moddir?"    Modules Directory ($moddir_default): "
[ x$moddir = x ] && moddir=$moddir_default

echo

echo "Step 3: The Tools Directory"
echo "    MOSVM comes with executables for compiling MOSVM applications, and"
echo "    an interactive evaulator.  Situation needs to know where to place these"
echo "    programs."
echo

if [ x$OS = Windows ]; then
    bindir_default="$basedir"
else
    bindir_default="$basedir/bin"
fi

IFS=:::NONESUCH::: read bindir?"    Modules Directory ($bindir_default): "
[ x$bindir = x ] && bindir=$bindir_default

echo

echo "Step 4: Finishing Up"
echo "    Situation now has sufficient information to produce the site"
echo "    configuration module.  Are you satisfied with the answers you have "
echo "    given?"
echo

goahead_default=Yes

IFS=:::NONESUCH::: read goahead?"    Proceed ($goahead_default): "
[ x$goahead = x ] && goahead=$goahead_default

echo $goahead | egrep '[Yy]([Ee]([Ss])?)?' >/dev/null || exit 1;

echo ";;; Generated by bin/situation.sh" >site/config.ms
echo "(set-site-config! 'bin-path \"$bindir\")" >>site/config.ms
echo "(set-site-config! 'mod-path '(\".\" \"$moddir\"))" >>site/config.ms

echo
echo site/config.ms created.
