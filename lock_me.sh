#!/bin/sh
# requirements: brew install lock or apt-get install util-linux

ME=`basename "$0"`;
LCK="/tmp/${ME}.LCK";
exec 8>$LCK;

if flock -n 8; then
  $*
else
  echo "I'm rejected ($$)";
fi
