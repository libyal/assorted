#!/bin/sh
# Script to run tests
#
# Version: 20260714

if [ -f "${PWD}/assorted/.libs/assorted.1.dylib" ] && [ -f ./pyorted/.libs/pyorted.so ]
then
    install_name_tool -change /usr/local/lib/assorted.1.dylib "${PWD}/assorted/.libs/assorted.1.dylib" ./pyorted/.libs/pyorted.so
fi

make check-build > /dev/null

# shellcheck disable=SC2068
make check $@
RESULT=$?

if [ ${RESULT} -ne 0 ]
then
    find . -name \*.log -path \*.dir/\*/\*.log -print -exec cat {} \;
fi
exit ${RESULT}

