#!/bin/sh
# Script to run tests on Travis-CI
#
# Version: 20190808

./configure ${CONFIGURE_OPTIONS};
RESULT=$?;

if test ${RESULT} -eq 0;
then
	make > /dev/null;
	RESULT=$?;
fi
if test ${RESULT} -eq 0;
then
	make check CHECK_WITH_STDERR=1;
	RESULT=$?;
fi
if test ${RESULT} -ne 0;
then
        if test -f tests/test-suite.log;
	then
		cat tests/test-suite.log;
	fi
fi
exit ${RESULT};

