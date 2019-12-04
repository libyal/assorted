#!/bin/sh
# Script to run script step on Travis-CI
#
# Version: 20190808

# Exit on error.
set -e;

if test ${TRAVIS_OS_NAME} = "linux" || test ${TRAVIS_OS_NAME} = "linux-ppc64le";
then
	export PATH=$(echo $PATH | tr ":" "\n" | sed '/\/opt\/python/d' | tr "\n" ":" | sed "s/::/:/g");
fi

if test ${TARGET} = "docker";
then
	docker run -t -v "${PWD}:/assorted" ${DOCKERHUB_REPO}:${DOCKERHUB_TAG} sh -c "cd assorted && .travis/script_docker.sh";

elif test ${TARGET} != "coverity";
then
	.travis/runtests.sh;

	if test ${TARGET} = "macos-gcc-pkgbuild";
	then
		export VERSION=`sed '5!d; s/^ \[//;s/\],$//' configure.ac`;

		make install DESTDIR=${PWD}/osx-pkg;
		mkdir -p ${PWD}/osx-pkg/usr/share/doc/assorted;
		cp AUTHORS COPYING COPYING.LESSER NEWS README ${PWD}/osx-pkg/usr/share/doc/assorted;

		pkgbuild --root osx-pkg --identifier com.github.libyal.assorted --version ${VERSION} --ownership recommended ../assorted-${VERSION}.pkg;
	fi
fi

