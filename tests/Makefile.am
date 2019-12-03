AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCTHREADS_CPPFLAGS@ \
	@LIBCDATA_CPPFLAGS@ \
	@LIBCLOCALE_CPPFLAGS@ \
	@LIBCNOTIFY_CPPFLAGS@ \
	@LIBUNA_CPPFLAGS@ \
	@LIBCFILE_CPPFLAGS@ \
	@LIBFCRYPTO_CPPFLAGS@ \
	@LIBFWNT_CPPFLAGS@ \
	@LIBHMAC_CPPFLAGS@ \
	@ZLIB_CPPFLAGS@ \
	@BZIP2_CPPFLAGS@

TESTS = \
	test_tools.sh

check_SCRIPTS = \
	test_runner.sh \
	test_tools.sh

EXTRA_DIST = \
	$(check_SCRIPTS)

check_PROGRAMS = \
	assorted_test_adler32 \
	assorted_test_ascii7 \
	assorted_test_crc32 \
	assorted_test_crc64 \
	assorted_test_deflate

assorted_test_adler32_SOURCES = \
	../src/adler32.c ../src/adler32.h \
	assorted_test_adler32.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_adler32_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_ascii7_SOURCES = \
	../src/ascii7.c ../src/ascii7.h \
	assorted_test_ascii7.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_ascii7_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_crc32_SOURCES = \
	../src/crc32.c ../src/crc32.h \
	assorted_test_crc32.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_crc32_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_crc64_SOURCES = \
	../src/crc64.c ../src/crc64.h \
	assorted_test_crc64.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_crc64_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_deflate_SOURCES = \
	../src/deflate.c ../src/deflate.h \
	assorted_test_deflate.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_deflate_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

