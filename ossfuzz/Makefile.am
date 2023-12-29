AUTOMAKE_OPTIONS = subdir-objects

if HAVE_LIB_FUZZING_ENGINE
AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCNOTIFY_CPPFLAGS@

bin_PROGRAMS = \
	bzip_fuzzer \
	deflate_fuzzer

bzip_fuzzer_SOURCES = \
	../src/assorted_bit_stream.c ../src/assorted_bit_stream.h \
	../src/assorted_bzip.c ../src/assorted_bzip.h \
	../src/assorted_huffman_tree.c ../src/assorted_huffman_tree.h \
	../src/assorted_libcerror.h \
	../src/assorted_libcnotify.h \
	bzip_fuzzer.cc

bzip_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	@LIBCERROR_LIBADD@ \
	@LIBCNOTIFY_LIBADD@

deflate_fuzzer_SOURCES = \
	../src/assorted_bit_stream.c ../src/assorted_bit_stream.h \
	../src/assorted_deflate.c ../src/assorted_deflate.h \
	../src/assorted_huffman_tree.c ../src/assorted_huffman_tree.h \
	../src/assorted_libcerror.h \
	../src/assorted_libcnotify.h \
	deflate_fuzzer.cc

deflate_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	@LIBCERROR_LIBADD@ \
	@LIBCNOTIFY_LIBADD@
endif

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	-rm -f Makefile

splint:
	@echo "Running splint on bzip_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(bzip_fuzzer_SOURCES)
	@echo "Running splint on deflate_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(deflate_fuzzer_SOURCES)

