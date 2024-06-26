AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = \
	-I../include -I$(top_srcdir)/include \
	-I../common -I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCTHREADS_CPPFLAGS@ \
	@LIBCDATA_CPPFLAGS@ \
	@LIBCLOCALE_CPPFLAGS@ \
	@LIBCNOTIFY_CPPFLAGS@ \
	@LIBUNA_CPPFLAGS@ \
	@LIBCFILE_CPPFLAGS@ \
	@LIBFCRYPTO_CPPFLAGS@ \
	@LIBFMOS_CPPFLAGS@ \
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
	assorted_test_bit_stream \
	assorted_test_bzip \
	assorted_test_crc32 \
	assorted_test_crc64 \
	assorted_test_deflate \
	assorted_test_fletcher32 \
	assorted_test_fletcher64 \
	assorted_test_huffman_tree \
	assorted_test_lzfu \
	assorted_test_lzma \
	assorted_test_xor32 \
	assorted_test_xor64

assorted_test_adler32_SOURCES = \
	../src/assorted_adler32.c ../src/assorted_adler32.h \
	assorted_test_adler32.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_adler32_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_ascii7_SOURCES = \
	../src/assorted_ascii7.c ../src/assorted_ascii7.h \
	assorted_test_ascii7.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_ascii7_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_bit_stream_SOURCES = \
	../src/assorted_bit_stream.c ../src/assorted_bit_stream.h \
	assorted_test_bit_stream.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_memory.c assorted_test_memory.h \
	assorted_test_unused.h

assorted_test_bit_stream_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_bzip_SOURCES = \
	../src/assorted_bit_stream.c ../src/assorted_bit_stream.h \
	../src/assorted_bzip.c ../src/assorted_bzip.h \
	../src/assorted_huffman_tree.c ../src/assorted_huffman_tree.h \
	assorted_test_bzip.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_bzip_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_crc32_SOURCES = \
	../src/assorted_crc32.c ../src/assorted_crc32.h \
	assorted_test_crc32.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_crc32_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_crc64_SOURCES = \
	../src/assorted_crc64.c ../src/assorted_crc64.h \
	assorted_test_crc64.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_crc64_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_deflate_SOURCES = \
	../src/assorted_bit_stream.c ../src/assorted_bit_stream.h \
	../src/assorted_deflate.c ../src/assorted_deflate.h \
	../src/assorted_huffman_tree.c ../src/assorted_huffman_tree.h \
	assorted_test_deflate.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_deflate_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_fletcher32_SOURCES = \
	../src/assorted_fletcher32.c ../src/assorted_fletcher32.h \
	assorted_test_fletcher32.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_fletcher32_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_fletcher64_SOURCES = \
	../src/assorted_fletcher64.c ../src/assorted_fletcher64.h \
	assorted_test_fletcher64.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_fletcher64_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_huffman_tree_SOURCES = \
	../src/assorted_bit_stream.c ../src/assorted_bit_stream.h \
	../src/assorted_huffman_tree.c ../src/assorted_huffman_tree.h \
	assorted_test_huffman_tree.c \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_memory.c assorted_test_memory.h \
	assorted_test_unused.h

assorted_test_huffman_tree_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_lzfu_SOURCES = \
	../src/assorted_crc32.c ../src/assorted_crc32.h \
	../src/assorted_lzfu.c ../src/assorted_lzfu.h \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_lzfu.c \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_lzfu_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_lzma_SOURCES = \
	../src/assorted_bit_stream.c ../src/assorted_bit_stream.h \
	../src/assorted_lzma.c ../src/assorted_lzma.h \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_lzma.c \
	assorted_test_macros.h \
	assorted_test_unused.h

assorted_test_lzma_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_xor32_SOURCES = \
	../src/assorted_xor32.c ../src/assorted_xor32.h \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h \
	assorted_test_xor32.c

assorted_test_xor32_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

assorted_test_xor64_SOURCES = \
	../src/assorted_xor64.c ../src/assorted_xor64.h \
	assorted_test_libcerror.h \
	assorted_test_libcnotify.h \
	assorted_test_macros.h \
	assorted_test_unused.h \
	assorted_test_xor64.c

assorted_test_xor64_LDADD = \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@

DISTCLEANFILES = \
	Makefile \
	Makefile.in

