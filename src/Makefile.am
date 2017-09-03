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

AM_LDFLAGS = @STATIC_LDFLAGS@

bin_PROGRAMS = \
	adler32sum \
	ascii7decompress \
	crc32sum \
	crc64sum \
	fletcher32sum \
	lzfudecompress \
	lznt1decompress \
	lzxpressdecompress \
	mssearchdecode \
	rc4crypt \
	serpentcrypt \
	xor32sum \
	xor64sum \
	zcompress \
	zdecompress

adler32sum_SOURCES = \
	adler32.c adler32.h \
	adler32sum.c \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h

adler32sum_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@ZLIB_LIBADD@

ascii7decompress_SOURCES = \
	ascii7.c ascii7.h \
	ascii7decompress.c \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h

ascii7decompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

crc32sum_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	crc32.c crc32.h \
	crc32sum.c

crc32sum_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

crc64sum_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	crc64.c crc64.h \
	crc64sum.c

crc64sum_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

fletcher32sum_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	fletcher32.c fletcher32.h \
	fletcher32sum.c

fletcher32sum_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

lzfudecompress_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	crc32.c crc32.h \
	lzfu.c lzfu.h \
	lzfudecompress.c

lzfudecompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

lznt1decompress_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libfwnt.h \
	assorted_output.c assorted_output.h \
	lznt1decompress.c

lznt1decompress_LDADD = \
	@LIBFWNT_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

lzxpressdecompress_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libfwnt.h \
	assorted_output.c assorted_output.h \
	lzxpressdecompress.c

lzxpressdecompress_LDADD = \
	@LIBFWNT_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

mssearchdecode_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libuna.h \
	assorted_output.c assorted_output.h \
	mssearch.c mssearch.h \
	mssearchdecode.c

mssearchdecode_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

rc4crypt_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libfcrypto.h \
	assorted_libuna.h \
	assorted_output.c assorted_output.h \
	rc4crypt.c

rc4crypt_LDADD = \
	@LIBFCRYPTO_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

serpentcrypt_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libfcrypto.h \
	assorted_libuna.h \
	assorted_output.c assorted_output.h \
	serpentcrypt.c

serpentcrypt_LDADD = \
	@LIBFCRYPTO_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

xor32sum_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	xor32.c xor32.h \
	xor32sum.c

xor32sum_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

xor64sum_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	xor64.c xor64.h \
	xor64sum.c

xor64sum_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

zcompress_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	deflate.c deflate.h \
	zcompress.c

zcompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@ZLIB_LIBADD@

zdecompress_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	deflate.c deflate.h \
	zdecompress.c

zdecompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@ZLIB_LIBADD@

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

splint:
	@echo "Running splint on adler32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(adler32sum_SOURCES)
	@echo "Running splint on ascii7decompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(ascii7decompress_SOURCES)
	@echo "Running splint on crc32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crc32sum_SOURCES)
	@echo "Running splint on crc64sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crc64sum_SOURCES)
	@echo "Running splint on fletcher32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(fletcher32sum_SOURCES)
	@echo "Running splint on mssearchdecode ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(mssearchdecode_SOURCES)
	@echo "Running splint on lzfudecompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(lzfudecompress_SOURCES)
	@echo "Running splint on lznt1decompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(lznt1decompress_SOURCES)
	@echo "Running splint on lzxpressdecompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(lzxpressdecompress_SOURCES)
	@echo "Running splint on rc4crypt ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(rc4crypt_SOURCES)
	@echo "Running splint on serpentcrypt ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(serpentcrypt_SOURCES)
	@echo "Running splint on xor32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(xor32sum_SOURCES)
	@echo "Running splint on xor64sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(xor64sum_SOURCES)
	@echo "Running splint on zcompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(zdecompress_SOURCES)
	@echo "Running splint on zdecompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(zdecompress_SOURCES)

