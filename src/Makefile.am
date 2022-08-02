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
	@LIBFGUID_CPPFLAGS@ \
	@LIBFVALUE_CPPFLAGS@ \
	@LIBFDATETIME_CPPFLAGS@ \
	@LIBFPLIST_CPPFLAGS@ \
	@LIBFWEVT_CPPFLAGS@ \
	@LIBFWNT_CPPFLAGS@ \
	@ZLIB_CPPFLAGS@ \
	@BZIP2_CPPFLAGS@ \
	@LZMA_CPPFLAGS@ \
	@LIBCRYPTO_CPPFLAGS@ \
	@LIBHMAC_CPPFLAGS@ \
	@PTHREAD_CPPFLAGS@

AM_LDFLAGS = @STATIC_LDFLAGS@

bin_PROGRAMS = \
	adcdecompress \
	adler32sum \
	ascii7decompress \
	banalyze \
	bz2decompress \
	crc32sum \
	crc64sum \
	fletcher32sum \
	fletcher64sum \
	lzfsedecompress \
	lzfudecompress \
	lzmadecompress \
	lznt1decompress \
	lzvndecompress \
	lzxdecompress \
	lzxpressdecompress \
	mssearchdecode \
	plistinfo \
	rc4crypt \
	serpentcrypt \
	wevtinfo \
	winregsave \
	winshellfolder \
	winshelllink \
	xor32sum \
	xor64sum \
	zcompress \
	zdecompress

adcdecompress_SOURCES = \
	adcdecompress.c \
	assorted_adc.c assorted_adc.h \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	assorted_system_string.h

adcdecompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

adler32sum_SOURCES = \
	adler32sum.c \
	assorted_adler32.c assorted_adler32.h \
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
	ascii7decompress.c \
	assorted_ascii7.c assorted_ascii7.h \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	assorted_system_string.h

ascii7decompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

banalyze_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcnotify.h \
	assorted_libhmac.h \
	assorted_output.c assorted_output.h \
	banalyze.c \
	digest_hash.c digest_hash.h

banalyze_LDADD = \
	@LIBHMAC_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LIBCRYPTO_LIBADD@ \
	@LIBDL_LIBADD@ \
	@PTHREAD_LIBADD@

bz2decompress_SOURCES = \
	assorted_bit_stream.c assorted_bit_stream.h \
	assorted_bzip.c assorted_bzip.h \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	assorted_system_string.h \
	bz2decompress.c \
	huffman_tree.c huffman_tree.h

bz2decompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@BZIP2_LIBADD@

crc32sum_SOURCES = \
	assorted_crc32.c assorted_crc32.h \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	crc32sum.c

crc32sum_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

crc64sum_SOURCES = \
	assorted_crc64.c assorted_crc64.h \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
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

fletcher64sum_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	fletcher64.c fletcher64.h \
	fletcher64sum.c

fletcher64sum_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

lzfsedecompress_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_lzfse.c assorted_lzfse.h \
	assorted_lzvn.c assorted_lzvn.h \
	assorted_output.c assorted_output.h \
	assorted_system_string.h \
	lzfsedecompress.c

lzfsedecompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

lzfudecompress_SOURCES = \
	assorted_crc32.c assorted_crc32.h \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	lzfu.c lzfu.h \
	lzfudecompress.c

lzfudecompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

lzmadecompress_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_lzma.c assorted_lzma.h \
	assorted_output.c assorted_output.h \
	assorted_system_string.h \
	lzmadecompress.c

lzmadecompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LZMA_LIBADD@

lznt1decompress_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libfwnt.h \
	assorted_output.c assorted_output.h \
	assorted_system_string.h \
	lznt1decompress.c

lznt1decompress_LDADD = \
	@LIBFWNT_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

lzvndecompress_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_lzvn.c assorted_lzvn.h \
	assorted_output.c assorted_output.h \
	assorted_system_string.h \
	lzvndecompress.c

lzvndecompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

lzxdecompress_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libfwnt.h \
	assorted_output.c assorted_output.h \
	assorted_signal.c assorted_signal.h \
	assorted_system_string.h \
	assorted_unused.h \
	decompression_handle.c decompression_handle.h \
	lzxdecompress.c

lzxdecompress_LDADD = \
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

plistinfo_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libfplist.h \
	assorted_libuna.h \
	assorted_output.c assorted_output.h \
	plistinfo.c

plistinfo_LDADD = \
	@LIBFPLIST_LIBADD@ \
	@LIBFVALUE_LIBADD@ \
	@LIBFGUID_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCDATA_LIBADD@ \
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

wevtinfo_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libfwevt.h \
	assorted_libuna.h \
	assorted_output.c assorted_output.h \
	wevtinfo.c

wevtinfo_LDADD = \
	@LIBFWEVT_LIBADD@ \
	@LIBFVALUE_LIBADD@ \
	@LIBFWNT_LIBADD@ \
	@LIBFGUID_LIBADD@ \
	@LIBFDATETIME_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCDATA_LIBADD@ \
	@LIBCERROR_LIBADD@

winregsave_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	winregsave.c

winregsave_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

winshellfolder_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	winshellfolder.c

winshellfolder_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@

winshelllink_SOURCES = \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	winshelllink.c

winshelllink_LDADD = \
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
	assorted_bit_stream.c assorted_bit_stream.h \
	assorted_deflate.c assorted_deflate.h \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	huffman_tree.c huffman_tree.h \
	zcompress.c

zcompress_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@ZLIB_LIBADD@

zdecompress_SOURCES = \
	assorted_bit_stream.c assorted_bit_stream.h \
	assorted_deflate.c assorted_deflate.h \
	assorted_getopt.c assorted_getopt.h \
	assorted_i18n.h \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_output.c assorted_output.h \
	assorted_system_string.h \
	huffman_tree.c huffman_tree.h \
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
	@echo "Running splint on adcdecompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(adcdecompress_SOURCES)
	@echo "Running splint on adler32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(adler32sum_SOURCES)
	@echo "Running splint on ascii7decompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(ascii7decompress_SOURCES)
	@echo "Running splint on banalyze ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(banalyze_SOURCES)
	@echo "Running splint on bz2decompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(bz2decompress_SOURCES)
	@echo "Running splint on crc32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crc32sum_SOURCES)
	@echo "Running splint on crc64sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crc64sum_SOURCES)
	@echo "Running splint on fletcher32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(fletcher32sum_SOURCES)
	@echo "Running splint on fletcher64sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(fletcher64sum_SOURCES)
	@echo "Running splint on lzfsedecompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(lzfsedecompress_SOURCES)
	@echo "Running splint on lzfudecompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(lzfudecompress_SOURCES)
	@echo "Running splint on lzmadecompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(lzmadecompress_SOURCES)
	@echo "Running splint on lznt1decompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(lznt1decompress_SOURCES)
	@echo "Running splint on lzvndecompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(lzvndecompress_SOURCES)
	@echo "Running splint on lzxdecompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(lzxdecompress_SOURCES)
	@echo "Running splint on lzxpressdecompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(lzxpressdecompress_SOURCES)
	@echo "Running splint on mssearchdecode ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(mssearchdecode_SOURCES)
	@echo "Running splint on plistinfo ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(plistinfo_SOURCES)
	@echo "Running splint on rc4crypt ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(rc4crypt_SOURCES)
	@echo "Running splint on serpentcrypt ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(serpentcrypt_SOURCES)
	@echo "Running splint on wevtinfo ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(wevtinfo_SOURCES)
	@echo "Running splint on winregsave ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(winregsave_SOURCES)
	@echo "Running splint on winshellfolder ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(winshellfolder_SOURCES)
	@echo "Running splint on winshelllink ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(winshelllink_SOURCES)
	@echo "Running splint on xor32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(xor32sum_SOURCES)
	@echo "Running splint on xor64sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(xor64sum_SOURCES)
	@echo "Running splint on zcompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(zcompress_SOURCES)
	@echo "Running splint on zdecompress ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(zdecompress_SOURCES)

