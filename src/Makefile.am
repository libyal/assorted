AM_CPPFLAGS = \
        -I$(top_srcdir)/include \
        -I$(top_srcdir)/common \
	@LIBCSTRING_CPPFLAGS@ \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCTHREADS_CPPFLAGS@ \
	@LIBCDATA_CPPFLAGS@ \
	@LIBCLOCALE_CPPFLAGS@ \
	@LIBCNOTIFY_CPPFLAGS@ \
	@LIBUNA_CPPFLAGS@ \
	@LIBCFILE_CPPFLAGS@ \
	@LIBFWNT_CPPFLAGS@ \
	@LIBHMAC_CPPFLAGS@ \
	@LIBCSYSTEM_CPPFLAGS@ \
	@ZLIB_CPPFLAGS@ \
	@BZIP2_CPPFLAGS@

AM_LDFLAGS = @STATIC_LDFLAGS@

bin_PROGRAMS = \
	adler32sum \
	crc32sum \
	crc64sum \
	fletcher32sum \
	rc4crypt \
	xor32sum \
	xor64sum

adler32sum_SOURCES = \
	adler32.c adler32.h \
	adler32sum.c \
	assorted_libcerror.h \
	assorted_libcnotify.h \
	assorted_libcstring.h \
	assorted_libcsystem.h \
	assorted_output.c assorted_output.h

adler32sum_LDADD = \
	@LIBCSYSTEM_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@ \
	@ZLIB_LIBADD@

crc32sum_SOURCES = \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libcstring.h \
	assorted_libcsystem.h \
	assorted_output.c assorted_output.h \
	crc32.c crc32.h \
	crc32sum.c

crc32sum_LDADD = \
	@LIBCSYSTEM_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

crc64sum_SOURCES = \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libcstring.h \
	assorted_libcsystem.h \
	assorted_output.c assorted_output.h \
	crc64.c crc64.h \
	crc64sum.c

crc64sum_LDADD = \
	@LIBCSYSTEM_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

fletcher32sum_SOURCES = \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libcstring.h \
	assorted_libcsystem.h \
	assorted_output.c assorted_output.h \
	fletcher32.c fletcher32.h \
	fletcher32sum.c

fletcher32sum_LDADD = \
	@LIBCSYSTEM_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

rc4crypt_SOURCES = \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libcstring.h \
	assorted_libcsystem.h \
	assorted_libuna.h \
	assorted_output.c assorted_output.h \
	rc4.c rc4.h \
	rc4crypt.c

rc4crypt_LDADD = \
	@LIBCSYSTEM_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

xor32sum_SOURCES = \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libcstring.h \
	assorted_libcsystem.h \
	assorted_output.c assorted_output.h \
	xor32.c xor32.h \
	xor32sum.c

xor32sum_LDADD = \
	@LIBCSYSTEM_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

xor64sum_SOURCES = \
	assorted_libcerror.h \
	assorted_libcfile.h \
	assorted_libcnotify.h \
	assorted_libcstring.h \
	assorted_libcsystem.h \
	assorted_output.c assorted_output.h \
	xor64.c xor64.h \
	xor64sum.c

xor64sum_LDADD = \
	@LIBCSYSTEM_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

splint:
	@echo "Running splint on adler32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(adler32sum_SOURCES)
	@echo "Running splint on crc32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crc32sum_SOURCES)
	@echo "Running splint on crc64sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crc64sum_SOURCES)
	@echo "Running splint on fletcher32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(fletcher32sum_SOURCES)
	@echo "Running splint on rc4crypt ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(rc4crypt_SOURCES)
	@echo "Running splint on xor32sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(xor32sum_SOURCES)
	@echo "Running splint on xor64sum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(xor64sum_SOURCES)

