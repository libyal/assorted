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
	adler32

adler32_SOURCES = \
	adler32.c \
	assorted_libcerror.h \
	assorted_libcnotify.h \
	assorted_libcstring.h \
	assorted_libcsystem.h \
	assorted_output.c assorted_output.h

adler32_LDADD = \
	@LIBCSYSTEM_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@ \
	@ZLIB_LIBADD@

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

splint:
	@echo "Running splint on adler32 ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(adler32_SOURCES)

