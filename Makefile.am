ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	common \
	libcerror \
	libcthreads \
	libcdata \
	libclocale \
	libcnotify \
	libuna \
	libcfile \
	libfcrypto \
	libfdatetime \
	libfguid \
	libfvalue \
	libfmos \
	libfplist \
	libfwevt \
	libfwnt \
	libhmac \
	src \
	po \
	tests \
	ossfuzz

GETTEXT_FILES = \
	config.rpath \
	po/Makevars.in

EXTRA_DIST = \
	$(GETTEXT_FILES)

DISTCLEANFILES = \
	config.cache \
	config.log \
	config.status \
	Makefile \
	Makefile.in \
	po/Makevars

libtool: @LIBTOOL_DEPS@
	cd $(srcdir) && $(SHELL) ./config.status --recheck

