ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	common \
	libcerror \
	libcthreads \
	libcdata \
	libcdatetime \
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
	manuals \
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

check-build: all
	cd $(srcdir)/tests && $(MAKE) check-build $(AM_MAKEFLAGS)

libtool: @LIBTOOL_DEPS@
	cd $(srcdir) && $(SHELL) ./config.status --recheck

