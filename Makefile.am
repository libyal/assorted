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

MAINTAINERCLEANFILES = \
	Makefile.in

libtool: @LIBTOOL_DEPS@
	cd $(srcdir) && $(SHELL) ./config.status --recheck

distclean: clean
	-rm -f Makefile
	-rm -f config.status
	-rm -f config.cache
	-rm -f config.log
	@for dir in ${subdirs}; do \
		(cd $$dir && $(MAKE) distclean) \
		|| case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac; \
	done && test -z "$$fail"

