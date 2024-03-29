AC_PREREQ([2.71])

AC_INIT(
 [assorted],
 [20240313],
 [joachim.metz@gmail.com])

AC_CONFIG_SRCDIR(
 [common/types.h.in])

AM_INIT_AUTOMAKE([gnu 1.6 tar-ustar])
AM_EXTRA_RECURSIVE_TARGETS([sources splint])

AC_CONFIG_MACRO_DIR([m4])

dnl Check for host type
AC_CANONICAL_HOST

dnl Check for large file support
AC_SYS_LARGEFILE

dnl Check for libtool DLL support
LT_INIT([win32-dll])

dnl Checks for programs
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_INSTALL

dnl Check for libtool
AC_SUBST(LIBTOOL_DEPS)

dnl Check for pkg-config
AC_PATH_PROG(PKGCONFIG,[pkg-config])

dnl Support of internationalization (i18n)
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.21])

dnl Check for compiler language support
AC_C_CONST
AC_C_VOLATILE

dnl Check if WINAPI support should be enabled
AX_COMMON_CHECK_ENABLE_WINAPI

dnl Check if wide character type should be enabled
AX_COMMON_CHECK_ENABLE_WIDE_CHARACTER_TYPE

dnl Check if verbose output should be enabled
AX_COMMON_CHECK_ENABLE_VERBOSE_OUTPUT

dnl Check if debug output should be enabled
AX_COMMON_CHECK_ENABLE_DEBUG_OUTPUT

dnl Check for type definitions
AX_TYPES_CHECK_LOCAL

dnl Checks for libraries and library functions
AX_COMMON_CHECK_LOCAL

dnl Check for enabling libcerror for cross-platform C error functions
AX_LIBCERROR_CHECK_ENABLE

dnl Check for enabling libcthreads for cross-platform C threads functions
AX_LIBCTHREADS_CHECK_ENABLE

dnl Check for enabling libcdata for cross-platform C generic data functions
AX_LIBCDATA_CHECK_ENABLE

dnl Check for enabling libclocale for cross-platform C locale functions
AX_LIBCLOCALE_CHECK_ENABLE

dnl Check for enabling libcnotify for cross-platform C notification functions
AX_LIBCNOTIFY_CHECK_ENABLE

dnl Check for enabling libuna for Unicode string support
AX_LIBUNA_CHECK_ENABLE

dnl Check for enabling libcfile for cross-platform C file functions
AX_LIBCFILE_CHECK_ENABLE

dnl Check for enabling libfcrypto for encryption types support
AX_LIBFCRYPTO_CHECK_ENABLE

dnl Check if libfdatetime or required headers and functions are available
AX_LIBFDATETIME_CHECK_ENABLE

dnl Check if libfguid or required headers and functions are available
AX_LIBFGUID_CHECK_ENABLE

dnl Check if libfvalue or required headers and functions are available
AX_LIBFVALUE_CHECK_ENABLE

dnl Check for enabling libfmos for file Mac OS type support
AX_LIBFMOS_CHECK_ENABLE

dnl Check if libfplist or required headers and functions are available
AX_LIBFPLIST_CHECK_ENABLE

dnl Check if libfwevt or required headers and functions are available
AX_LIBFWEVT_CHECK_ENABLE

dnl Check for enabling libfwnt for file Windows NT type support
AX_LIBFWNT_CHECK_ENABLE

dnl Check for zlib compression support
AX_ZLIB_CHECK_ENABLE
AX_ZLIB_CHECK_ADLER32
AX_ZLIB_CHECK_COMPRESS2
AX_ZLIB_CHECK_COMPRESSBOUND
AX_ZLIB_CHECK_UNCOMPRESS

dnl Check for bz2lib compression support
AX_BZIP2_CHECK_ENABLE
AX_BZIP2_CHECK_DECOMPRESS

dnl Check if lzma or required headers and functions are available
AX_LZMA_CHECK_ENABLE

dnl Check for enabling libhmac for message digest hash function support
AX_LIBHMAC_CHECK_ENABLE

dnl Headers included in various places
AC_CHECK_HEADERS([stdarg.h varargs.h])

AS_IF(
 [test "x$ac_cv_header_stdarg_h" != xyes && test "x$ac_cv_header_varargs_h" != xyes],
 [AC_MSG_FAILURE(
  [Missing headers: stdarg.h and varargs.h],
  [1])
 ])

dnl Check if assorted tools required headers and functions are available
AX_ASSORTED_TOOLS_CHECK_LOCAL

dnl Check if tests required headers and functions are available
AX_TESTS_CHECK_LOCAL
AX_TESTS_CHECK_OSSFUZZ

dnl Set additional compiler flags
CFLAGS="$CFLAGS -Wall";

dnl Have configure make the Makefiles
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([common/Makefile])
AC_CONFIG_FILES([libcerror/Makefile])
AC_CONFIG_FILES([libcthreads/Makefile])
AC_CONFIG_FILES([libcdata/Makefile])
AC_CONFIG_FILES([libclocale/Makefile])
AC_CONFIG_FILES([libcnotify/Makefile])
AC_CONFIG_FILES([libuna/Makefile])
AC_CONFIG_FILES([libcfile/Makefile])
AC_CONFIG_FILES([libfcrypto/Makefile])
AC_CONFIG_FILES([libfdatetime/Makefile])
AC_CONFIG_FILES([libfguid/Makefile])
AC_CONFIG_FILES([libfvalue/Makefile])
AC_CONFIG_FILES([libfmos/Makefile])
AC_CONFIG_FILES([libfplist/Makefile])
AC_CONFIG_FILES([libfwevt/Makefile])
AC_CONFIG_FILES([libfwnt/Makefile])
AC_CONFIG_FILES([libhmac/Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([po/Makefile.in])
AC_CONFIG_FILES([po/Makevars])
AC_CONFIG_FILES([tests/Makefile])
AC_CONFIG_FILES([ossfuzz/Makefile])
dnl Have configure make distribution specific files
AC_CONFIG_FILES([common/types.h])
dnl Have configure write its configuration
AC_CONFIG_HEADERS([common/config.h])

AC_OUTPUT

dnl Print a summary
AC_MSG_NOTICE([
Building:
   libcerror support:                              $ac_cv_libcerror
   libcthreads support:                            $ac_cv_libcthreads
   libcdata support:                               $ac_cv_libcdata
   libclocale support:                             $ac_cv_libclocale
   libuna support:                                 $ac_cv_libuna
   libcfile support:                               $ac_cv_libcfile
   libfcrypto support:                             $ac_cv_libfcrypto
   libfdatetime support:                           $ac_cv_libfdatetime
   libfguid support:                               $ac_cv_libfguid
   libfvalue support:                              $ac_cv_libfvalue
   libfmos support:                                $ac_cv_libfmos
   libfplist support:                              $ac_cv_libfplist
   libfwevt support:                               $ac_cv_libfwevt
   libfwnt support:                                $ac_cv_libfwnt
   ADC compression support:                        $ac_cv_libfmos
   ADLER32 checksum support:                       $ac_cv_adler32
   DEFLATE compression support:                    $ac_cv_uncompress
   BZIP2 compression support:                      $ac_cv_bzip2_decompress
   LZFSE compression support:                      $ac_cv_libfmos
   LZFU compression support:                       local
   LZMA compression support:                       $ac_cv_lzma
   LZNT1 compression support:                      $ac_cv_libfwnt
   LZX compression support:                        $ac_cv_libfwnt
   LZXPRESS compression support:                   $ac_cv_libfwnt
   LZVN compression support:                       $ac_cv_libfmos
   libhmac support:                                $ac_cv_libhmac
   MD5 support:                                    $ac_cv_libhmac_md5
   SHA1 support:                                   $ac_cv_libhmac_sha1
   SHA256 support:                                 $ac_cv_libhmac_sha256

Features:
   Wide character type support:                    $ac_cv_enable_wide_character_type
   assorted tools are build as static executables: $ac_cv_enable_static_executables
   Verbose output:                                 $ac_cv_enable_verbose_output
   Debug output:                                   $ac_cv_enable_debug_output
]);

