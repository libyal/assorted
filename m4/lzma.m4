dnl Checks for lzma required headers and functions
dnl
dnl Version: 20210404

dnl Function to detect if lzma is available
AC_DEFUN([AX_LZMA_CHECK_LIB],
  [AS_IF(
    [test "x$ac_cv_enable_shared_libs" = xno || test "x$ac_cv_with_lzma" = xno],
    [ac_cv_lzma=no],
    [ac_cv_lzma=check
    dnl Check if the directory provided as parameter exists
    AS_IF(
      [test "x$ac_cv_with_lzma" != x && test "x$ac_cv_with_lzma" != xauto-detect],
      [AS_IF(
        [test -d "$ac_cv_with_lzma"],
        [CFLAGS="$CFLAGS -I${ac_cv_with_lzma}/include"
        LDFLAGS="$LDFLAGS -L${ac_cv_with_lzma}/lib"],
        [AC_MSG_FAILURE(
          [no such directory: $ac_cv_with_lzma],
          [1])
        ])
      ],
      [dnl Check for a pkg-config file
      AS_IF(
        [test "x$cross_compiling" != "xyes" && test "x$PKGCONFIG" != "x"],
        [PKG_CHECK_MODULES(
          [liblzma],
          [liblzma >= 5.2.5],
          [ac_cv_lzma=liblzma],
          [ac_cv_lzma=check])
        ])
      AS_IF(
        [test "x$ac_cv_lzma" = xliblzma],
        [ac_cv_lzma_CPPFLAGS="$pkg_cv_liblzma_CFLAGS"
        ac_cv_lzma_LIBADD="$pkg_cv_liblzma_LIBS"])
      ])

    AS_IF(
      [test "x$ac_cv_lzma" = xcheck],
      [dnl Check for headers
      AC_CHECK_HEADERS([lzma.h])

      AS_IF(
        [test "x$ac_cv_header_lzma_h" = xno],
        [ac_cv_lzma=no],
        [dnl Check for the individual functions
        ac_cv_lzma=liblzma

        AC_CHECK_LIB(
          lzma,
          lzma_version_number,
          [],
          [ac_cv_lzma=no])

        AS_IF(
          [test "x$ac_cv_lib_lzma_lzma_version_number" = xno],
          [AC_MSG_FAILURE(
            [Missing function: lzma_version_number in library: lzma.],
            [1])
          ])

        ac_cv_lzma_LIBADD="-llzma";
        ])
      ])
    ])

  AS_IF(
    [test "x$ac_cv_lzma" = xliblzma],
    [AC_DEFINE(
      [HAVE_LIBLZMA],
      [1],
      [Define to 1 if you have the 'lzma' library (-llzma).])
    ])

  AS_IF(
    [test "x$ac_cv_lzma" != xno],
    [AC_SUBST(
      [HAVE_LIBLZMA],
      [1]) ],
    [AC_SUBST(
      [HAVE_LIBLZMA],
      [0])
    ])
  ])

dnl Function to detect if the lzma_code function is available
AC_DEFUN([AX_LZMA_CHECK_DECOMPRESS],
  [AS_IF(
    [test "x$ac_cv_lzma" != xliblzma],
    [ac_cv_lzma_decompress=local],
    [AC_CHECK_LIB(
      lzma,
      lzma_code,
      [ac_cv_lzma_decompress=liblzma],
      [ac_cv_lzma_decompress=local])

    AS_IF(
      [test "x$ac_cv_lzma_decompress" = xliblzma],
      [AC_DEFINE(
        [HAVE_LZMA_DECOMPRESS],
        [1],
        [Define to 1 if you have the `lzma_code' function.])
      ])
    ])
  ])

dnl Function to detect how to enable lzma
AC_DEFUN([AX_LZMA_CHECK_ENABLE],
  [AX_COMMON_ARG_WITH(
    [lzma],
    [lzma],
    [search for lzma in includedir and libdir or in the specified DIR, or no if not to use lzma],
    [auto-detect],
    [DIR])

  dnl Check for a shared library version
  AX_LZMA_CHECK_LIB

  AS_IF(
    [test "x$ac_cv_lzma_CPPFLAGS" != "x"],
    [AC_SUBST(
      [LZMA_CPPFLAGS],
      [$ac_cv_lzma_CPPFLAGS])
    ])
  AS_IF(
    [test "x$ac_cv_lzma_LIBADD" != "x"],
    [AC_SUBST(
      [LZMA_LIBADD],
      [$ac_cv_lzma_LIBADD])
    ])

  AS_IF(
    [test "x$ac_cv_lzma" = xliblzma],
    [AC_SUBST(
      [ax_lzma_pc_libs_private],
      [-llzma])
    ])

  AS_IF(
    [test "x$ac_cv_lzma" = xliblzma],
    [AC_SUBST(
      [ax_lzma_spec_requires],
      [xz-libs])
    AC_SUBST(
      [ax_lzma_spec_build_requires],
      [xz-devel])
    AC_SUBST(
      [ax_lzma_static_spec_requires],
      [xz-static])
    AC_SUBST(
      [ax_lzma_static_spec_build_requires],
      [xz-static])
    ])
  ])

