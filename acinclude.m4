dnl Checks for required headers and functions
dnl
dnl Version: 20190317

dnl Function to detect if assorted tools dependencies are available
AC_DEFUN([AX_ASSORTED_TOOLS_CHECK_LOCAL],
  [AC_CHECK_HEADERS([math.h])

  AC_CHECK_LIB(
    m,
    log,
    [],
    [AC_MSG_FAILURE(
      [Missing function: log in library: libm.],
      1)
    ])

  dnl Check if assorted tools should be build as static executables
  AX_COMMON_CHECK_ENABLE_STATIC_EXECUTABLES
])

