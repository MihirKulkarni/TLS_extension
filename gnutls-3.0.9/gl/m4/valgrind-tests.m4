# valgrind-tests.m4 serial 2
dnl Copyright (C) 2008-2011 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl From Simon Josefsson

# gl_VALGRIND_TESTS()
# -------------------
# Check if valgrind is available, and set VALGRIND to it if available.
AC_DEFUN([gl_VALGRIND_TESTS],
[
  AC_ARG_ENABLE(valgrind-tests,
    AS_HELP_STRING([--enable-valgrind-tests],
                   [run self tests under valgrind]),
    [opt_valgrind_tests=$enableval], [opt_valgrind_tests=yes])

  # Run self-tests under valgrind?
  if test "$opt_valgrind_tests" = "yes" && test "$cross_compiling" = no; then
    AC_CHECK_PROGS(VALGRIND, valgrind)
  fi

  if test -n "$VALGRIND" && $VALGRIND -q true > /dev/null 2>&1; then
    opt_valgrind_tests=yes
    VALGRIND="$VALGRIND -q --error-exitcode=1 --suppressions=suppressions.valgrind"
  else
    opt_valgrind_tests=no
    VALGRIND=
  fi

  AC_MSG_CHECKING([whether self tests are run under valgrind])
  AC_MSG_RESULT($opt_valgrind_tests)
])
