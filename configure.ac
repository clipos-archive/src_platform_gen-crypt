# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.
dnl Process this file with autoconf to produce a configure script.
AC_INIT(src/check.c)

dnl Checks for programs.
AC_PROG_CC

dnl Set some flags by default
[
if test "x$GCC" = "xyes"; then
  CFLAGS="$CFLAGS -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes"
  CFLAGS+=" -Wcast-qual -Wcast-align -Wpointer-arith -Wnested-externs"
  CFLAGS+=" -Wconversion -Wwrite-strings"
  CFLAGS+=" -pipe -O2 -std=gnu99"
  LDFLAGS="$LDFLAGS -Wl,-z,now -Wl,-z,relro -lutil"
fi
]

dnl Check for sign option
AC_ARG_ENABLE(sign,
   AC_HELP_STRING([--enable-sign], [build signing tool]),
     [with_sign=$enableval], [with_sign=no])
AC_SUBST(with_sign)

dnl Check for crypto option
AC_ARG_WITH(crypto,
  AC_HELP_STRING([--with-crypto=(civil)],
    [select 'civil' crypto (default: civil)]),
    [crypto=$withval], [crypto=civil])
AC_SUBST(crypto)

dnl Check for test option
AC_ARG_ENABLE(testing,
   AC_HELP_STRING([--enable-testing], [enables testing features]),
     [with_test=$enableval], [with_test=no])
AC_SUBST(with_test)

dnl Check for code coverage option
AC_ARG_ENABLE(coverage,
   AC_HELP_STRING([--enable-coverage], [enables gcov code coverage compilation flags]),
     [with_coverage=$enableval], [with_coverage=no])
AC_SUBST(with_coverage)


dnl Check for dependencies
if test -z "$PKG_CONFIG"; then
  PKG_CONFIG=pkg-config
fi
AC_SUBST(PKG_CONFIG)

AC_MSG_CHECKING(that pkg-config runs)
if "$PKG_CONFIG" --version > /dev/null 2>&1 ; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
  AC_MSG_ERROR([*** $PKG_CONFIG missing ***

\'$PKG_CONFIG --version\' failed to run - make sure it is inside one of the
directories in your PATH environment variable!

pkg-config comes with the developement packages for GTK+-2.2, available at:
http://www.gtk.org])
fi


AC_DEFUN([BUILD_DEPENDS], [
AC_MSG_CHECKING(that $1 (version >= $2) is installed)
if "$PKG_CONFIG" --atleast-version=$2 $1 ; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
  if "$PKG_CONFIG" --exists $1 ; then
    ERRSTR=`"$PKG_CONFIG"  --modversion $1`
    AC_MSG_ERROR(Current version is only $ERRSTR)
  else
    AC_MSG_ERROR(Package is not installed)
  fi
fi
])

BUILD_DEPENDS(clip, 1.2.14)

dnl Checks for header files.
AC_HEADER_STDC

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

dnl Checks for library functions.

AC_OUTPUT(Makefile)
