# Initialize Autoconf
AC_INIT([minimal-ws-server], [1.0], [youremail@example.com])
AC_PREREQ([2.69])

# Initialize Automake
AM_INIT_AUTOMAKE([foreign])

# Check for the C compiler
AC_PROG_CC

# Check for the C++ compiler
AC_PROG_CXX

# Check for pkg-config
AC_PATH_PROG([PKG_CONFIG], [pkg-config], [no])
if test "$PKG_CONFIG" = "no"; then
  AC_MSG_ERROR([pkg-config is required but was not found])
fi

# Check for libwebsockets using pkg-config
PKG_CHECK_MODULES([LIBWEBSOCKETS], [libwebsockets >= 4.0],
  [],
  [AC_MSG_ERROR([libwebsockets >= 4.0 is required but was not found.])])

# Substitute the pkg-config variables into the Makefile
AC_SUBST([LIBWEBSOCKETS_CFLAGS])
AC_SUBST([LIBWEBSOCKETS_LIBS])

# Generate Makefile
AC_CONFIG_FILES([Makefile])
AC_OUTPUT