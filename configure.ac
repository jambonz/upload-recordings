# Initialize Autoconf
AC_INIT([upload_recordings], [1.0], [youremail@example.com])
AC_PREREQ([2.69])

# Define required macros
m4_pattern_allow([AC_MSG_ERROR])
m4_pattern_allow([PKG_CHECK_MODULES])

# Initialize Automake
AM_INIT_AUTOMAKE([foreign])

# Add macro directory
AC_CONFIG_MACRO_DIRS([m4])

# Check for the C compiler
AC_PROG_CC

# Check for the C++ compiler
AC_PROG_CXX

# Check for pkg-config
AC_PATH_PROG([PKG_CONFIG], [pkg-config], [no])
if test "$PKG_CONFIG" = "no"; then
  AC_MSG_ERROR([pkg-config is required but was not found])
fi

# Initialize pkg-config
PKG_PROG_PKG_CONFIG

# Check for libwebsockets using pkg-config
PKG_CHECK_MODULES([LIBWEBSOCKETS], [libwebsockets >= 4.0],
  [],
  [AC_MSG_ERROR([libwebsockets >= 4.0 is required but was not found.])])

# Check for libcurl using pkg-config
PKG_CHECK_MODULES([LIBCURL], [libcurl >= 7.0],
  [],
  [AC_MSG_ERROR([libcurl >= 7.0 is required but was not found.])])

# Check for Boost
AX_BOOST_BASE([1.66], [], [AC_MSG_ERROR([Boost is required but was not found.])])
AX_BOOST_SYSTEM
AX_BOOST_THREAD

# We don't need a separate check for Boost.Asio as it's header-only
# and is included in the standard Boost distribution that we've already checked for

# optional linking with tcmalloc
AC_ARG_ENABLE([tcmalloc],
[  --enable-tcmalloc    Link with tcmalloc (requires libgoogle-perftools-dev)],
[case "${enableval}" in
  yes) tcmalloc=true ;;
  no)  tcmalloc=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-tcmalloc]) ;;
esac],[tcmalloc=false])
AM_CONDITIONAL([TCMALLOC], [test x$tcmalloc = xtrue])

# Substitute the pkg-config variables into the Makefile
AC_SUBST([LIBWEBSOCKETS_CFLAGS])
AC_SUBST([LIBWEBSOCKETS_LIBS])
AC_SUBST([LIBCURL_CFLAGS])
AC_SUBST([LIBCURL_LIBS])

# Generate Makefile
AC_CONFIG_FILES([Makefile])
AC_OUTPUT