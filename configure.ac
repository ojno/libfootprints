AC_CONFIG_MACRO_DIR([m4])
AC_PREREQ([2.69])
AC_INIT([libfootprints], [0.1], [jf451@cl.cam.ac.uk])
AC_CONFIG_SRCDIR([src/test_footprints.c])

CFLAGS="-I$prefix/include $CFLAGS"
CXXFLAGS="-I$prefix/include $CXXFLAGS"
CPPFLAGS="-I$prefix/include $CPPFLAGS"
LDFLAGS="-L$prefix/lib $LDFLAGS"
PKG_CONFIG_PATH="$prefix/lib/pkgconfig:$PKG_CONFIG_PATH"
export CFLAGS CXXFLAGS LDFLAGS PKG_CONFIG_PATH

LT_INIT
AC_LANG([C])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wno-portability])
AM_MAINTAINER_MODE
AC_PROG_CC

AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_PROG_LN_S
AC_PROG_INSTALL

AC_CHECK_HEADERS([asm/fcntl.h asm/posix_types.h asm/types.h assert.h elf.h link.h stdarg.h stdlib.h string.h sys/mman.h sys/syscall.h sys/types.h unistd.h], [], [AC_MSG_FAILURE([required standard headers: asm/fcntl.h asm/posix_types.h asm/types.h assert.h elf.h link.h stdarg.h stdlib.h string.h sys/mman.h sys/syscall.h sys/types.h unistd.h])])

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([DWARFIDL], [dwarfidl])
PKG_CHECK_MODULES([LIBALLOCS], [liballocs])

AC_CONFIG_FILES([Makefile libfootprints.pc])
AC_OUTPUT
