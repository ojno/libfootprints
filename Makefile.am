ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -std=gnu99 -ggdb -O0 -Iinclude -Isrc -fPIC -DPIC -Wall  -Wno-unused-variable -Wno-unused-but-set-variable -Werror -ffreestanding -fno-omit-frame-pointer $(LIBALLOCS_CFLAGS) $(DWARFIDL_CFLAGS)
AM_LDFLAGS = $(LIBALLOCS_LIBS) $(DWARFIDL_LIBS) -lantlr3c -ldl

extra_DIST = libfootprints.pc.in
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libfootprints.pc

libfootprints_includedir = $(includedir)/libfootprints
libfootprints_include_HEADERS = include/footprints.h include/footprints_enums.h include/footprints_types.h include/footprints_funcs.h include/perform_syscall.h

noinst_PROGRAMS = src/test_footprints src/test_syscalls

src_test_footprints_SOURCES = src/test_footprints.c
src_test_footprints_LDADD = src/libfootprints.la

src_test_syscalls_SOURCES = src/test_syscalls.c 
src_test_syscalls_LDADD = src/libfootprints.la src/libfootprints_syscalls.la
src_test_syscalls_DEPENDENCIES = src/libfootprints.la src/libfootprints_syscalls.la

src/dynamic-list: src/linux-syscall-ifacetypes.o
	( echo '{'; nm --format=posix "$<" | sed 's/[[:blank:]].*/;/'; echo '};') > "$@" || rm -f "$@"

lib_LTLIBRARIES = src/libfootprints.la src/libfootprints_syscalls.la
src_libfootprints_la_SOURCES = src/binary_ops.c src/eval.c src/footprints.c src/parser.c src/subscripts.c src/unary_ops.c src/values.c src/control_flow.c src/exprs.c src/idents.c src/objects.c src/printer.c src/unions.c src/linux-syscall-ifacetypes.c
src_libfootprints_la_LDFLAGS = $(AM_LDFLAGS) -Wl,--hash-style=sysv -Wl,--dynamic-list,src/dynamic-list -Wl,--version-script,src/version-script
src_libfootprints_la_DEPENDENCIES = src/dynamic-list

src_libfootprints_syscalls_la_SOURCES = src/perform_syscall.c
src_libfootprints_syscalls_la_LIBADD = src/libfootprints.la
src_libfootprints_syscalls_la_DEPENDENCIES = src/libfootprints.la src/dynamic-list
