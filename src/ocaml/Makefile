LIBDIR ?= /home/jf451/prefix/lib

default: ocaml_test_syscalls.native

-include config.mk

.PHONY: make-ctypes
make-ctypes:
	$(MAKE) -C ocaml-ctypes

.PHONY: ocaml_test_syscalls.native
ocaml_test_syscalls.native: make-ctypes
	ocamlbuild ocaml_test_syscalls.native \
		-cflags -thread \
		-I ocaml-bytes \
		-I ocaml-ctypes/src/ctypes-top \
		-I ocaml-ctypes/src/ctypes-foreign-unthreaded \
		-I ocaml-ctypes/src/cstubs \
		-I ocaml-ctypes/src/ctypes-foreign-threaded \
		-I ocaml-ctypes/src/ctypes-foreign-base \
		-I ocaml-ctypes/src/libffi-abigen \
		-I ocaml-ctypes/src/ctypes \
		-lflags -cclib,-Xlinker -lflags -cclib,--no-as-needed \
		-lflags -cclib,-L${LIBDIR} -lflags -cclib,-L$(shell pwd)/ocaml-ctypes/_build \
		-lflags -cclib,-lfootprints -lflags -cclib,-lfootprints_syscalls \
		-tag thread -lib bigarray -lib str -lib unix \
		-lflags -cclib,-lctypes_stubs -lflags -cclib,-lctypes-foreign-base_stubs -lflags -cclib,-lffi \
		-lflags -linkall
