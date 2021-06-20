# ==== Begin prologue boilerplate.
all: # The canonical default target.
BUILD := debug
build_dir := ${CURDIR}
exes := # Executables to build.
# ==== End prologue boilerplate.

COMPILER=gcc
CC.gcc := /bin/gcc
CC := ${CC.${COMPILER}}

# ==== Flags
CFLAGS.gcc.debug := -g -ansi 
CFLAGS.gcc := -pthread -march=native -Wall -fmessage-length=0 ${CXXFLAGS.gcc.${BUILD}}

CFLAGS := ${CFLAGS.${COMPILER}}

# ==== Command
COMPILE.C := ${CC} ${CFLAGS}

all: main

main:
	${strip ${COMPILE.C}} main.c -o main

clean:
	rm -rf main

.PHONY: clean all