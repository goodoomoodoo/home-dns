# ==== Begin prologue boilerplate.
all: # The canonical default target.
BUILD := debug
build_dir := ${CURDIR}
target_files := main.c
obj := ${target_files:.c=.o}
EXE_FILE = main
# ==== End prologue boilerplate.

COMPILER=gcc
CC.gcc := /bin/gcc
CC := ${CC.${COMPILER}}

# ==== Flags
CFLAGS.gcc.debug := -g -ansi 
CFLAGS.gcc := -c -pthread -march=native -Wall -fmessage-length=0 ${CXXFLAGS.gcc.${BUILD}}

CFLAGS := ${CFLAGS.${COMPILER}}

# ==== Command
COMPILE.C := ${CC} ${CFLAGS}

all: ${EXE_FILE}

${EXE_FILE}: ${obj}
	${CC} ${obj} -o ${EXE_FILE}

%.o: %.c
	${strip ${COMPILE.C}} $< -o $@

clean:
	rm -rf ${EXE_FILE} ${obj}

.PHONY: clean all
