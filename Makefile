# ==== Begin prologue boilerplate.
all: # The canonical default target.
BUILD := debug
build_dir := ${CURDIR}
target_files := main.c dns.c
OBJ := ${target_files:.c=.o}
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

${EXE_FILE}: ${OBJ}
	${CC} ${OBJ} -o ${EXE_FILE}

%.o: %.c %.h
	${strip ${COMPILE.C}} $< -o $@

clean:
	rm -rf ${EXE_FILE} ${OBJ}

.PHONY: clean all
