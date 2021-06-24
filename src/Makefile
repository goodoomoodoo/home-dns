# ==== Begin prologue boilerplate.
all: # The canonical default target.
BUILD := debug

target_files := main.c dns.c
BIN_DIR := ${CURDIR}/../bin

OBJ := ${patsubst %,${BIN_DIR}/%,${target_files:.c=.o}}
DEP := ${patsubst %.o,%.d,${OBJ}}
EXE_FILE = ${BIN_DIR}/main
# ==== End prologue boilerplate.

COMPILER=gcc
CC.gcc := /bin/gcc
CC := ${CC.${COMPILER}}

# ==== Flags
CFLAGS.gcc.debug := -g -ansi 
CFLAGS.gcc := -c -pthread -march=native -Wall ${CXXFLAGS.gcc.${BUILD}} -MD

CFLAGS := ${CFLAGS.${COMPILER}}

# ==== Command
COMPILE.C := ${CC} ${CFLAGS}

all: directories ${EXE_FILE}

directories: ${BIN_DIR}

${BIN_DIR}:
	mkdir -p ${BIN_DIR}

${EXE_FILE}: ${OBJ}
	${CC} ${OBJ} -o ${EXE_FILE}

${BIN_DIR}/%.o: %.c
	${strip ${COMPILE.C}} $< -o $@

${DEP}: %.d : %.c
	${CC} -MM ${CFLAGS} $< > $@

-include ${DEP}

clean:
	rm -rf ${BIN_DIR}

.PHONY: clean all directories
