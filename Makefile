SUBDIRS := src

all: ${SUBDIRS}
${SUBDIRS}:
	${MAKE} -C $@

clean:
	rm -rf bin

.PHONY: all ${SUBDIRS} clean