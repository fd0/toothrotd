-include config.mk

CFLAGS += -g -Wall -std=gnu99 -O2
LDFLAGS += -lpcap

ifeq ($(DEBUG),1)
	CFLAGS += -Wall -W -Wchar-subscripts -Wmissing-prototypes
	CFLAGS += -Wmissing-declarations -Wredundant-decls
	CFLAGS += -Wstrict-prototypes -Wshadow -Wbad-function-cast
	CFLAGS += -Winline -Wpointer-arith -Wsign-compare
	CFLAGS += -Wunreachable-code -Wdisabled-optimization
	CFLAGS += -Wcast-align -Wwrite-strings -Wnested-externs -Wundef
	CFLAGS += -DDEBUG
endif

MAIN=toothrotd
FILES=$(wildcard *.c)
HEADERS=$(wildcard *.h)
OBJECTS=$(patsubst %.c,%.o,$(FILES))

.PHONY: all clean install

all: $(MAIN)

$(MAIN): $(OBJECTS) version.h

version.h:
	@echo "#define VERSION \"$(shell git describe)\"" > version.h

clean:
	rm -f $(MAIN) *.o
