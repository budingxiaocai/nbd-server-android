CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wshadow -Wconversion -Wstrict-prototypes
LDFLAGS ?=

TARGET := nbd-server-android

.PHONY: all clean

all: $(TARGET)

$(TARGET): nbd-server.c
	$(CC) $(CFLAGS) -D_FILE_OFFSET_BITS=64 -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
