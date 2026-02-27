CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDFLAGS ?=

TARGET := awdog-saver
SBINDIR ?= /sbin

.PHONY: all clean install
.PHONY: test

all: $(TARGET)

$(TARGET): awdog-saver.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: $(TARGET)
	install -D -m 0755 $(TARGET) "$(DESTDIR)$(SBINDIR)/$(TARGET)"

test: $(TARGET)
	sh tests/test_awdog_saver.sh ./$(TARGET)

clean:
	rm -f $(TARGET)
