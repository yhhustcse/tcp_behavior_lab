CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDLIBS ?= -lpcap -lcrypto -lz

BIN := ftp_reassemble_info
SRC := ftp_reassemble_info.c

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(BIN) *.o

.PHONY: all clean
