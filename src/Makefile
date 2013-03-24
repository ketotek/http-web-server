
CFLAGS=-Wall -ggdb
LDFLAGS=-laio -lbsd

all: server

server: server.o http.o sock.o

.PHONY: clean
clean:
	rm *.o server test

