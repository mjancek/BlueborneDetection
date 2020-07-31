CC = gcc
CFLAGS = -Wall -Wextra -pedantic -g
LDFLAGS = -lbluetooth
SHELL = /bin/bash

all: detectBlueborne

debug: CFLAGS += -DDEBUG
debug: detectBlueborne

detectBlueborne: detectBlueborne.o

detectBlueborne.o: detectBlueborne.c

clean:
	-rm -f *.o detectBlueborne

