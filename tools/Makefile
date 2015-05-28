CC = gcc
CPP= g++
AS = nasm
CFLAGS = -Wall
LDFLAGS = -lelf
ASFLAGS = -f bin
SRC = elfinject.c generate_inject.c
BIN = elfinject generate_inject

.PHONY: all clean

all: elfinject generate_inject

elfinject : elfinject.c
	$(CC) $(CFLAGS) -o elfinject elfinject.c $(LDFLAGS)

generate_inject : generate_inject.cpp
	$(CPP) $(CFLAGS) -o generate_inject generate_inject.cpp $(LDFLAGS)

clean:
	rm -f $(BIN)

