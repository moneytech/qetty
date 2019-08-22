# Globals and files to compile.
EXE    := qetty
SOURCE := $(shell find . -type f -name '*.c')
OBJ    := $(SOURCE:.c=.o)

# User options.
PREFIX  = /sbin
DESTDIR =

CC = gcc

CFLAGS  = -O2 -pipe -Wall -Wextra
LDFLAGS = -O2

CHARDFLAGS  := $(CFLAGS) -masm=intel -I.
LDHARDFLAGS := $(LDFLAGS)

.PHONY: all clean install

all: $(OBJ)
	$(CC) $(OBJ) $(LDHARDFLAGS) -o $(EXE)

%.o: %.c
	$(CC) $(CHARDFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXE)

install:
	mkdir -p $(DESTDIR)$(PREFIX)
	cp $(EXE) $(DESTDIR)$(PREFIX)/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/$(EXE)
