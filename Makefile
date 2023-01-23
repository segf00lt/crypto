CFLAGS = -Wall -Werror -Wpedantic -g
LDFLAGS = -lgmp

all:
	$(CC) $(CFLAGS) $(LDFLAGS) rsa.c -o rsa

.PHONY: all
