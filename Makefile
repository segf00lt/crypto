CFLAGS = -Wall -Werror -Wpedantic
LDFLAGS = -lgmp

all:
	$(CC) $(CFLAGS) $(LDFLAGS) rsa.c -o rsa

.PHONY: all
