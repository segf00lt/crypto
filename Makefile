CFLAGS = -Wall -Werror -Wpedantic -g
LDFLAGS = -lgmp

all: enigma rsa

enigma:
	$(CC) $(CFLAGS) enigma.c -o enigma
rsa:
	$(CC) $(CFLAGS) $(LDFLAGS) rsa.c -o rsa
test: all
	./test.sh
clean:
	rm -f enigma rsa

.PHONY: all test rsa enigma
