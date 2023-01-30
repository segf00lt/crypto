#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>

#define WHEELSIZE 26
#define MESSAGESIZE 256

char cipher1[WHEELSIZE] = {'E','T','F','N','Q','Y','H','L','O','K','U','Z','M','G','X','S','P','V','C','J','W','B','I','D','A','R'};
char cipher2[WHEELSIZE] = {'H','P','C','A','M','Q','E','Z','R','W','Y','J','S','G','B','I','V','L','X','O','U','F','N','D','T','K'};
char cipher3[WHEELSIZE] = {'Y','P','N','T','C','B','X','I','Z','U','V','W','M','Q','E','O','R','G','D','L','K','F','H','A','S','J'};

char message[MESSAGESIZE];
char ciphertext[MESSAGESIZE];
char decrypted_ciphertext[MESSAGESIZE];

typedef struct {
	char cipher[WHEELSIZE];
	int cur;
} Wheel;

void wheel_init(Wheel *w, char cipher[WHEELSIZE]) {
	for(int i = 0; i < WHEELSIZE; ++i)
		w->cipher[i] = cipher[i];
	w->cur = 0;
}

bool wheel_advance(Wheel *w) {
	++w->cur;
	w->cur %= WHEELSIZE;

	return w->cur == 0;
}

char wheel_encrypt(Wheel *w, char c) {
	int i = (int)(c - 'A');

	return w->cipher[i];
}

char wheel_decrypt(Wheel *w, char c) {
	int i = 0;

	for(; i < WHEELSIZE && w->cipher[i] != c; ++i);

	return (char)(i + 'A');
}

int main(void) {
	char c0, c1, c2, c3;
	int i, j;
	bool turn_round2 = false;

	Wheel round1; wheel_init(&round1, cipher1);
	Wheel round2; wheel_init(&round2, cipher2);
	Wheel round3; wheel_init(&round3, cipher3);

	printf("Enter message: ");
	fgets(message, MESSAGESIZE, stdin);
	printf("\n");

	/* encrypt */
	for(i = 0, j = 0; i < MESSAGESIZE && message[i]; ++i) {
		c0 = toupper(message[i]);

		if(!isupper(c0))
			continue;

		c1 = wheel_encrypt(&round1, c0);

		if(wheel_advance(&round1))
			turn_round2 = wheel_advance(&round2);

		c2 = wheel_encrypt(&round2, c1);

		if(turn_round2)
			wheel_advance(&round3);

		c3 = wheel_encrypt(&round3, c2);

		ciphertext[j++] = c3;
	}

	ciphertext[j] = 0;
	round1.cur = round2.cur = round3.cur = 0;
	turn_round2 = false;

	/* decrypt */
	for(i = 0; i < MESSAGESIZE && ciphertext[i]; ++i) {
		c0 = ciphertext[i];
		c3 = wheel_decrypt(&round3, c0);

		if(wheel_advance(&round3))
			turn_round2 = wheel_advance(&round2);

		c2 = wheel_decrypt(&round2, c3);

		if(turn_round2)
			wheel_advance(&round1);

		c1 = wheel_decrypt(&round1, c2);

		decrypted_ciphertext[i] = c1;
	}

	printf("Message:\n%s\nCiphertext:\n%s\n\nDecrypted Ciphertext:\n%s\n\n",
			message, ciphertext, decrypted_ciphertext);

	return 0;
}
