#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <assert.h>
#include <error.h>
#include <sys/time.h>

typedef struct rsa_struct {
	mpz_t e; /* public key */
	mpz_t d; /* private key */
	mpz_t n; /* modulo */
} RSA;

bool miller_rabin(mpz_t n, int k) {
	mpz_t s, d, a, x;
	mpz_t n_1, n_3;
	mpz_t count;
	gmp_randstate_t rs;
	bool res = true;

	if(mpz_cmp_si(n, 3) <= 0)
		return false;

	if(mpz_odd_p(n) == 0)
		return false;

	gmp_randinit_default(rs);
	mpz_inits(s, d, a, x, n_1, n_3, count, 0);
	mpz_sub_ui(n_1, n, 1);
	mpz_sub_ui(n_3, n, 3);
	mpz_set_ui(s, 0);
	mpz_sub_ui(d, n, 1);

	/* find s and d such that n-1 = 2^s * d */
	while(mpz_even_p(d)) {
		mpz_cdiv_q_ui(d, d, 2);
		mpz_add_ui(s, s, 1);
	}

	for(; k > 0; --k) {
		mpz_urandomm(a, rs, n_3);
		mpz_add_ui(a, a, 2); /* a is random int in range 2 to n - 2 */
		mpz_powm(x, a, d, n);

		if(mpz_cmp_ui(x, 1) == 0)
			continue;

		mpz_set_ui(count, 0);
		while(mpz_cmp(count, s) < 0) {
			if(mpz_cmp(x, n_1) == 0)
				break;
			mpz_powm_ui(x, x, 2, n);
			mpz_add_ui(count, count, 1);
		}

		if(mpz_cmp(x, n_1) == 0)
			continue;

		res = false;
		break;
	}

	mpz_clear(s);
	mpz_clear(d);
	mpz_clear(a);
	mpz_clear(x);
	mpz_clear(n_1);
	mpz_clear(n_3);
	mpz_clear(count);
	gmp_randclear(rs);

	return res;
}

void euler_tot(mpz_t dest, mpz_t p, mpz_t q) {
	mpz_t p_1, q_1;

	mpz_inits(p_1, q_1, 0);
	mpz_sub_ui(p_1, p, 1);
	mpz_sub_ui(q_1, q, 1);
	mpz_mul(dest, p_1, q_1);
	mpz_clear(p_1);
	mpz_clear(q_1);
}

/*
 * gen_private_key() finds the modular multiplicative inverse of e mod tot
 * I.E. it finds d such that d*e % tot == 1
 */
void gen_private_key(mpz_t d, mpz_t e, mpz_t tot) {
	mpz_t r, t, new_r, new_t, quotient;
	mpz_t tmp_r, tmp_t;

	mpz_inits(quotient, tmp_r, tmp_t, 0);
	mpz_init_set_ui(t, 0);
	mpz_init_set_ui(new_t, 1);
	mpz_init_set(r, tot);
	mpz_init_set(new_r, e);

	while(mpz_cmp_ui(new_r, 0) != 0) {
		mpz_cdiv_q(quotient, r, new_r);
		mpz_set(tmp_r, new_r);
		mpz_set(tmp_t, new_t);
		mpz_mul(new_r, new_r, quotient);
		mpz_mul(new_t, new_t, quotient);
		mpz_sub(new_r, r, new_r);
		mpz_sub(new_t, t, new_t);
		mpz_set(r, tmp_r);
		mpz_set(t, tmp_t);
	}

	if(mpz_cmp_ui(r, 1) > 0)
		return;

	if(mpz_cmp_ui(t, 0) < 0)
		mpz_add(t, t, tot);

	mpz_set(d, t);

	mpz_clear(r);
	mpz_clear(t);
	mpz_clear(new_r);
	mpz_clear(new_t);
	mpz_clear(quotient);
	mpz_clear(tmp_r);
	mpz_clear(tmp_t);
}

#include <time.h>
void rsa_gen_keys(RSA *rsa) {
	srand(time(0));
	unsigned long seed = rand() % (1<<9) + 67;
	gmp_randstate_t rng;
	mpz_t p, q;
	mpz_t tot;
	mpz_t r, t, new_r, new_t, quotient;
	mpz_t tmp_r, tmp_t;

	mpz_inits(p, q, tot, r, t, new_r, new_t, quotient, tmp_r, tmp_t, 0);
	//mpz_inits(p, q, tot,0);
	gmp_randinit_mt(rng);
	gmp_randseed_ui(rng, seed % (1<<16));

	do {
		mpz_urandomb(p, rng, 98);
		mpz_urandomb(q, rng, 102);
		//mpz_add_ui(p, p, 0x200);
		//mpz_add_ui(q, q, 0x200);
	} while(!miller_rabin(p, 100) || !miller_rabin(q, 100));
	gmp_printf("p = %Zd\nq = %Zd\n", p, q);

	mpz_mul(rsa->n, p, q);
	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
	mpz_mul(tot, p, q);
	mpz_clear(p);
	mpz_clear(q);

	do {
		mpz_urandomb(rsa->e, rng, 8);
	} while(!miller_rabin(rsa->e, 100));
	//mpz_set_ui(rsa->e, 167);

	gmp_printf("e = %Zd\n", rsa->e);

	/* generate private key */
	//gen_private_key(rsa->d, rsa->e, tot);

	mpz_set_ui(t, 0);
	mpz_set_ui(new_t, 1);
	mpz_set(r, tot);
	mpz_set(new_r, rsa->e);

	while(mpz_cmp_ui(new_r, 0) != 0) {
		mpz_cdiv_q(quotient, r, new_r);
		mpz_set(tmp_r, new_r);
		mpz_set(tmp_t, new_t);
		mpz_mul(new_r, new_r, quotient);
		mpz_mul(new_t, new_t, quotient);
		mpz_sub(new_r, r, new_r);
		mpz_sub(new_t, t, new_t);
		mpz_set(r, tmp_r);
		mpz_set(t, tmp_t);
	}

	if(mpz_cmp_ui(r, 1) <= 0) {
		if(mpz_cmp_ui(t, 0) < 0)
			mpz_add(t, t, tot);

		mpz_set(rsa->d, t);
	} else {
		mpz_t tmp, priv;

		mpz_init(tmp);
		mpz_init_set(priv, rsa->e);

		while(true) {
			mpz_mul(tmp, priv, rsa->e);
			mpz_mod(tmp, tmp, tot);
			if(mpz_cmp_ui(tmp, 1) == 0)
				break;
			mpz_add_ui(priv, priv, 1);
		}

		mpz_set(rsa->d, priv);
		mpz_clear(tmp);
		mpz_clear(priv);
	}

	gmp_printf("d = %Zd\n", rsa->d);

	mpz_clear(r);
	mpz_clear(t);
	mpz_clear(new_r);
	mpz_clear(new_t);
	mpz_clear(quotient);
	mpz_clear(tmp_r);
	mpz_clear(tmp_t);
	mpz_clear(tot);
}

/* NOTE message must be less than n */
/*
 * TODO
 * randomly generate p and q
 * randomly generate e
 */

#define BLOCKSIZE 16
void rsa_encrypt(RSA *rsa, FILE *inp, FILE *outp) {
	size_t n;
	char buf1[BLOCKSIZE], buf2[BLOCKSIZE<<1];
	mpz_t m;

	mpz_init(m);

	while((n = fread(buf1, 1, sizeof(buf1), inp)) > 0) {
		for(size_t i = n; i < sizeof(buf1); buf1[i++] = 0);
		mpz_import(m, 1, -1, sizeof(buf1), -1, 0, buf1);
		mpz_powm(m, m, rsa->e, rsa->n);
		mpz_export(buf2, &n, -1, sizeof(buf2), -1, 0, m);
		fwrite(buf2, 1, sizeof(buf2), outp);
	}

	mpz_clear(m);
}

void rsa_decrypt(RSA *rsa, FILE *inp, FILE *outp) {
	size_t n;
	char buf1[BLOCKSIZE<<1], buf2[BLOCKSIZE];
	mpz_t c;

	mpz_init(c);

	while((n = fread(buf1, 1, sizeof(buf1), inp)) > 0) {
		for(size_t i = n; i < sizeof(buf1); buf1[i++] = 0);
		mpz_import(c, sizeof(buf1), -1, 1, -1, 0, buf1);
		mpz_powm(c, c, rsa->d, rsa->n);
		mpz_export(buf2, &n, -1, 1, -1, 0, c);
		fwrite(buf2, 1, n, outp);
	}

	mpz_clear(c);
}

int main(void) {
	//mpz_t p, q;
	//mpz_t e, tot;
	//mpz_t d;
	//mpz_t n;
	//mpz_t tmp;
	//bool isprime;

	//struct timeval start, stop;
	//double t;

	//mpz_init(tmp);
	//mpz_inits(e, tot, d, n, 0);
	//mpz_init_set_str(p, "244758923712231307864815224347", 10);
	//mpz_init_set_str(q, "652551178654081356640243276091", 10);
	//isprime = miller_rabin(p, 100);
	//gmp_printf("p = %Zd %s prime\n", p, isprime ? "is probably" : "is not");
	//isprime = miller_rabin(q, 100);
	//gmp_printf("q = %Zd %s prime\n", q, isprime ? "is probably" : "is not");
	//euler_tot(tot, p, q);
	//gmp_printf("totient(p, q) = %Zd\n", tot);
	//mpz_init_set_ui(e, 167);
	//isprime = miller_rabin(e, 100);
	//gmp_printf("e = %Zd %s prime\n", e, isprime ? "is probably" : "is not");
	//mpz_init(d);
	//mpz_gcd(tmp, e, tot);
	//gmp_printf("gcd(e, tot) = %Zd\n", tmp);

	//mpz_set_ui(d, 0);
	//printf("########## test modular inverse algorithm ##########\n");

	//gettimeofday(&start, 0);
	//gen_private_key(d, e, tot);
	//gettimeofday(&stop, 0);
	//t = (double)(stop.tv_sec - start.tv_sec) * 1000.0f + (double)(stop.tv_usec - start.tv_usec);
	//printf("gen_private_key: %.2fms\n", t);

	//gmp_printf("d = %Zd\n", d);
	//mpz_mul(tmp, d, e);
	//mpz_mod(tmp, tmp, tot);
	//assert(mpz_cmp_ui(tmp, 1) == 0);
	//gmp_printf("d*e %% tot = %Zd\n", tmp);

	RSA rsa;
	mpz_inits(rsa.e, rsa.d, rsa.n, 0);
	rsa_gen_keys(&rsa);
//	mpz_t a, b, c;
//	mpz_inits(a,b,c,0);
//	mpz_set_str(a, "99064193639041831239", 10);
//	gmp_printf("a = %Zd\n", a);
//	mpz_powm(b, a, rsa.e, rsa.n);
//	gmp_printf("b = %Zd\n", b);
//	printf("bitlen(b) = %zu\n", mpz_sizeinbase(b, 2));
//	mpz_powm(c, b, rsa.d, rsa.n);
//	gmp_printf("c = %Zd\n", c);
//	mpz_clear(a);
//	mpz_clear(b);
//	mpz_clear(c);
	//mpz_set(rsa.e, e);
	//mpz_set(rsa.d, d);
	//mpz_mul(rsa.n, p, q);
	//gmp_printf("rsa.e = %Zd, rsa.d = %Zd, rsa.n = %Zd\n", rsa.e, rsa.d, rsa.n);
	FILE *inp, *outp;
	inp = fopen("rsa.c", "r");
	outp = fopen("encrypted", "wb");

	rsa_encrypt(&rsa, inp, outp);

	fclose(inp);
	fclose(outp);

	inp = fopen("encrypted", "rb");
	outp = fopen("decrypted", "w");

	rsa_decrypt(&rsa, inp, outp);

	fclose(inp);
	fclose(outp);

	mpz_clear(rsa.e);
	mpz_clear(rsa.d);
	mpz_clear(rsa.n);

	//mpz_clear(p);
	//mpz_clear(q);
	//mpz_clear(e);
	//mpz_clear(tot);
	//mpz_clear(d);
	//mpz_clear(tmp);
	//mpz_clear(n);
	return 0;
}
