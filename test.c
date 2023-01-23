#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <limits.h>
#include <gmp.h>

int main(void) {
        /* data */
        int p = 61;
        int q = 53;
        size_t e = (1 << 16) + 1; /* public exponent */
        size_t d;      /* private exponent not given */
        int msg = 123; /* message to be encrypted */
        printf("==============\n");
        printf("DATA\n");
        printf("==============\n");
        printf("int p = %d\n", p);
        printf("int q = %d\n", q);
        printf("int e = %ld\n", e);
        printf("int msg = %d\n\n", msg);

        /* compute modulo n */
        int n = p*q;
        printf("=========================\n");
        printf("1 - Compute n = p * q\n");
        printf("=========================\n");
        printf("n = %d\n\n", n);

        /* compute totient Euler function */
        printf("==========================================================\n");
        printf("2 - Compute totient Euler function phi(n) = (p-1)(q-1)\n");
        printf("==========================================================\n");
        int phi = (p-1) * (q-1);
        printf("totient = %d\n\n", phi);

        /* compute d private exponent */
        printf("==========================================================\n");
        printf("3 - Compute d private exponent d*e mod(phi(n)) = 1\n");
        printf("==========================================================\n");

        for(d = 1; d < ULONG_MAX; d++) {
                int tmp = (d * e)%phi;
                if (tmp == 1) {
                        printf("d is FOUND: %ld\n\n", d);
                        break;
                }
        }

        /* encryption function */
        printf("==========================================================\n");
        printf("4 - ENCRYPTION of message 123 --> enc_msg = m^e mod(n)\n");
        printf("==========================================================\n");
        printf("modulo n = %d\n", n);

        /* we are using gmp to be able to compute very large numbers */
        mpz_t me;      /* message^pub_exp */
        mpz_t enc_msg; /* encrypted message */
        mpz_t modn;    /* modulo n previously computed "3233" */
        mpz_inits(me, enc_msg, modn, 0);
        mpz_set_str(modn, "3233", 10); /* 10 means decimal number */

        mpz_ui_pow_ui(me, msg, e);  /* compute m^e */
        mpz_mod(enc_msg, me, modn); /* compute m^e mod(n) */

        printf("message^e mod(n) = ");
        mpz_out_str(NULL, 10, enc_msg);
        printf("\n\n");


        /* decryption function */
        printf("=============================================================\n");
        printf("5 - DECRYPTION of enc_msg 855 --> dec_msg = enc_msg^d mod(n)\n");
        printf("=============================================================\n");
        printf("modulo n = %d\n", n);

        int enc_message = 855; /* previously computed */
        mpz_t md;              /* enc_message^priv_exp */
        mpz_t dec_msg;         /* decrypted message */
        mpz_inits(md, dec_msg, 0);
        mpz_set_str(modn, "3233", 10);

        mpz_ui_pow_ui(md, enc_message, d);  /* compute enc_message^d */
        mpz_mod(dec_msg, md, modn); /* compute enc_msg^d mod(n) */

        printf("dec_msg^d mod(n) = ");
        mpz_out_str(NULL, 10, dec_msg);
        printf("\n\n");

        /* free */
        mpz_clear(me);
        mpz_clear(md);
        mpz_clear(modn);
        mpz_clear(enc_msg);
        mpz_clear(dec_msg);

        return 0;
}
