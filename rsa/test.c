#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <gmp.h>
#include <time.h>
#include <getopt.h>

#define MAXBITS 16384
#define MAXBYTEBUFF (MAXBITS / 8)

unsigned char l_p[MAXBYTEBUFF];
unsigned char l_q[MAXBYTEBUFF];
unsigned char l_pt[MAXBYTEBUFF];

struct option g_options[] = {
	{ "bits", required_argument, NULL, 'b' },
	{ "help", no_argument, NULL, '?' },
	{ NULL, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
	unsigned int i;
	int l_urandom_fd; // file descriptor for /dev/urandom
	int res; // result variable for UNIX reads
	unsigned int l_bits = 128; // default bit width
	int opt;
	while ((opt = getopt_long(argc, argv, "b:?", g_options, NULL)) != -1) {
		switch (opt) {
			case 'b':
				{
					l_bits = atoi(optarg);
				}
				break;
			case '?':
				{
					printf("usage: rsa -b (--bits) <bit width>\n");
					printf("  p/q bit width must be between 128-8192 in 64 bit increments\n");
					printf("  default: %d bits\n", l_bits);
					exit(EXIT_SUCCESS);
				}
				break;
		}
	}
	if (l_bits > 8192) {
		fprintf(stderr, "rsa: bit width too big for practical purposes.\n");
		exit(EXIT_FAILURE);
	}
	if (l_bits < 128) {
		fprintf(stderr, "rsa: bit width too small for practical purposes.\n");
		exit(EXIT_FAILURE);
	}
	if ((l_bits % 64) != 0) {
		fprintf(stderr, "rsa: bit width should be divisible by 64.\n");
		exit(EXIT_FAILURE);
	}

	printf("RSA toolbox\n");
	printf("RSA p/q bit width: %d\n", l_bits);

	// open urandom
	l_urandom_fd = open("/dev/urandom", O_RDONLY);
	if (l_urandom_fd < 0) {
		fprintf(stderr, "rsa: problems opening /dev/urandom: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	mpz_t l_p_import;
	mpz_init(l_p_import);
	mpz_t l_q_import;
	mpz_init(l_q_import);
	mpz_t l_p1;
	mpz_init(l_p1);
	mpz_t l_q1;
	mpz_init(l_q1);
	mpz_t l_n;
	mpz_init(l_n);
	mpz_t l_ct;
	mpz_init(l_ct);
	mpz_t l_e;
	mpz_init(l_e);
	mpz_t l_tmp;
	mpz_init(l_tmp);
	mpz_t l_d;
	mpz_init(l_d);
	mpz_t l_q2;
	mpz_init(l_q2);
	mpz_t l_counter;
	mpz_init(l_counter);
	int l_success = 0;
	unsigned int l_attempt = 1;
	while (l_success == 0) {
		printf("attempt %d to generate key...\n", l_attempt++);

		// prepare random n-bit odd number for p factor
		res = read(l_urandom_fd, l_p, (l_bits / 8));
		if (res != (l_bits / 8)) {
			fprintf(stderr, "dh: problems reading /dev/urandom: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		l_p[0] |= 0x80; // make it between 2^n - 1 and 2^(n-1)
		l_p[(l_bits / 8) - 1] |= 0x01; // make it odd

		mpz_import(l_p_import, (l_bits / 8), 1, sizeof(unsigned char), 0, 0, l_p);
		int l_pp = mpz_probab_prime_p(l_p_import, 50);
		if (l_pp == 0) {
			mpz_nextprime(l_p_import, l_p_import);
		}
		gmp_printf("p       = %Zx\n", l_p_import);
		l_pp = mpz_probab_prime_p(l_p_import, 50);

		// prepare random n-bit odd number for q factor
		res = read(l_urandom_fd, l_q, (l_bits / 8));
		if (res != (l_bits / 8)) {
			fprintf(stderr, "rsa: problems reading /dev/urandom: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		l_q[0] &= 0x7f; // set up q to hopefully be < p/2
		l_q[(l_bits / 8) - 1] |= 0x01; // make it odd

		mpz_import(l_q_import, (l_bits / 8), 1, sizeof(unsigned char), 0, 0, l_q);
		l_pp = mpz_probab_prime_p(l_q_import, 50);
		if (l_pp == 0) {
			mpz_nextprime(l_q_import, l_q_import);
		}
		gmp_printf("q       = %Zx\n", l_q_import);
		l_pp = mpz_probab_prime_p(l_q_import, 50);

		// p and q should not be identical
		if (mpz_cmp(l_p_import, l_q_import) == 0) {
			fprintf(stderr, "error: p and q cannot be identical.");
			continue;
		}

		// p should be > than 2q
		mpz_mul_ui(l_q2, l_q_import, 2);
		if (mpz_cmp(l_q2, l_p_import) >= 0) {
			fprintf(stderr, "error: p must be greater than 2q.\n");
			continue;
		}

		// establish p-1 and q-1
		mpz_sub_ui(l_p1, l_p_import, 1);
		mpz_sub_ui(l_q1, l_q_import, 1);
		gmp_printf("(p - 1) = %Zx\n", l_p1);
		gmp_printf("(q - 1) = %Zx\n", l_q1);

		// p-1 and q-1 should not have small prime factors. Check both of them for all primes <100
		mpz_set_ui(l_counter, 2); // start with 3 as all even numbers are divisible by 2
		int l_bailout = 0;
		do {
			mpz_nextprime(l_counter, l_counter);
//			gmp_printf("testing %Zd against P - 1...\n", l_counter);
			mpz_gcd(l_tmp, l_counter, l_p1);
			if (mpz_cmp(l_tmp, l_counter) == 0) {
				l_bailout = 1;
				break;
			}
		} while (mpz_cmp_ui(l_counter, 100) <= 0);
		if (l_bailout == 1) {
			gmp_printf("error: (p - 1) value has small prime factor of %Zd.\n", l_counter);
			continue;
		}

		mpz_set_ui(l_counter, 2); // start with 3 as all even numbers are divisible by 2
		l_bailout = 0;
		do {
			mpz_nextprime(l_counter, l_counter);
//			gmp_printf("testing %Zd against Q - 1...\n", l_counter);
			mpz_gcd(l_tmp, l_counter, l_q1);
			if (mpz_cmp(l_tmp, l_counter) == 0) {
				l_bailout = 1;
				break;
			}
		} while (mpz_cmp_ui(l_counter, 100) <= 0);
		if (l_bailout == 1) {
			gmp_printf("error: (q - 1) value has small prime factor of %Zd.\n", l_counter);
			continue;
		}

		// prepare n = p * q
		mpz_mul(l_n, l_p_import, l_q_import);
		gmp_printf("n       = %Zx\n", l_n);

		// prepare carmichael totient
		mpz_lcm(l_ct, l_p1, l_q1);
		gmp_printf("ct      = %Zx\n", l_ct);

		// choose e, so that e is coprime with ct
		mpz_set_ui(l_e, 65536); // start at 65537 after nextprime is called
		do {
			mpz_nextprime(l_e, l_e);
			gmp_printf("testing e = %Zd...\n", l_e);
			mpz_gcd(l_tmp, l_e, l_ct);
		} while (mpz_cmp_ui(l_tmp, 1) != 0);

		// choose d
		if (mpz_invert(l_d, l_e, l_ct) == 0) {
			fprintf(stderr, "invert failed!\n");
			continue;
		} else {
			gmp_printf("d       = %Zx\n", l_d);
		}
		l_success = 1; // made it this far, we generated a key pair!
	}

	mpz_t l_plain;
	mpz_init(l_plain);
	mpz_t l_cipher;
	mpz_init(l_cipher);
	mpz_t l_decrypted;
	mpz_init(l_decrypted);
	printf("encrypt with public key -> decrypt with private key\n");
	for (i = 0; i < 10; ++i) {
		res = read(l_urandom_fd, l_pt, ((l_bits * 2) / 8));
		if (res != ((l_bits * 2) / 8)) {
			fprintf(stderr, "rsa: problems reading /dev/urandom: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		// padding
		l_pt[0] = 0x00;
		mpz_import(l_plain, ((l_bits * 2) / 8) - 1, 1, sizeof(unsigned char), 0, 0, l_pt);
		mpz_powm(l_cipher, l_plain, l_e, l_n);
		mpz_powm(l_decrypted, l_cipher, l_d, l_n);
		gmp_printf("plain     = %Zx\ncipher    = %Zx\ndecrypted = %Zx %d\n", l_plain, l_cipher, l_decrypted, mpz_cmp(l_plain, l_decrypted));
	}
	printf("encrypt with private key -> decrypt with public key\n");
	for (i = 0; i < 10; ++i) {
		res = read(l_urandom_fd, l_pt, ((l_bits * 2) / 8));
		if (res != ((l_bits * 2) / 8)) {
			fprintf(stderr, "rsa: problems reading /dev/urandom: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		// padding
		l_pt[0] = 0x00;
		mpz_import(l_plain, ((l_bits * 2) / 8) - 1, 1, sizeof(unsigned char), 0, 0, l_pt);
		mpz_powm(l_cipher, l_plain, l_d, l_n);
		mpz_powm(l_decrypted, l_cipher, l_e, l_n);
		gmp_printf("plain     = %Zx\ncipher    = %Zx\ndecrypted = %Zx %d\n", l_plain, l_cipher, l_decrypted, mpz_cmp(l_plain, l_decrypted));
	}

	// clean up
	mpz_clear(l_p_import);
	mpz_clear(l_q_import);
	mpz_clear(l_p1);
	mpz_clear(l_q1);
	mpz_clear(l_n);
	mpz_clear(l_ct);
	mpz_clear(l_e);
	mpz_clear(l_tmp);
	mpz_clear(l_d);
	mpz_clear(l_plain);
	mpz_clear(l_cipher);
	mpz_clear(l_decrypted);
	mpz_clear(l_q2);
	mpz_clear(l_counter);

	return 0;
}

