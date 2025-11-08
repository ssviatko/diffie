#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <gmp.h>
#include <time.h>
#include <getopt.h>

#define MAXBITS 16384
#define MAXBYTEBUFF (MAXBITS / 8)

unsigned char g_p[MAXBYTEBUFF];
unsigned char g_q[MAXBYTEBUFF];
unsigned char g_buff[MAXBYTEBUFF];

struct option g_options[] = {
	{ "bits", required_argument, NULL, 'b' },
	{ "help", no_argument, NULL, '?' },
	{ "debug", no_argument, NULL, 'd' },
	{ NULL, 0, NULL, 0 }
};

int g_debug = 0;
// note: for the keygen, g_bits now refers to the n/block size, not the p/q size
unsigned int g_bits = 256; // default bit width
unsigned int g_pqbits; // convenience value
int g_urandom_fd; // file descriptor for /dev/urandom

void print_hex(uint8_t *a_buffer, size_t a_len)
{
	int i;
	for (i = 0; i < a_len; ++i) {
		if (i % 32 == 0)
			printf("\n");
		printf("%02X ", a_buffer[i]);
	}
	printf("\n");
}

static void right_justify(size_t a_size, size_t a_offset, char *a_buff)
{
	// move a_size number of bytes over by a_offset in buffer a_buff
	int i;
	for (i = a_size - 1; i >= 0; --i) {
		a_buff[i + a_offset] = a_buff[i];
	}
	// zero out space we vacated in front
	for (i = 0; i < a_offset; ++i) {
		a_buff[i] = 0;
	}
}

int main(int argc, char **argv)
{
	unsigned int i;
	int res; // result variable for UNIX reads
	int opt;
	while ((opt = getopt_long(argc, argv, "db:?", g_options, NULL)) != -1) {
		switch (opt) {
			case 'd':
				{
					g_debug = 1;
				}
				break;
			case 'b':
				{
					g_bits = atoi(optarg);
				}
				break;
			case '?':
				{
					printf("usage: rsa-keygen -b (--bits) <bit width>\n");
					printf("  RSA bit width must be between 256-8192 in 256 bit increments\n");
					printf("  default: %d bits\n", g_bits);
					exit(EXIT_SUCCESS);
				}
				break;
		}
	}
	if (g_bits > 8192) {
		fprintf(stderr, "rsa-keygen: bit width too big for practical purposes.\n");
		exit(EXIT_FAILURE);
	}
	if (g_bits < 256) {
		fprintf(stderr, "rsa-keygen: bit width too small for practical purposes.\n");
		exit(EXIT_FAILURE);
	}
	if ((g_bits % 256) != 0) {
		fprintf(stderr, "rsa-keygen: bit width should be divisible by 256.\n");
		exit(EXIT_FAILURE);
	}

	g_pqbits = g_bits / 2;
	printf("RSA keygen\n");
	printf("RSA block bit width: %d\n", g_bits);
	if (g_debug > 0) {
		printf("debug mode enabled\n");
	}

	// open urandom
	g_urandom_fd = open("/dev/urandom", O_RDONLY);
	if (g_urandom_fd < 0) {
		fprintf(stderr, "rsa: problems opening /dev/urandom: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	setbuf(stdout, NULL); // disable buffering so we can print our progress

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
		if (g_debug) printf("attempt %d to generate key...\n", l_attempt++);
		else printf(".");

		// prepare random n-bit odd number for p factor
		res = read(g_urandom_fd, g_p, (g_pqbits / 8));
		if (res != (g_pqbits / 8)) {
			fprintf(stderr, "dh: problems reading /dev/urandom: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		g_p[0] |= 0x80; // make it between 2^n - 1 and 2^(n-1)
		g_p[(g_pqbits / 8) - 1] |= 0x01; // make it odd

		mpz_import(l_p_import, (g_pqbits / 8), 1, sizeof(unsigned char), 0, 0, g_p);
		int l_pp = mpz_probab_prime_p(l_p_import, 50);
		if (l_pp == 0) {
			mpz_nextprime(l_p_import, l_p_import);
		}

		if (g_debug) gmp_printf("p       = %Zx\n", l_p_import);
		else printf(".");

		l_pp = mpz_probab_prime_p(l_p_import, 50);

		// prepare random n-bit odd number for q factor
		res = read(g_urandom_fd, g_q, (g_pqbits / 8));
		if (res != (g_pqbits / 8)) {
			fprintf(stderr, "rsa: problems reading /dev/urandom: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		g_q[0] &= 0x7f; // set up q to hopefully be < p/2
		g_q[0] |= 0x40; // but not too little, please.. enforce first byte between 0x40 and 0x7f
		g_q[(g_pqbits / 8) - 1] |= 0x01; // make it odd

		mpz_import(l_q_import, (g_pqbits / 8), 1, sizeof(unsigned char), 0, 0, g_q);
		l_pp = mpz_probab_prime_p(l_q_import, 50);
		if (l_pp == 0) {
			mpz_nextprime(l_q_import, l_q_import);
		}

		if (g_debug) gmp_printf("q       = %Zx\n", l_q_import);
		else printf(".");

		l_pp = mpz_probab_prime_p(l_q_import, 50);

		// p and q should not be identical
		if (mpz_cmp(l_p_import, l_q_import) == 0) {
			if (g_debug) fprintf(stderr, "error: p and q cannot be identical.");
			else printf("+");
			continue;
		}

		// p should be > than 2q
		mpz_mul_ui(l_q2, l_q_import, 2);
		if (mpz_cmp(l_q2, l_p_import) >= 0) {
			if (g_debug) fprintf(stderr, "error: p must be greater than 2q.\n");
			else printf("+");
			continue;
		}

		// establish p-1 and q-1
		mpz_sub_ui(l_p1, l_p_import, 1);
		mpz_sub_ui(l_q1, l_q_import, 1);
		if (g_debug) gmp_printf("(p - 1) = %Zx\n", l_p1);
		if (g_debug) gmp_printf("(q - 1) = %Zx\n", l_q1);

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
			if (g_debug) gmp_printf("error: (p - 1) value has small prime factor of %Zd.\n", l_counter);
			else printf("+");
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
			if (g_debug) gmp_printf("error: (q - 1) value has small prime factor of %Zd.\n", l_counter);
			else printf("+");
			continue;
		}

		// prepare n = p * q
		mpz_mul(l_n, l_p_import, l_q_import);
		if (g_debug) gmp_printf("n       = %Zx\n", l_n);
		else printf(".");

		// prepare carmichael totient
		mpz_lcm(l_ct, l_p1, l_q1);
		if (g_debug) gmp_printf("ct      = %Zx\n", l_ct);

		// choose e, so that e is coprime with ct
		mpz_set_ui(l_e, 65536); // start at 65537 after nextprime is called
		do {
			mpz_nextprime(l_e, l_e);
			if (g_debug) gmp_printf("testing e = %Zd...\n", l_e);
			mpz_gcd(l_tmp, l_e, l_ct);
		} while (mpz_cmp_ui(l_tmp, 1) != 0);

		// choose d
		if (mpz_invert(l_d, l_e, l_ct) == 0) {
			if (g_debug) fprintf(stderr, "invert failed!\n");
			else printf("+");
			continue;
		} else {
			if (g_debug) gmp_printf("d       = %Zx\n", l_d);
		}
		l_success = 1; // made it this far, we generated a key pair!
	}
	printf("\nDone\n");

	// export
	size_t l_written = 0;

	mpz_export(g_buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_n);
	if (l_written != (g_bits / 8)) {
		right_justify(l_written, (g_bits / 8) - l_written, (char *)g_buff);
	}
	printf("modulus n (%d bits):", g_bits);
	print_hex(g_buff, (g_bits / 8));

	mpz_export(g_buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_e);
	if (l_written != 4) { // save e as a 32 bit value, big endian
		right_justify(l_written, 4 - l_written, (char *)g_buff);
	}
	printf("public exponent e:", g_bits);
	print_hex(g_buff, 4);

	mpz_export(g_buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_d);
	if (l_written != (g_bits / 8)) {
		right_justify(l_written, (g_bits / 8) - l_written, (char *)g_buff);
	}
	printf("private exponent d:", g_bits);
	print_hex(g_buff, (g_bits / 8));

	mpz_export(g_buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_p_import);
	if (l_written != (g_pqbits / 8)) {
		right_justify(l_written, (g_pqbits / 8) - l_written, (char *)g_buff);
	}
	printf("prime p:");
	print_hex(g_buff, (g_pqbits / 8));

	mpz_export(g_buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_q_import);
	if (l_written != (g_pqbits / 8)) {
		right_justify(l_written, (g_pqbits / 8) - l_written, (char *)g_buff);
	}
	printf("prime q:");
	print_hex(g_buff, (g_pqbits / 8));

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
	mpz_clear(l_q2);
	mpz_clear(l_counter);

	return 0;
}

