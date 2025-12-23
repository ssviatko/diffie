/**
 *
 * RSA Implementation
 * 2025/Nov/15 - Revision 0.80 alpha
 *
 * Created by: Stephen Sviatko
 *
 * (C) 2025 Good Neighbors LLC - All Rights Reserved, except where noted
 *
 * This file and any intellectual property (designs, algorithms, formulas,
 * procedures, trademarks, and related documentation) contained herein are
 * property of Good Neighbors, an Arizona Limited Liability Company.
 *
 * LICENSING INFORMATION
 *
 * This file may not be distributed in any modified form without expressed
 * written permission of Good Neighbors LLC or its regents. Permission is
 * granted to use this file in any non-commercial, non-governmental capacity
 * (such as student projects, hobby projects, etc) without an official
 * licensing agreement as long as the original author(s) are credited in any
 * derivative work.
 *
 * Commercial licensing of this content is available, any agreement must
 * include consulting services as part of a deployment strategy. For more
 * information, please contact Stephen Sviatko at the following email address:
 *
 * ssviatko@gmail.com
 *
 * @file rsa-keygen.c
 * @brief RSA key pair generator
 *
 * This file implements an RSA key pair generator.
 *
 * Usage:
 *
 * ./rsa-keygen
 *
 * (see usage screen for more details using -? or --help switch)
 *
 * Build Info:
 *
 * type "make"
 *
 * Linking: RSA uses the GMP (Gnu Multi-Precision) library to compute various
 * coefficients needed for the RSA algorithms to work, and as a result of
 * this you will need to have the GMP library and its relevant headers loaded
 * onto your system in order to build.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <gmp.h>
#include <sys/time.h>
#include <getopt.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "ccct.h"
#include "color_print.h"

#pragma pack(1)

#define MAXBITS 262144
#define MAXBYTEBUFF (MAXBITS / 8)
#define MAXTHREADS 48

#define BUFFLEN 1024

struct timeval g_start_time, g_end_time;

typedef struct {
	pthread_t thread;
	unsigned int id;
	unsigned char p[MAXBYTEBUFF];
	unsigned char q[MAXBYTEBUFF];
	unsigned char buff[MAXBYTEBUFF];
} thread_work_area;

thread_work_area twa[MAXTHREADS];

pthread_mutex_t g_bell_mtx;
int g_bell = 0;

struct option g_options[] = {
	{ "bits", required_argument, NULL, 'b' },
	{ "help", no_argument, NULL, '?' },
	{ "debug", no_argument, NULL, 'd' },
	{ "threads", required_argument, NULL, 't' },
	{ "out", required_argument, NULL, 'o' },
	{ "pem", no_argument, NULL, 1001 },
	{ "nocolor", no_argument, NULL, 1002 },
	{ NULL, 0, NULL, 0 }
};

int g_debug = 0;
int g_pem = 0;
// note: for the keygen, g_bits now refers to the n/block size, not the p/q size
unsigned int g_bits = 4096; // default bit width
unsigned int g_pqbits; // convenience value
pthread_mutex_t g_urandom_mtx;
unsigned int g_threads = 8; // default number of threads

const char *g_private_suffix = "-private.bin";
const char *g_public_suffix = "-public.bin";
const char *g_private_pem_suffix = "-private.pem";
const char *g_public_pem_suffix = "-public.pem";
char g_private_filename[BUFFLEN];
char g_public_filename[BUFFLEN];
int g_filename_specified = 0;
const char *g_default_filename = "default";

const uint8_t KIHT_MODULUS = 1;
const uint8_t KIHT_PUBEXP = 2;
const uint8_t KIHT_PRIVEXP = 3;
const uint8_t KIHT_P = 4;
const uint8_t KIHT_Q = 5;
const uint8_t KIHT_DP = 6;
const uint8_t KIHT_DQ = 7;
const uint8_t KIHT_QINV = 8;

typedef struct {
	uint8_t type;
	uint32_t bit_width;
} key_item_header;

int g_nocolor = 0;

void color_gmp_printf(const char *format, ...)
{
	if (g_debug == 0)
		return; // don't print anything if debug isn't turned on
		char edited_format[BUFFLEN];
	edited_format[0] = 0;
	if (!g_nocolor)
		strcat(edited_format, "\033[34m");
	strcat(edited_format, format);
	if (!g_nocolor)
		strcat(edited_format, "\033[39m\033[49m");
	va_list args;
	va_start(args, format);
	gmp_vprintf(edited_format, args);
	va_end(args);
}

void *gen_tf(void *arg)
{
	thread_work_area *a_twa;
	a_twa = arg;

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

	// chinese remainder stuff
	mpz_t l_dp;
	mpz_init(l_dp);
	mpz_t l_dq;
	mpz_init(l_dq);
	mpz_t l_qinv;
	mpz_init(l_qinv);
	mpz_t l_m1;
	mpz_init(l_m1);
	mpz_t l_m2;
	mpz_init(l_m2);
	mpz_t l_h;
	mpz_init(l_h);

	int l_success = 0;
	unsigned int l_attempt = 1;
	int res;
	unsigned int i;

	while (l_success == 0) {
		pthread_mutex_lock(&g_bell_mtx);
		if (g_bell > 0) {
			// we didn't make it, so terminate
			pthread_mutex_unlock(&g_bell_mtx);
			pthread_exit(NULL);
			// if we made it here there was a problem
			return NULL;
		}
		pthread_mutex_unlock(&g_bell_mtx);

		color_debug("tid %d: attempt %d to generate key...\n", a_twa->id, l_attempt++);
		printf(".");

		// prepare random n-bit odd number for p factor
		ccct_get_random(a_twa->p, (g_pqbits / 8));
		a_twa->p[0] |= 0xc0; // make it between (2^n - 1) + (2^n - 2) and 2^(n-1)
		a_twa->p[(g_pqbits / 8) - 1] |= 0x01; // make it odd

		mpz_import(l_p_import, (g_pqbits / 8), 1, sizeof(unsigned char), 0, 0, a_twa->p);
		int l_pp = mpz_probab_prime_p(l_p_import, 50);
		if (l_pp == 0) {
			mpz_nextprime(l_p_import, l_p_import);
		}

		color_gmp_printf("tid %d: p       = %Zx\n", a_twa->id, l_p_import);

		l_pp = mpz_probab_prime_p(l_p_import, 50);

		// prepare random n-bit odd number for q factor
		ccct_get_random(a_twa->q, (g_pqbits / 8));
//		a_twa->q[0] &= 0x7f; // set up q to hopefully be < p/2
//		a_twa->q[0] |= 0x40; // but not too little, please.. enforce first byte between 0x40 and 0x7f
		a_twa->q[0] |= 0xc0; // make it just just like p... instead of the old way commented out above
		a_twa->q[(g_pqbits / 8) - 1] |= 0x01; // make it odd

		// top 4 bits of p equal to top 4 bits of q? if so, invert bits 4-5 to make it different
		if ((a_twa->q[0] & 0xf0) == (a_twa->p[0] & 0xf0)) {
			color_debug("tid %d: inversion: p[0]=%02X q[0]=%02X, inverting bits 4-5 of top byte of q: ", a_twa->id, a_twa->p[0], a_twa->q[0]);
			a_twa->q[0] ^= 0x30;
			color_debug("%02X\n", a_twa->q[0]);
		}

		mpz_import(l_q_import, (g_pqbits / 8), 1, sizeof(unsigned char), 0, 0, a_twa->q);
		l_pp = mpz_probab_prime_p(l_q_import, 50);
		if (l_pp == 0) {
			mpz_nextprime(l_q_import, l_q_import);
		}

		color_gmp_printf("tid %d: q       = %Zx\n",a_twa->id, l_q_import);

		l_pp = mpz_probab_prime_p(l_q_import, 50);

		// p and q will never be identical courtesy of our inversion scheme above
//		// p and q should not be identical
//		if (mpz_cmp(l_p_import, l_q_import) == 0) {
//			if (g_debug) fprintf(stderr, "tid %d: error: p and q cannot be identical.", a_twa->id);
//			continue;
//		}

		// openssl doesn't preform this test.. so why should we?
//		// p should be > than 2q
//		mpz_mul_ui(l_q2, l_q_import, 2);
//		if (mpz_cmp(l_q2, l_p_import) >= 0) {
//			if (g_debug) fprintf(stderr, "tid %d: error: p must be greater than 2q.\n", a_twa->id);
//			continue;
//		}

		// establish p-1 and q-1
		mpz_sub_ui(l_p1, l_p_import, 1);
		mpz_sub_ui(l_q1, l_q_import, 1);
		color_gmp_printf("tid %d: (p - 1) = %Zx\n", a_twa->id, l_p1);
		color_gmp_printf("tid %d: (q - 1) = %Zx\n", a_twa->id, l_q1);

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
			color_gmp_printf("tid %d: error: (p - 1) value has small prime factor of %Zd.\n", a_twa->id, l_counter);
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
			color_gmp_printf("tid %d: error: (q - 1) value has small prime factor of %Zd.\n", a_twa->id, l_counter);
			continue;
		}

		// prepare n = p * q
		mpz_mul(l_n, l_p_import, l_q_import);
		color_gmp_printf("tid %d: n       = %Zx\n", a_twa->id, l_n);

		// prepare carmichael totient
		mpz_lcm(l_ct, l_p1, l_q1);
		color_gmp_printf("tid %d: ct      = %Zx\n", a_twa->id, l_ct);

		// choose e, so that e is coprime with ct
		mpz_set_ui(l_e, 65536); // start at 65537 after nextprime is called
		do {
			mpz_nextprime(l_e, l_e);
			color_gmp_printf("tid %d: testing e = %Zd...\n", a_twa->id, l_e);
			mpz_gcd(l_tmp, l_e, l_ct);
		} while (mpz_cmp_ui(l_tmp, 1) != 0);

		// choose d
		if (mpz_invert(l_d, l_e, l_ct) == 0) {
			if (g_debug) color_err_printf(0, "tid %d: invert failed!", a_twa->id);
			continue;
		} else {
			color_gmp_printf("tid %d: d       = %Zx\n", a_twa->id, l_d);
		}

		// make sure d isn't too small: we want it to be at least bits - 7 in size.
		// i.e. the top byte of d should not be zero
		unsigned int l_sib = mpz_sizeinbase(l_d, 2);
		if (l_sib < (g_bits - 4)) {
			color_debug("tid %d: error: d bit size to low: %d bits.\n", a_twa->id, l_sib);
			continue;
		} else {
			color_debug("tid %d: d bit size is %d.\n", a_twa->id, l_sib);
		}

		// set up for chinese remainder
		mpz_mod(l_dp, l_d, l_p1);
		color_gmp_printf("tid %d: chinese: dp = %Zx\n", a_twa->id, l_dp);
		mpz_mod(l_dq, l_d, l_q1);
		color_gmp_printf("tid %d: chinese: dq = %Zx\n", a_twa->id, l_dq);
		mpz_invert(l_qinv, l_q_import, l_p_import);
		color_gmp_printf("tid %d: chinese: qinv = %Zx\n", a_twa->id, l_qinv);

		l_success = 1; // made it this far, we generated a key pair!
	}

	pthread_mutex_lock(&g_bell_mtx);
	if (g_bell > 0) {
		// we didn't make it, so terminate
		pthread_mutex_unlock(&g_bell_mtx);
		pthread_exit(NULL);
		// if we made it here there was a problem
		return NULL;
	}
	g_bell = 1;
	pthread_mutex_unlock(&g_bell_mtx);
	//printf("\ntid %d: Done.\n", a_twa->id);
	color_printf("\n*arsa-keygen:*d done.\n");
	gettimeofday(&g_end_time, NULL);
	color_printf("*arsa-keygen:*d found key in *h%ld*d seconds *h%ld*d usecs.\n", g_end_time.tv_sec - g_start_time.tv_sec - ((g_end_time.tv_usec - g_start_time.tv_usec < 0) ? 1 : 0),
		g_end_time.tv_usec - g_start_time.tv_usec + ((g_end_time.tv_usec - g_start_time.tv_usec < 0) ? 1000000 : 0));

	// export
	
	int privkey_fd, pubkey_fd;
	int privkey_pem_fd, pubkey_pem_fd;

	if (g_pem == 1) {
		color_printf("*arsa-keygen:*d output mode: privacy-enhanced mail format\n");
		strcat(g_private_filename, g_private_pem_suffix);
		strcat(g_public_filename, g_public_pem_suffix);
	} else {
		color_printf("*arsa-keygen:*d output mode: native binary format\n");
		strcat(g_private_filename, g_private_suffix);
		strcat(g_public_filename, g_public_suffix);
	}
	color_printf("*arsa-keygen:*d public key file : *h%s*d\n", g_public_filename);
	color_printf("*arsa-keygen:*d private key file: *h%s*d\n", g_private_filename);

	char l_priv_template[32];
	char l_public_template[32];

	if (g_pem == 0) {
		privkey_fd = open(g_private_filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (privkey_fd < 0) {
			color_err_printf(1, "rsa-keygen: unable to open private key file for writing");
			exit(EXIT_FAILURE);
		}
		pubkey_fd = open(g_public_filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (pubkey_fd < 0) {
			color_err_printf(1, "rsa-keygen: unable to open public key file for writing");
			exit(EXIT_FAILURE);
		}
	} else {
		strcpy(l_priv_template, "/tmp/rsa-keygen-privateXXXXXX");
		strcpy(l_public_template, "/tmp/rsa-keygen-publicXXXXXX");
		privkey_fd = mkstemp(l_priv_template);
		if (privkey_fd < 0) {
			color_err_printf(1, "rsa-keygen: unable to open temporary private key file for writing");
			exit(EXIT_FAILURE);
		}
		pubkey_fd = mkstemp(l_public_template);
		if (pubkey_fd < 0) {
			color_err_printf(1, "rsa-keygen: unable to open temporary public key file for writing");
			exit(EXIT_FAILURE);
		}
		color_debug("/tmp private template: %s\n", l_priv_template);
		color_debug("/tmp public template: %s\n", l_public_template);
	}
	size_t l_written = 0;

	mpz_export(a_twa->buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_n);
	if (l_written != (g_bits / 8)) {
		ccct_right_justify(l_written, (g_bits / 8) - l_written, (char *)a_twa->buff);
	}
	color_printf("*amodulus n (*b%d*a bits):*d", g_bits);
	ccct_print_hex(a_twa->buff, (g_bits / 8));
	if (g_filename_specified) {
		key_item_header l_kih;
		l_kih.type = KIHT_MODULUS;
		l_kih.bit_width = htonl(g_bits);
		res = write(privkey_fd, &l_kih, sizeof(l_kih));
		if (res != sizeof(l_kih)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
		res = write(privkey_fd, a_twa->buff, (g_bits / 8));
		if (res != (g_bits / 8)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}

		res = write(pubkey_fd, &l_kih, sizeof(l_kih));
		if (res != sizeof(l_kih)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
		res = write(pubkey_fd, a_twa->buff, (g_bits / 8));
		if (res != (g_bits / 8)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
	}

	mpz_export(a_twa->buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_e);
	if (l_written != 4) { // save e as a 32 bit value, big endian
		ccct_right_justify(l_written, 4 - l_written, (char *)a_twa->buff);
	}
	color_printf("*apublic exponent e:*d");
	ccct_print_hex(a_twa->buff, 4);
	if (g_filename_specified) {
		key_item_header l_kih;
		l_kih.type = KIHT_PUBEXP;
		l_kih.bit_width = htonl(32);
		res = write(privkey_fd, &l_kih, sizeof(l_kih));
		if (res != sizeof(l_kih)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
		res = write(privkey_fd, a_twa->buff, 4);
		if (res != 4) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}

		res = write(pubkey_fd, &l_kih, sizeof(l_kih));
		if (res != sizeof(l_kih)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
		res = write(pubkey_fd, a_twa->buff, 4);
		if (res != 4) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
	}

	mpz_export(a_twa->buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_d);
	if (l_written != (g_bits / 8)) {
		ccct_right_justify(l_written, (g_bits / 8) - l_written, (char *)a_twa->buff);
	}
	color_printf("*aprivate exponent d:*d");
	ccct_print_hex(a_twa->buff, (g_bits / 8));
	if (g_filename_specified) {
		key_item_header l_kih;
		l_kih.type = KIHT_PRIVEXP;
		l_kih.bit_width = htonl(g_bits);
		res = write(privkey_fd, &l_kih, sizeof(l_kih));
		if (res != sizeof(l_kih)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
		res = write(privkey_fd, a_twa->buff, (g_bits / 8));
		if (res != (g_bits / 8)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
	}

	mpz_export(a_twa->buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_p_import);
	if (l_written != (g_pqbits / 8)) {
		ccct_right_justify(l_written, (g_pqbits / 8) - l_written, (char *)a_twa->buff);
	}
	color_printf("*aprime p:*d");
	ccct_print_hex(a_twa->buff, (g_pqbits / 8));
	if (g_filename_specified) {
		key_item_header l_kih;
		l_kih.type = KIHT_P;
		l_kih.bit_width = htonl(g_pqbits);
		res = write(privkey_fd, &l_kih, sizeof(l_kih));
		if (res != sizeof(l_kih)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
		res = write(privkey_fd, a_twa->buff, (g_pqbits / 8));
		if (res != (g_pqbits / 8)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
	}

	mpz_export(a_twa->buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_q_import);
	if (l_written != (g_pqbits / 8)) {
		ccct_right_justify(l_written, (g_pqbits / 8) - l_written, (char *)a_twa->buff);
	}
	color_printf("*aprime q:*d");
	ccct_print_hex(a_twa->buff, (g_pqbits / 8));
	if (g_filename_specified) {
		key_item_header l_kih;
		l_kih.type = KIHT_Q;
		l_kih.bit_width = htonl(g_pqbits);
		res = write(privkey_fd, &l_kih, sizeof(l_kih));
		if (res != sizeof(l_kih)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
		res = write(privkey_fd, a_twa->buff, (g_pqbits / 8));
		if (res != (g_pqbits / 8)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
	}

	mpz_export(a_twa->buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_dp);
	if (l_written != (g_pqbits / 8)) {
		ccct_right_justify(l_written, (g_pqbits / 8) - l_written, (char *)a_twa->buff);
	}
	color_printf("*aexponent dp:*d");
	ccct_print_hex(a_twa->buff, (g_pqbits / 8));
	if (g_filename_specified) {
		key_item_header l_kih;
		l_kih.type = KIHT_DP;
		l_kih.bit_width = htonl(g_pqbits);
		res = write(privkey_fd, &l_kih, sizeof(l_kih));
		if (res != sizeof(l_kih)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
		res = write(privkey_fd, a_twa->buff, (g_pqbits / 8));
		if (res != (g_pqbits / 8)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
	}

	mpz_export(a_twa->buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_dq);
	if (l_written != (g_pqbits / 8)) {
		ccct_right_justify(l_written, (g_pqbits / 8) - l_written, (char *)a_twa->buff);
	}
	color_printf("*aexponent dq:*d");
	ccct_print_hex(a_twa->buff, (g_pqbits / 8));
	if (g_filename_specified) {
		key_item_header l_kih;
		l_kih.type = KIHT_DQ;
		l_kih.bit_width = htonl(g_pqbits);
		res = write(privkey_fd, &l_kih, sizeof(l_kih));
		if (res != sizeof(l_kih)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
		res = write(privkey_fd, a_twa->buff, (g_pqbits / 8));
		if (res != (g_pqbits / 8)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
	}

	mpz_export(a_twa->buff, &l_written, 1, sizeof(unsigned char), 0, 0, l_qinv);
	if (l_written != (g_pqbits / 8)) {
		ccct_right_justify(l_written, (g_pqbits / 8) - l_written, (char *)a_twa->buff);
	}
	color_printf("*acoefficient qinv:*d");
	ccct_print_hex(a_twa->buff, (g_pqbits / 8));
	if (g_filename_specified) {
		key_item_header l_kih;
		l_kih.type = KIHT_QINV;
		l_kih.bit_width = htonl(g_pqbits);
		res = write(privkey_fd, &l_kih, sizeof(l_kih));
		if (res != sizeof(l_kih)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
		res = write(privkey_fd, a_twa->buff, (g_pqbits / 8));
		if (res != (g_pqbits / 8)) {
			color_err_printf(1, "rsa-keygen: problems writing key data");
			exit(EXIT_FAILURE);
		}
	}

	// if we're writing a pem, rewind these files and load them up into memory
	// then convert to base64, then write them to the normal filenames.
	if (g_pem == 1) {
		res = lseek(privkey_fd, 0, SEEK_SET);
		if (res < 0) {
			color_err_printf(1, "rsa-keygen: can't rewind temporary private key file");
			exit(EXIT_FAILURE);
		}
		res = lseek(pubkey_fd, 0, SEEK_SET);
		if (res < 0) {
			color_err_printf(1, "rsa-keygen: can't rewind temporary public key file");
			exit(EXIT_FAILURE);
		}
		// find out how big our private key file is
		struct stat l_privstat;
		res = stat(l_priv_template, &l_privstat);
		if (res < 0) {
			color_err_printf(1, "rsa-keygen: unable to stat temporary private key file");
			exit(EXIT_FAILURE);
		}
		// and create a buffer big enough to load it in, and another to hold the base64, and another to hold the format
		size_t l_buff_load_size = l_privstat.st_size + 255;
		size_t l_buff_enc_size = (l_buff_load_size * 4 / 3) + 255;
		char *buff_load = NULL;
		buff_load = malloc(l_buff_load_size);
		if (buff_load == NULL) {
			color_err_printf(0, "rsa-keygen: unable to allocate buffer to load temporary key files");
			exit(EXIT_FAILURE);
		}
		char *buff_enc = NULL;
		buff_enc = malloc(l_buff_enc_size);
		if (buff_enc == NULL) {
			color_err_printf(0, "rsa-keygen: unable to allocate buffer to encrypt temporary key files");
			exit(EXIT_FAILURE);
		}
		char *buff_fmt = NULL;
		buff_fmt = malloc(l_buff_enc_size + 512);
		if (buff_fmt == NULL) {
			color_err_printf(0, "rsa-keygen: unable to allocate buffer to hold formatted temporary key files");
			exit(EXIT_FAILURE);
		}

		size_t buff_load_len = 0;

		// load up private key
		do {
			res = read(privkey_fd, buff_load + buff_load_len, 4096);
			if (res < 0) {
				color_err_printf(1, "rsa-keygen: problems reading temporary private key");
				exit(EXIT_FAILURE);
			}
			buff_load_len += res;
		} while (res != 0);
		// convert it to base64
		ccct_base64_encode(buff_load, buff_load_len, buff_enc);
		ccct_base64_format(buff_enc, buff_fmt, "BEGIN PRIVATE KEY", "END PRIVATE KEY");
		// write out key to user specified file
		privkey_pem_fd = open(g_private_filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (privkey_pem_fd < 0) {
			color_err_printf(1, "rsa-keygen: unable to open private key file for writing");
			exit(EXIT_FAILURE);
		}
		res = write(privkey_pem_fd, buff_fmt, strlen(buff_fmt));
		if (res < 0) {
			color_err_printf(1, "rsa-keygen: unable to write to private key file");
			exit(EXIT_FAILURE);
		} else if (res != strlen(buff_fmt)) {
			color_err_printf(0, "rsa-keygen: unable to write entire contents of formatted buffer: wrote %d expected %d.\n", res, strlen(buff_fmt));
			exit(EXIT_FAILURE);
		}
		close(privkey_pem_fd);

		// load up public key
		buff_load_len = 0;
		do {
			res = read(pubkey_fd, buff_load + buff_load_len, 4096);
			if (res < 0) {
				color_err_printf(1, "rsa-keygen: problems reading temporary private key");
				exit(EXIT_FAILURE);
			}
			buff_load_len += res;
		} while (res != 0);
		// convert it to base64
		ccct_base64_encode(buff_load, buff_load_len, buff_enc);
		ccct_base64_format(buff_enc, buff_fmt, "BEGIN PUBLIC KEY", "END PUBLIC KEY");
		pubkey_pem_fd = open(g_public_filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (pubkey_pem_fd < 0) {
			color_err_printf(1, "rsa-keygen: unable to open public key file for writing");
			exit(EXIT_FAILURE);
		}
		res = write(pubkey_pem_fd, buff_fmt, strlen(buff_fmt));
		if (res < 0) {
			color_err_printf(1, "rsa-keygen: unable to write to public key file");
			exit(EXIT_FAILURE);
		} else if (res != strlen(buff_fmt)) {
			color_err_printf(0, "rsa-keygen: unable to write entire contents of formatted buffer: wrote %d expected %d.\n", res, strlen(buff_fmt));
			exit(EXIT_FAILURE);
		}
		close(pubkey_pem_fd);

		free(buff_load);
		free(buff_enc);
		free(buff_fmt);

		unlink(l_priv_template);
		unlink(l_public_template);
	}

	close(privkey_fd);
	close(pubkey_fd);

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
	mpz_clear(l_m1);
	mpz_clear(l_m2);
	mpz_clear(l_h);
	mpz_clear(l_dp);
	mpz_clear(l_dq);
	mpz_clear(l_qinv);

	// dirty, yes.. but I hate to wait
	exit(EXIT_SUCCESS);
	return NULL;
}

int main(int argc, char **argv)
{
	unsigned int i;
	int res; // result variable for UNIX reads
	int opt;

	// try to determine hardware concurrency
	unsigned int l_tcnt = sysconf(_SC_NPROCESSORS_ONLN);
	if (l_tcnt != 0) {
		g_threads = l_tcnt;
	}

	// set up colors
	color_init(g_nocolor, g_debug);
	color_set_theme(3);

	while ((opt = getopt_long(argc, argv, "db:?t:o:", g_options, NULL)) != -1) {
		switch (opt) {
			case 1001: // pem
				{
					g_pem = 1;
				}
			break;
			case 1002: // nocolor
				{
					g_nocolor = 1;
					color_set_nocolor(g_nocolor);
				}
			break;
			case 'd':
				{
					g_debug = 1;
					ccct_set_debug(1);
					color_set_debug(g_debug);
				}
				break;
			case 't':
				{
					g_threads = atoi(optarg);
				}
				break;
			case 'b':
				{
					g_bits = atoi(optarg);
				}
				break;
			case 'o':
				{
					strcpy(g_private_filename, optarg);
					strcpy(g_public_filename, optarg);
					g_filename_specified = 1;
				}
				break;
			case '?':
				{
					color_printf("*hRSA key pair generator*d\n");
					color_printf("*aby Stephen Sviatko - (C) 2025 Good Neighbors LLC*d\n");
					color_printf("revision 0.80 alpha - 2025/Nov/15\n");
					color_printf("*husage: rsa-keygen <options>*d\n");
					color_printf("*a  -b (--bits) <bit width>*d key modulus size\n");
					color_printf("*a  -t (--threads) <threads>*d number of threads to use\n");
					color_printf("*a  -o (--out) <name>*d filename specifier to write out keys\n");
					color_printf("     otherwise, key will be written to default-* filenames.\n");
					color_printf("*a     (--pem)*d output key in privacy-enhanced mail format\n");
					color_printf("*a     (--nocolor)*d defeat terminal colors\n");
					color_printf("  RSA bit width must be between *b768*d and *b%d*d in 256 bit increments\n", MAXBITS);
					color_printf("  default: *b%d*d bits\n", g_bits);
					exit(EXIT_SUCCESS);
				}
				break;
		}
	}
	if (g_bits > MAXBITS) {
		color_err_printf(0, "rsa-keygen: bit width too big for practical purposes.");
		exit(EXIT_FAILURE);
	}
	if (g_bits < 768) {
		color_err_printf(0, "rsa-keygen: bit width too small for practical purposes.");
		exit(EXIT_FAILURE);
	}
	if ((g_bits % 256) != 0) {
		color_err_printf(0, "rsa-keygen: bit width should be divisible by 256.");
		exit(EXIT_FAILURE);
	}

	// do we need to specify a default filename for output?
	if (g_filename_specified == 0) {
		strcpy(g_private_filename, g_default_filename);
		strcpy(g_public_filename, g_default_filename);
		g_filename_specified = 1;
	}

	// police thread count
	if (g_threads < 1) {
		color_err_printf(0, "rsa-keygen: need to use at least 1 thread.");
		exit(EXIT_FAILURE);
	}
	if (g_threads > MAXTHREADS) {
		color_err_printf(0, "rsa-keygen: thread limit: %d.", MAXTHREADS);
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(&g_bell_mtx, NULL);
	pthread_mutex_init(&g_urandom_mtx, NULL);

	g_pqbits = g_bits / 2;
	color_printf("*arsa-keygen:*d block bit width: *b%d*d\n", g_bits);
	color_debug("debug mode enabled\n");
	if (g_threads > 1)
		color_printf("*arsa-keygen:*d enabling *h%d*d threads.\n", g_threads);

	// open urandom
	ccct_open_urandom();

	// terminal stuff
	setbuf(stdout, NULL); // disable buffering so we can print our progress
	ccct_get_term_size();

	gettimeofday(&g_start_time, NULL);

	color_printf("*arsa-keygen:*d searching for key ...");

	for (i = 0; i < g_threads; ++i) {
		twa[i].id = i;
		pthread_create(&twa[i].thread, NULL, gen_tf, &twa[i]);
	}

	// join
	for (i = 0; i < g_threads; ++i) {
//		printf("joining %d...\n", i);
		pthread_join(twa[i].thread, NULL);
	}

	pthread_mutex_destroy(&g_bell_mtx);
	pthread_mutex_destroy(&g_urandom_mtx);
	ccct_close_urandom();

	return 0;
}


