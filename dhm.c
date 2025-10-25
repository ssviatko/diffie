#include "dhm.h"

const char *dhm_error_string[] = {
	"none",
	"unable to open /dev/urandom",
	"unable to read /dev/urandom",
	"unable to close /dev/urandom",
	"value error",
	"general unspecified error"
};

const char *dhm_strerror(dhm_error_t a_errno)
{
	return dhm_error_string[a_errno];
}

dhm_error_t dhm_init_session(dhm_session_t *a_session, int a_debug)
{
	// open urandom
	a_session->urandom_fd = open("/dev/urandom", O_RDONLY);
	if (a_session->urandom_fd < 0) {
		return DHM_ERR_OPENURANDOM;
	}
	
	// suck some data out of urandom to get the entropy moving
	char l_buff[256];;
	int i;
	int res;
	for (i = 0; i < 32; ++i) {
		res = read(a_session->urandom_fd, l_buff, 256);
		if (res != 256) {
			return DHM_ERR_READURANDOM;
		}
	}
	
	// populate GUID field
	res = read(a_session->urandom_fd, a_session->guid, GUIDSIZE);
	if (res != GUIDSIZE) {
		return DHM_ERR_READURANDOM;
	}

	return DHM_ERR_NONE;
}

dhm_error_t dhm_end_session  (dhm_session_t *a_session, int a_debug)
{
	int res;
	res = close(a_session->urandom_fd);
	if (res < 0) {
		return DHM_ERR_CLOSEURANDOM;
	}
	return DHM_ERR_NONE;
}

dhm_error_t dhm_get_alice(dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_private_t *a_alice_private, int a_debug)
{
	int i;
	int res;
	
	// zero out our Alice packet
	memset(a_alice, 0, sizeof(dhm_alice_t));
	
	// copy our session GUID into Alice packet
	memcpy(a_alice->guid, a_session->guid, GUIDSIZE);
	
	if (a_debug) {
		// show our session GUID
		printf("dhm_get_alice: session guid ");
		for (i = 0; i < GUIDSIZE; ++i) {
			printf("%02X", a_alice->guid[i]);
		}
		printf("\n");
	}
	
	// prepare random n-bit odd number for DH p factor
	res = read(a_session->urandom_fd, a_alice->p, PUBSIZE);
	if (res != PUBSIZE) {
		return DHM_ERR_READURANDOM;
	}
	a_alice->p[0] |= 0x80; // make it between 2^n - 1 and 2^(n-1)
	a_alice->p[PUBSIZE - 1] |= 0x01; // make it odd

	mpz_t l_p_import;
	mpz_init(l_p_import);
	mpz_import(l_p_import, PUBSIZE, 1, sizeof(unsigned char), 0, 0, a_alice->p);
	if (a_debug)
		gmp_printf("dhm_get_alice: p = %Zx\n", l_p_import);
	int l_pp = mpz_probab_prime_p(l_p_import, 50);
	if (a_debug)
		printf("dhm_get_alice: mpz_probab_prime_p returned %d.\n", l_pp);
	if (l_pp == 0) {
		if (a_debug)
			printf("dhm_get_alice: calling mpz_nextprime...\n");
		mpz_nextprime(l_p_import, l_p_import);
	}
	if (a_debug)
		gmp_printf("dhm_get_alice: p = %Zx\n", l_p_import);
	l_pp = mpz_probab_prime_p(l_p_import, 50);
	if (a_debug)
		printf("dhm_get_alice: mpz_probab_prime_p now returns %d.\n", l_pp);
	// stick our p value in the Alice data structure
	size_t l_written = 0;
	mpz_export(a_alice->p, &l_written, 1, sizeof(unsigned char), 0, 0, l_p_import);
	if (a_debug)
		printf("dhm_get_alice: wrote %ld bytes to p field of Alice data structure.\n", l_written);
	// police our written value
	if (l_written != PUBSIZE) {
		return DHM_ERR_VALUE;
	}
	
	if (a_debug)
		printf("dhm_get_alice: preparing g value...\n");
	mpz_t l_g;
	mpz_init(l_g);
	unsigned int l_g_rand;
	res = read(a_session->urandom_fd, &l_g_rand, sizeof(l_g_rand));
	if (res != sizeof(l_g_rand)) {
		return DHM_ERR_READURANDOM;
	}
	// l_g_rand even/odd?
	if ((l_g_rand & 0x01) == 0) {
		mpz_set_ui(l_g, 3);
		a_alice->g = htons(3);
	} else {
		mpz_set_ui(l_g, 5);
		a_alice->g = htons(5);
	}
	if (a_debug)
		gmp_printf("dhm_get_alice: g = %Zd\n", l_g);

	if (a_debug)
		printf("dhm_get_alice: preparing private key...\n");
	res = read(a_session->urandom_fd, a_alice_private->key, PRIVSIZE);
	if (res != PRIVSIZE) {
		return DHM_ERR_READURANDOM;
	}
	mpz_t l_a_import;
	mpz_init(l_a_import);
	mpz_import(l_a_import, PRIVSIZE, 1, sizeof(unsigned char), 0, 0, a_alice_private->key);
	if (a_debug)
		gmp_printf("dhm_get_alice: a = %Zx\n", l_a_import);

	// generate A
	mpz_t l_A;
	mpz_init(l_A);
	mpz_powm(l_A, l_g, l_a_import, l_p_import);
	if (a_debug)
		gmp_printf("dhm_get_alice: A = %Zx\n", l_A);
	mpz_export(a_alice->A, &l_written, 1, sizeof(unsigned char), 0, 0, l_A);
	if (a_debug)
		printf("dhm_get_alice: wrote %ld bytes to A field of Alice data structure.\n", l_written);
	// police our written value
	if (l_written != PUBSIZE) {
		return DHM_ERR_VALUE;
	}
	

	return DHM_ERR_NONE;
}
