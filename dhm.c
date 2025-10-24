#include "dhm.h"

const char *dhm_error_string[] = {
	"none",
	"unable to open /dev/urandom",
	"unable to read /dev/urandom",
	"unable to close /dev/urandom",
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
	int res;
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
	return DHM_ERR_NONE;
}
