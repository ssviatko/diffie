#include "dhm.h"

const char *dhm_error_string[] = {
	"none",
	"unable to open /dev/urandom",
	"unable to read /dev/urandom",
	"unable to close /dev/urandom",
	"value error",
	"general unspecified error"
};

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

dhm_error_t dhm_end_session(dhm_session_t *a_session, int a_debug)
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
//		fprintf(stderr, "RIGHT_JUSTIFY: l_written was %ld\n", l_written);
		right_justify(l_written, PUBSIZE - l_written, (char *)a_alice->p);
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
//		fprintf(stderr, "RIGHT_JUSTIFY: l_written was %ld\n", l_written);
		right_justify(l_written, PUBSIZE - l_written, (char *)a_alice->A);
	}

	mpz_clear(l_p_import);
	mpz_clear(l_g);
	mpz_clear(l_a_import);
	mpz_clear(l_A);
	
	return DHM_ERR_NONE;
}

dhm_error_t dhm_get_bob(dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_bob_t *a_bob, dhm_private_t *a_bob_private, int a_debug)
{
	int i;
	int res;
	
	// zero out our Bob packet
	memset(a_bob, 0, sizeof(dhm_bob_t));
	
	// copy our session GUID from Alice packet into Bob packet AND set as session GUID
	memcpy(a_session->guid, a_alice->guid, GUIDSIZE);
	memcpy(a_bob->guid, a_alice->guid, GUIDSIZE);
	
	if (a_debug) {
		// show our session GUID
		printf("dhm_get_bob: session guid ");
		for (i = 0; i < GUIDSIZE; ++i) {
			printf("%02X", a_bob->guid[i]);
		}
		printf("\n");
	}

	// generate b (bob private key)
	res = read(a_session->urandom_fd, a_bob_private->key, PRIVSIZE);
	if (res != PRIVSIZE) {
		return DHM_ERR_READURANDOM;
	}
	mpz_t l_b_import;
	mpz_init(l_b_import);
	mpz_import(l_b_import, PRIVSIZE, 1, sizeof(unsigned char), 0, 0, a_bob_private->key);
	if (a_debug)
		gmp_printf("dhm_get_bob: b = %Zx\n", l_b_import);
		
	// copy p, g, and A out of Alice packet and make GMP variables
	mpz_t l_p_import;
	mpz_init(l_p_import);
	mpz_t l_g_import;
	mpz_init(l_g_import);
	mpz_t l_A_import;
	mpz_init(l_A_import);
	mpz_import(l_p_import, PUBSIZE, 1, sizeof(unsigned char), 0, 0, a_alice->p);
	mpz_import(l_g_import, sizeof(uint16_t), 1, sizeof(unsigned char), 0, 0, &a_alice->g);
	mpz_import(l_A_import, PUBSIZE, 1, sizeof(unsigned char), 0, 0, a_alice->A);
	if (a_debug) {
		gmp_printf("dhm_get_bob: p = %Zx\n", l_p_import);
		gmp_printf("dhm_get_bob: g = %Zx\n", l_g_import);
		gmp_printf("dhm_get_bob: A = %Zx\n", l_A_import);
	}

	// compute B
	mpz_t l_B;
	mpz_init(l_B);
	mpz_powm(l_B, l_g_import, l_b_import, l_p_import);
	if (a_debug)
		gmp_printf("dhm_get_bob: B = %Zx\n", l_B);
	size_t l_written;
	mpz_export(a_bob->B, &l_written, 1, sizeof(unsigned char), 0, 0, l_B);
	if (a_debug)
		printf("dhm_get_bob: wrote %ld bytes to B field of Bob data structure.\n", l_written);
	// police our written value
	if (l_written != PUBSIZE) {
//		fprintf(stderr, "RIGHT_JUSTIFY: l_written was %ld\n", l_written);
		right_justify(l_written, PUBSIZE - l_written, (char *)a_bob->B);
	}
	
	// compute Bob's secret
	mpz_t l_sb;
	mpz_init(l_sb);
	mpz_powm(l_sb, l_A_import, l_b_import, l_p_import);
	if (a_debug)
		gmp_printf("dhm_get_bob: secret = %Zx\n", l_sb);
	mpz_export(a_session->s, &l_written, 1, sizeof(unsigned char), 0, 0, l_sb);
	if (a_debug)
		printf("dhm_get_bob: wrote %ld bytes to s field of session data structure.\n", l_written);
	// police our written value
	if (l_written != PUBSIZE) {
//		fprintf(stderr, "RIGHT_JUSTIFY: l_written was %ld\n", l_written);
		right_justify(l_written, PUBSIZE - l_written, (char *)a_session->s);
	}

	mpz_clear(l_b_import);
	mpz_clear(l_p_import);
	mpz_clear(l_g_import);
	mpz_clear(l_A_import);
	mpz_clear(l_B);
	mpz_clear(l_sb);
	
	return DHM_ERR_NONE;
}

dhm_error_t dhm_alice_secret (dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_bob_t *a_bob, dhm_private_t *a_alice_private, int a_debug)
{
	int i;
	if (a_debug) {
		// show our session GUID in Bob packet
		printf("dhm_alice_secret: session guid ");
		for (i = 0; i < GUIDSIZE; ++i) {
			printf("%02X", a_bob->guid[i]);
		}
		printf("\n");
	}
	// compute secret key for Alice and save it in Alice's session
	// copy p, g, and A out of Alice packet and make GMP variables
	mpz_t l_p_import;
	mpz_init(l_p_import);
	mpz_t l_B_import;
	mpz_init(l_B_import);
	mpz_t l_a_import;
	mpz_init(l_a_import);
	mpz_import(l_p_import, PUBSIZE, 1, sizeof(unsigned char), 0, 0, a_alice->p);
	mpz_import(l_B_import, PUBSIZE, 1, sizeof(unsigned char), 0, 0, a_bob->B);
	mpz_import(l_a_import, PRIVSIZE, 1, sizeof(unsigned char), 0, 0, a_alice_private->key);
	if (a_debug) {
		gmp_printf("dhm_alice_secret: p = %Zx\n", l_p_import);
		gmp_printf("dhm_alice_secret: A = %Zx\n", l_B_import);
		gmp_printf("dhm_alice_secret: a = %Zx\n", l_a_import);
	}

	mpz_t l_sa;
	mpz_init(l_sa);
	mpz_powm(l_sa, l_B_import, l_a_import, l_p_import);
	if (a_debug)
		gmp_printf("dhm_alice_secret: secret = %Zx\n", l_sa);
	size_t l_written;
	mpz_export(a_session->s, &l_written, 1, sizeof(unsigned char), 0, 0, l_sa);
	if (a_debug)
		printf("dhm_alice_secret: wrote %ld bytes to s field of session data structure.\n", l_written);
	// police our written value
	if (l_written != PUBSIZE) {
//		fprintf(stderr, "RIGHT_JUSTIFY: l_written was %ld\n", l_written);
		right_justify(l_written, PUBSIZE - l_written, (char *)a_session->s);
	}

	mpz_clear(l_p_import);
	mpz_clear(l_B_import);
	mpz_clear(l_a_import);
	mpz_clear(l_sa);
	
	return DHM_ERR_NONE;
}