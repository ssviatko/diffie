/**
 *
 * Diffie/Hellman/Merkle Implementation
 * 2025/Nov/11 - Revision 0.80 alpha
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
 * @file dhm.c
 * @brief Diffie/Hellman/Merkle API
 *
 * This file implements the Diffie/Hellman/Merkle API, which provides sessions,
 * formatted packets, and mathematical functions for computing the secrets
 * of the Diffie/Hellman/Merkle algorithm. It also provides the basis for
 * implementation of custom protocols for sending requests over a network.
 *
 * Usage:
 *
 * In a typical network scenario, a client establishes a connection to a server
 * over TCP or serial or some other physical means. The client then makes a
 * call to dhm_init_session to establish a DHM session.
 *
 * With this session structure, a call is the made by the client to
 * dhm_get_alice. This retrieves an Alice packet which is then sent over the
 * insecure link to the server.
 *
 * This implemenation utilizes a 2176 bit public modulus and 368 bit private
 * exponents. This key size provides a good balance of speed and security.
 * Tests on slow machines (2nd gen Sandy Bridge machines) as of this writing
 * in 2025 indicate that packet generation happens on average in .1-.3 seconds
 * with rare outliers taking .5 seconds to generate. On a modern machine the
 * time to generate is negligible and unnoticeable. Most of the processing
 * happens on the client side so it is unlikely to bog down a server if many
 * clients are connecting.
 *
 * On the server end, the server receives and catalogues the Alice packet from
 * the client, and establishes its own session structure with its own call to
 * dhm_init_session. Then it calls dhm_get_bob, providing the session
 * structure, received Alice packet, and a buffer to populate with a generated
 * Bob packet. Then the server sends the Bob packet back to the client.
 *
 * At this point Bob is in possession of the shared secret, which has been
 * populated into the server side session structure by the call to dhm_get_bob.
 *
 * Upon receipt of the Bob packet, the client calls dhm_alice_secret, providing
 * the received Bob packet, the Alice private key, and the client's session
 * structure. This call populates the client side session with the shared
 * secret, which can be read and used in any way the client wishes to create
 * private keys, symmetric keys, initialization vectors, etc.
 *
 * At the end of the encrypted communication session, both the client and the
 * server call dhm_end_session on their respective sides to close the DHM
 * session. After closing the session, all memory that has been allocated for
 * any data structures (sessions, packets, private keys, etc) needs to be
 * freed by the caller or valgrind will report a memory leak. It is important
 * to note that the DHM library does no memory management whatsoever!
 *
 * Build Info:
 *
 * To integrate this code into your project, copy the following files into
 * your project and configure your Make file to compile them:
 *
 * dhm.c
 * dhm.h
 * sha2.c
 * sha2.h
 *
 * The dhm.* files are the Diffie/Hellman/Merkle implementation and the sha2.*
 * files are the official FIPS implemenation of SHA2 by Oliver Gay. DHM
 * depends on SHA2 in order to compute hashes of packets to ensure data
 * integrity.
 *
 * Linking: DHM uses the GMP (Gnu Multi-Precision) library to compute various
 * coefficients needed for the DHM key exchange to work, and as a result of
 * this you will need to include the following flag in your linker string:
 *
 * -lgmp
 *
 */

#include "dhm.h"

const char *dhm_error_string[] = {
	"none",
	"unable to open /dev/urandom",
	"unable to read /dev/urandom",
	"unable to close /dev/urandom",
	"value error",
	"general unspecified error",
	"unrecognized packet type",
	"packet hash check failure"
}; ///< List of standard DHM error strings correlated to integer DHM error codes.

const uint16_t dhm_alice_packtype = 0xc1a5; ///< Packet type stamp for Alice packet. Stored in the packet in network byte order
const uint16_t dhm_bob_packtype = 0xc2a5; ///< Packet type stamp for Bob packet. Stored in the packet in network byte order

/**
 * @brief "Right justifies" a string of bytes within a set size byte buffer
 * Shifts over the data to the right and pads the data with zeros, in the
 * space on the left that was vacated by the move.
 *
 * @param[in] a_size The size of the byte buffer in bytes
 * @param[in] a_offset Number of bytes to shift the data over, i.e. the size of the buffer - the length of the data
 * @param[in] a_buff Pointer to the buffer to operate on
 */

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

/**
 * @brief Returns a char pointer to an existing error string
 * Works in exactly the same way as the strerror(errno) function works in the standard library
 *
 * @param[in] a_errno The numerical error returned by the function
 * @return character pointer to error message
 */

const char *dhm_strerror(dhm_error_t a_errno)
{
	return dhm_error_string[a_errno];
}

/**
 * @brief Initialize the DHM session
 * This function needs to be called before any other packet generation is attempted.
 *
 * @param[in] a_session Pointer to session data structure. It is the responsibility of the caller to allocate memory for this structure.
 * @param[in] a_debug Set this flag to 1 if you want to print debugging information.
 * @return standard DHM error enumeration dhm_error_t
 */

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

/**
 * @brief Close the DHM session
 * This function needs to be called after using the DHM library functions.
 *
 * @param[in] a_session Pointer to session data structure. It is the responsibility of the caller to free memory for this structure after calling dhm_end_session.
 * @param[in] a_debug Set this flag to 1 if you want to print debugging information.
 * @return standard DHM error enumeration dhm_error_t
 */

dhm_error_t dhm_end_session(dhm_session_t *a_session, int a_debug)
{
	int res;
	res = close(a_session->urandom_fd);
	if (res < 0) {
		return DHM_ERR_CLOSEURANDOM;
	}
	return DHM_ERR_NONE;
}

/**
 * @brief Get an Alice packet
 * This function is called by the client in order to initiate a DHM coversation. It is the first step to establishing an encrypted communications channel.
 *
 * @param[in] a_session Pointer to already-initialized session data structure.
 * @param[in] a_alice Pointer to buffer to hold Alice packet. It is the responsibility of the caller to allocate memory for this structure.
 * @param[in] a_alice_private Pointer to buffer to hold Alice's prvate key. It is the responsibility of the caller to allocate memory for this structure.
 * @param[in] a_debug Set this flag to 1 if you want to print debugging information.
 * @return standard DHM error enumeration dhm_error_t
 */

dhm_error_t dhm_get_alice(dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_private_t *a_alice_private, int a_debug)
{
	int i;
	int res;
	
	// zero out our Alice packet
	memset(a_alice, 0, sizeof(dhm_alice_t));
	
	// set type
	a_alice->packtype = htons(dhm_alice_packtype);
	
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
	
	// set packet hash
	size_t l_hstart = sizeof(a_alice->packtype) + SHASIZE;
	size_t l_hsize = sizeof(dhm_alice_t) - l_hstart;
	sha224_ctx l_ctx;
	sha224_init(&l_ctx);
	// guid is first field after packet type and hash
	sha224_update(&l_ctx, (const uint8_t *)a_alice->guid, l_hsize);
	sha224_final(&l_ctx, a_alice->hash);
	if (a_debug) {
		printf("dhm_get_alice: packet hash: ");
		for (i = 0; i < SHASIZE; ++i) {
			printf("%02X", a_alice->hash[i]);
		}
		printf("\n");
	}

	return DHM_ERR_NONE;
}

/**
 * @brief Get a Bob packet
 * This function is called by the server in reply to an Alice packet. It is the second step to establishing an encrypted communications channel.
 * In the process of generating the Bob packet, the shared secret is stored in the server's session structure.
 *
 * @param[in] a_session Pointer to already-initialized session data structure.
 * @param[in] a_alice Pointer to buffer containing a received Alice packet.
 * @param[in] a_bob Pointer to buffer large enough to contain a Bob packet. It is the responsibility of the caller to allocate memory for this structure.
 * @param[in] a_bob_private Pointer to buffer to hold Bob's prvate key. It is the responsibility of the caller to allocate memory for this structure.
 * @param[in] a_debug Set this flag to 1 if you want to print debugging information.
 * @return standard DHM error enumeration dhm_error_t
 */

dhm_error_t dhm_get_bob(dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_bob_t *a_bob, dhm_private_t *a_bob_private, int a_debug)
{
	int i;
	int res;
	
	// vet our Alice packet to see if it is OK
	if (a_alice->packtype != ntohs(dhm_alice_packtype)) {
		return DHM_ERR_WRONG_PACKTYPE;
	}
	// check Alice hash
	uint8_t l_digest[SHASIZE];
	size_t l_hstart = sizeof(a_alice->packtype) + SHASIZE;
	size_t l_hsize = sizeof(dhm_alice_t) - l_hstart;
	sha224_ctx l_ctx;
	sha224_init(&l_ctx);
	sha224_update(&l_ctx, (const uint8_t *)a_alice->guid, l_hsize);
	sha224_final(&l_ctx, l_digest);
	if (memcmp(l_digest, a_alice->hash, SHASIZE) != 0) {
		return DHM_ERR_HASH_FAILURE;
	}
	if (a_debug) {
		printf("dhm_get_bob: Alice packet hash OK (");
		for (i = 0; i < SHASIZE; ++i) {
			printf("%02X", l_digest[i]);
		}
		printf(")\n");
	}

	// zero out our Bob packet
	memset(a_bob, 0, sizeof(dhm_bob_t));
	
	// set packet type
	a_bob->packtype = htons(dhm_bob_packtype);
	
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
	
	// set packet hash
	l_hstart = sizeof(a_bob->packtype) + SHASIZE;
	l_hsize = sizeof(dhm_bob_t) - l_hstart;
	sha224_ctx l_ctx_b;
	sha224_init(&l_ctx_b);
	// guid is first field after packet type and hash
	sha224_update(&l_ctx_b, (const uint8_t *)a_bob->guid, l_hsize);
	sha224_final(&l_ctx_b, a_bob->hash);
	if (a_debug) {
		printf("dhm_get_bob: packet hash: ");
		for (i = 0; i < SHASIZE; ++i) {
			printf("%02X", a_bob->hash[i]);
		}
		printf("\n");
	}
	return DHM_ERR_NONE;
}

/**
 * @brief Compute shared secret on the client side
 * This function is called by the client in reply to a Bob packet. It computes the shared secret which then gets stored in Alice's session structure.
 *
 * @param[in] a_session Pointer to already-initialized session data structure.
 * @param[in] a_alice Pointer to buffer containing the original Alice packet created by the client.
 * @param[in] a_bob Pointer to buffer containing the received Bob packet.
 * @param[in] a_alice_private Pointer to buffer containing the original Alice private key created by the call to dhm_get_alice.
 * @param[in] a_debug Set this flag to 1 if you want to print debugging information.
 * @return standard DHM error enumeration dhm_error_t
 */

dhm_error_t dhm_alice_secret (dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_bob_t *a_bob, dhm_private_t *a_alice_private, int a_debug)
{
	int i;
	// check Bob packet type
	if (a_bob->packtype != ntohs(dhm_bob_packtype)) {
		return DHM_ERR_WRONG_PACKTYPE;
	}
	// check Bob hash
	uint8_t l_digest[SHASIZE];
	size_t l_hstart = sizeof(a_bob->packtype) + SHASIZE;
	size_t l_hsize = sizeof(dhm_bob_t) - l_hstart;
	sha224_ctx l_ctx;
	sha224_init(&l_ctx);
	sha224_update(&l_ctx, (const uint8_t *)a_bob->guid, l_hsize);
	sha224_final(&l_ctx, l_digest);
	if (memcmp(l_digest, a_bob->hash, SHASIZE) != 0) {
		return DHM_ERR_HASH_FAILURE;
	}
	if (a_debug) {
		printf("dhm_alice_secret: Bob packet hash OK (");
		for (i = 0; i < SHASIZE; ++i) {
			printf("%02X", l_digest[i]);
		}
		printf(")\n");
	}
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
