/**
 *
 * Diffie/Hellman/Merkle Implementation
 * 2025/Nov/11 - Revision 1
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
  * @file: dhm.h
 * @brief: Diffie/Hellman/Merkle API
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

#ifndef DHM_H
#define DHM_H

#pragma pack(1)

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <gmp.h>
#include <arpa/inet.h>

#include "sha2.h"

#define PUBBITS 2176 ///< bit width of public modulus
#define PUBSIZE 272 ///< size of public modulus in bytes
#define PRIVBITS 368 ///< bit width of private exponent(s)
#define PRIVSIZE 46 ///< size of private exponent(s) in bytes

#define GUIDSIZE 12 ///< size of unique session ID token
#define SHASIZE 28 ///< size of a SHA2-224 hash

/**
 * @struct dhm_session_t
 * @brief Store data relevant to a DHM session.
 * It can be envisioned to be like a "context" used
 * by an encryption library to establish a context or session.
 */

typedef struct {
	int urandom_fd; ///< File descriptor of open /dev/urandom device, used for reading cryptographically random bytes
	uint8_t guid[GUIDSIZE]; ///< Unique global user identification used to identify the session, this gets stamped into packets
	uint8_t s[PUBSIZE]; ///< Space for the computed secret, after "Alice" and "Bob" have exchanged packets
} dhm_session_t;

/**
 * @struct dhm_alice_t
 * @brief The "Alice" packet, created by the client to establish a Diffie/Hellman/Merkle conversation with a server.
 */

typedef struct {
	uint16_t packtype; ///< Packet type stamp, so receiver can identify this as an Alice packet
	uint8_t hash[SHASIZE]; ///< SHA2 hash of everything subsequent to this field
	uint8_t guid[GUIDSIZE]; ///< GUID, copied from the GUID established in dhm_session_t
	uint16_t g; ///< Generator primitive, randomly chosen to be either 3 or 5
	uint8_t p[PUBSIZE]; ///< Public key, which is a gigantic prime number
	uint8_t A[PUBSIZE]; ///< Result of modular exponentiation of generator with private exponent and public modulus
} dhm_alice_t;

/**
 * @struct dhm_bob_t
 * @brief The "Bob" packet, created by the server in response to an "Alice" packet.
 */

typedef struct {
	uint16_t packtype; ///< Packet typ stamp, so receiver can identify this as a Bob packet
	uint8_t hash[SHASIZE]; ///< SHA2 hash of everything subsequent to this field
	uint8_t guid[GUIDSIZE]; ///< GUID, copied from the Alice packet received previously
	uint8_t B[PUBSIZE]; ///< Result of modular exponentiation of generator with private exponent and public modulus
} dhm_bob_t;

/**
 * @struct dhm_private_t
 * @brief Private key structure
 * This holds space for Alice and Bob's private keys, which are kept secret and never shared
 */

typedef struct {
	uint8_t key[PRIVSIZE]; ///< Space for private key
} dhm_private_t;

/**
 * @enum dhm_error_t
 * @brief An enumerated list of return error codes.
 */

typedef enum {
	DHM_ERR_NONE = 0, ///< No error occurred, situation nominal
	DHM_ERR_OPENURANDOM, ///< Problems opening /dev/urandom
	DHM_ERR_READURANDOM, ///< Problems reading from /dev/urandom
	DHM_ERR_CLOSEURANDOM, ///< Problems closing /dev/urandom
	DHM_ERR_VALUE, ///< Generic value error
	DHM_ERR_GENERAL, ///< General unspecified error
	DHM_ERR_WRONG_PACKTYPE, ///< Received an unexpected packet type
	DHM_ERR_HASH_FAILURE ///< Hash mismatch error
} dhm_error_t;

const char *dhm_strerror     (dhm_error_t a_errno);
dhm_error_t dhm_init_session (dhm_session_t *a_session, int a_debug);
dhm_error_t dhm_end_session  (dhm_session_t *a_session, int a_debug);
dhm_error_t dhm_get_alice    (dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_private_t *a_alice_private, int a_debug);
dhm_error_t dhm_get_bob      (dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_bob_t *a_bob, dhm_private_t *a_bob_private, int a_debug);
dhm_error_t dhm_alice_secret (dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_bob_t *a_bob, dhm_private_t *a_alice_private, int a_debug);

#endif // DHM_H

