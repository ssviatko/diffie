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

#define PUBBITS 2176
#define PUBSIZE 272
#define PRIVBITS 368
#define PRIVSIZE 46

#define GUIDSIZE 12 // size of unique session ID token
#define SHASIZE 28 // size of a SHA2-224 hash

typedef struct {
	int urandom_fd;
	uint8_t guid[GUIDSIZE];
	uint8_t s[PUBSIZE];
} dhm_session_t;

typedef struct {
	uint16_t packtype;
	uint8_t hash[SHASIZE]; // hash of everything subsequent to this field
	uint8_t guid[GUIDSIZE];
	uint16_t g;
	uint8_t p[PUBSIZE];
	uint8_t A[PUBSIZE];
} dhm_alice_t;

typedef struct {
	uint16_t packtype;
	uint8_t hash[SHASIZE];
	uint8_t guid[GUIDSIZE];
	uint8_t B[PUBSIZE];
} dhm_bob_t;

typedef struct {
	uint8_t key[PRIVSIZE];
} dhm_private_t;

typedef enum {
	DHM_ERR_NONE = 0,
	DHM_ERR_OPENURANDOM,
	DHM_ERR_READURANDOM,
	DHM_ERR_CLOSEURANDOM,
	DHM_ERR_VALUE,
	DHM_ERR_GENERAL,
	DHM_ERR_WRONG_PACKTYPE,
	DHM_ERR_HASH_FAILURE
} dhm_error_t;

const char *dhm_strerror     (dhm_error_t a_errno);
dhm_error_t dhm_init_session (dhm_session_t *a_session, int a_debug);
dhm_error_t dhm_end_session  (dhm_session_t *a_session, int a_debug);
dhm_error_t dhm_get_alice    (dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_private_t *a_alice_private, int a_debug);
dhm_error_t dhm_get_bob      (dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_bob_t *a_bob, dhm_private_t *a_bob_private, int a_debug);
dhm_error_t dhm_alice_secret (dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_bob_t *a_bob, dhm_private_t *a_alice_private, int a_debug);

#endif // DHM_H

