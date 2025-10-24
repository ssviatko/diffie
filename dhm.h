#ifndef DHM_H
#define DHM_H

#pragma pack(1)

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <gmp.h>

#define PUBBITS 2176
#define PUBSIZE 272
#define PRIVBITS 368
#define PRIVSIZE 46

#define GUIDSIZE 12 // size of unique session ID token

typedef struct {
	int urandom_fd;
	uint8_t guid[GUIDSIZE];
} dhm_session_t;

typedef struct {
	uint16_t g;
	uint8_t p[PUBSIZE];
	uint8_t A[PUBSIZE];
} dhm_alice_t;

typedef struct {
	uint8_t key[PRIVSIZE];
} dhm_private_t;

typedef enum {
	DHM_ERR_NONE = 0,
	DHM_ERR_OPENURANDOM,
	DHM_ERR_READURANDOM,
	DHM_ERR_CLOSEURANDOM,
	DHM_ERR_GENERAL
} dhm_error_t;

const char *dhm_strerror     (dhm_error_t a_errno);
dhm_error_t dhm_init_session (dhm_session_t *a_session, int a_debug);
dhm_error_t dhm_end_session  (dhm_session_t *a_session, int a_debug);
dhm_error_t dhm_get_alice    (dhm_session_t *a_session, dhm_alice_t *a_alice, dhm_private_t *a_alice_private, int a_debug);

#endif // DHM_H

