#ifndef DHM_H
#define DHM_H

#pragma pack

#include <stdint.h>
#include <gmp.h>

#define PUBBITS 2176
#define PUBSIZE 272
#define PRIVBITS 368
#define PRIVSIZE 46

typedef struct {
	uint16_t g;
	uint8_t p[PUBSIZE];
	uint8_t A[PUBSIZE];
} dhm_alice_t;

typedef struct {
	uint8_t key[PRIVSIZE];
} dhm_private_t;

enum {
	DHM_ERR_NONE = 0,
	DHM_ERR_BOUNDS
} dhm_error_t;

dhm_error_t dhm_get_alice(dhm_alice_t *a_alice, dhm_private_t *a_alice_private);

#endif // DHM_H

