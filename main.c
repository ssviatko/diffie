#include <stdio.h>
#include <stdint.h>
#include <getopt.h>

#include "dhm.h"
#include "aes.h"

struct option g_options[] = {
	{ "debug", no_argument, NULL, 'd' },
	{ "showpacks", no_argument, NULL, 'p' },
	{ "connect", required_argument, NULL, 'c' },
	{ "server", no_argument, NULL, 's' },
	{ "help", no_argument, NULL, '?' },
	{ "port", required_argument, NULL, 'o' },
	{ NULL, 0, NULL, 0 }
};

int g_debug = 0;
int g_showpacks = 0;
char g_host[256];
int g_mode = 0; // 0=local, 1=client, 2=server
uint16_t g_port = 9734;

void mode_client()
{
	printf("attempting to connect to: %s on port %d\n", g_host, g_port);
}

void mode_server()
{
	printf("establishing a TCP server on port %d\n", g_port);
}

void mode_local()
{
	int i;
	dhm_error_t dhm_result;

	dhm_session_t *l_alice_session = NULL;
	l_alice_session = malloc(sizeof(dhm_session_t));
	if (l_alice_session == NULL) {
		fprintf(stderr, "unable to allocate memory for DHM session.\n");
		exit(EXIT_FAILURE);
	}
	printf("local (Alice): calling dhm_init_session for Alice session...\n");
	dhm_result = dhm_init_session(l_alice_session, 1);
	if (dhm_result != DHM_ERR_NONE) {
		fprintf(stderr, "unable to dhm_init_session: %s\n", dhm_strerror(dhm_result));
		exit(EXIT_FAILURE);
	}
	
	dhm_alice_t *l_alice = NULL;
	l_alice = malloc(sizeof(dhm_alice_t));
	if (l_alice == NULL) {
		fprintf(stderr, "unable to allocate memory for Alice packet.\n");
		exit(EXIT_FAILURE);
	}
	dhm_private_t *l_alice_private = NULL;
	l_alice_private = malloc(sizeof(dhm_private_t));
	if (l_alice_private == NULL) {
		fprintf(stderr, "unable to allocate memory for Alice private key.\n");
		exit(EXIT_FAILURE);
	}
	printf("local (Alice): calling dhm_get_alice...\n");
	dhm_result = dhm_get_alice(l_alice_session, l_alice, l_alice_private, g_debug);
	if (dhm_result != DHM_ERR_NONE) {
		fprintf(stderr, "unable to dhm_get_alice: %s\n", dhm_strerror(dhm_result));
		exit(EXIT_FAILURE);
	}
	
	if (g_showpacks == 1) {
		printf("local (Alice): completed Alice packet\n");
		printf("hash: ");
		for (i = 0; i < SHASIZE; ++i) {
			printf("%02X", l_alice->hash[i]);
		}
		printf("\nguid: ");
		for (i = 0; i < GUIDSIZE; ++i) {
			printf("%02X", l_alice->guid[i]);
		}
		printf("\np: ");
		for (i = 0; i < PUBSIZE; ++i) {
			printf("%02X", l_alice->p[i]);
		}
		printf("\ng: %d", ntohs(l_alice->g));
		printf("\nA: ");
		for (i = 0; i < PUBSIZE; ++i) {
			printf("%02X", l_alice->A[i]);
		}
		printf("\n");
		printf("local (Alice): Alice's private key\n");
		printf("a: ");
		for (i = 0; i < PRIVSIZE; ++i) {
			printf("%02X", l_alice_private->key[i]);
		}
		printf("\n");
	}
	
	printf("local: ...simulating sending Alice packet to Bob over insecure link...\n");
	
	// Bob has received Alice packet, take over now from Bob's perspective.
	// Bob needs his own session; allocate memory for it but do not initialize
	dhm_session_t *l_bob_session = NULL;
	l_bob_session = malloc(sizeof(dhm_session_t));
	if (l_bob_session == NULL) {
		fprintf(stderr, "unable to allocate memory for DHM Bob session.\n");
		exit(EXIT_FAILURE);
	}
	printf("local (Bob): calling dhm_init_session for Bob session...\n");
	dhm_result = dhm_init_session(l_bob_session, 1);
	if (dhm_result != DHM_ERR_NONE) {
		fprintf(stderr, "unable to dhm_init_session: %s\n", dhm_strerror(dhm_result));
		exit(EXIT_FAILURE);
	}
	dhm_bob_t *l_bob = NULL;
	l_bob = malloc(sizeof(dhm_bob_t));
	if (l_bob == NULL) {
		fprintf(stderr, "unable to allocate memory for Bob packet.\n");
		exit(EXIT_FAILURE);
	}
	dhm_private_t *l_bob_private = NULL;
	l_bob_private = malloc(sizeof(dhm_private_t));
	if (l_bob_private == NULL) {
		fprintf(stderr, "unable to allocate memory for Bob private key.\n");
		exit(EXIT_FAILURE);
	}
	printf("local (Bob): calling dhm_get_bob...\n");
	dhm_result = dhm_get_bob(l_bob_session, l_alice, l_bob, l_bob_private, g_debug);
	if (dhm_result != DHM_ERR_NONE) {
		fprintf(stderr, "unable to dhm_get_bob: %s\n", dhm_strerror(dhm_result));
		exit(EXIT_FAILURE);
	}
	if (g_showpacks == 1) {
		printf("local (Bob): completed Bob packet\n");
		printf("guid: ");
		for (i = 0; i < GUIDSIZE; ++i) {
			printf("%02X", l_bob->guid[i]);
		}
		printf("\n");
		printf("B: ");
		for (i = 0; i < PUBSIZE; ++i) {
			printf("%02X", l_bob->B[i]);
		}
		printf("\n");
		printf("local (Bob): Bob's private key\n");
		printf("b: ");
		for (i = 0; i < PRIVSIZE; ++i) {
			printf("%02X", l_bob_private->key[i]);
		}
		printf("\n");
		printf("local (Bob): secret key\n");
		printf("s: ");
		for (i = 0; i < PUBSIZE; ++i) {
			printf("%02X", l_bob_session->s[i]);
		}
		printf("\n");
	}
	printf("local (Bob):   secret (AES256 key): ");
	for (i = 0; i < 32; ++i) {
		printf("%02X", l_bob_session->s[i]);
	}
	printf("\n");

	printf("local: ...simulating sending Bob packet back to Alice over insecure link...\n");
	
	// Alice has received Bob's reply packet and now will use it to compute her copy of the secret
	
	printf("local (Alice): calling dhm_alice_secret\n");
	dhm_alice_secret(l_alice_session, l_alice, l_bob, l_alice_private, g_debug);
	if (g_showpacks) {
		printf("local (Alice): secret key\n");
		printf("s: ");
		for (i = 0; i < PUBSIZE; ++i) {
			printf("%02X", l_alice_session->s[i]);
		}
		printf("\n");
	}
	printf("local (Alice): secret (AES256 key): ");
	for (i = 0; i < 32; ++i) {
		printf("%02X", l_alice_session->s[i]);
	}
	printf("\n");
	
	// clean up
	printf("local (cleanup): calling dhm_end_session for Alice session...\n");
	dhm_result = dhm_end_session(l_alice_session, 1);
	if (dhm_result != DHM_ERR_NONE) {
		fprintf(stderr, "unable to dhm_end_session: %s\n", dhm_strerror(dhm_result));
		exit(EXIT_FAILURE);
	}
	printf("local (cleanup): calling dhm_end_session for Bob session...\n");
	dhm_result = dhm_end_session(l_bob_session, 1);
	if (dhm_result != DHM_ERR_NONE) {
		fprintf(stderr, "unable to dhm_end_session: %s\n", dhm_strerror(dhm_result));
		exit(EXIT_FAILURE);
	}
	free(l_alice);
	free(l_alice_private);
	free(l_alice_session);
	free(l_bob);
	free(l_bob_private);
	free(l_bob_session);
}

int main(int argc, char **argv)
{
	int opt;

	printf("Diffie/Hellman/Merkle C Library Demonstration program\n");
	printf("-? or --help for usage and information.\n");
	
	while ((opt = getopt_long(argc, argv, "dp?c:so:", g_options, NULL)) != -1) {
		switch (opt) {
			case 'd':
				{
					g_debug = 1;
					printf("debug mode enabled.\n");
				}
				break;
			case 'p':
				{
					g_showpacks = 1;
					printf("showing constructed packets.\n");
				}
				break;
			case 'o':
				{
					g_port = atoi(optarg);
				}
				break;
			case 'c':
				{
					if (g_mode != 0)
						break; // do nothing if we already selected something else
					g_mode = 1; // client mode
					strcpy(g_host, optarg);
				}
				break;
			case 's':
				{
					if (g_mode != 0)
						break;
					g_mode = 2;
				}
				break;
			case '?':
				{
					printf("usage: dhmtest <options>\n");
					printf("  -d (--debug) enable debug mode\n");
					printf("  -p (--showpacks) show completed packets\n");
					printf("  -? (--help) this screen\n");
					printf("  -o (--port) specify IP port to use (default 9734)\n");
					printf("  -c (--connect) <host> select client mode, specify host\n");
					printf("  -s (--server) select server mode\n");
					exit(EXIT_SUCCESS);
				}
				break;
		}
	}
	
	switch (g_mode) {
		case 0:
			printf("selecting local mode\n");
			mode_local();
			break;
		case 1:
			printf("selecting client mode\n");
			mode_client();
			break;
		case 2:
			printf("selecting server mode\n");
			mode_server();
			break;
		default:
			printf("I don't know what to do!\n");
			break;
	}
	
	return 0;
}

