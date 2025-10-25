#include <stdio.h>
#include <getopt.h>

#include "dhm.h"
#include "aes.h"

struct option g_options[] = {
	{ "debug", no_argument, NULL, 'd' },
	{ "showpacks", no_argument, NULL, 'p' },
	{ "connect", required_argument, NULL, 'c' },
	{ "server", no_argument, NULL, 's' },
	{ "help", no_argument, NULL, '?' },
	{ NULL, 0, NULL, 0 }
};

int g_debug = 0;
int g_showpacks = 0;
char g_host[256];
int g_mode = 0; // 0=local, 1=client, 2=server

void mode_client()
{
	
}

void mode_server()
{
	
}

void mode_local()
{
	int i;
	dhm_error_t dhm_result;

	printf("local: calling dhm_init_session...\n");
	dhm_session_t *l_session = NULL;
	l_session = malloc(sizeof(dhm_session_t));
	if (l_session == NULL) {
		fprintf(stderr, "unable to allocate memory for DHM session.\n");
		exit(EXIT_FAILURE);
	}
	dhm_result = dhm_init_session(l_session, 1);
	if (dhm_result != DHM_ERR_NONE) {
		fprintf(stderr, "unable to dhm_init_session: %s\n", dhm_strerror(dhm_result));
		exit(EXIT_FAILURE);
	}
	
	printf("local: calling dhm_get_alice...\n");
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
	dhm_result = dhm_get_alice(l_session, l_alice, l_alice_private, g_debug);
	if (dhm_result != DHM_ERR_NONE) {
		fprintf(stderr, "unable to dhm_get_alice: %s\n", dhm_strerror(dhm_result));
		exit(EXIT_FAILURE);
	}
	
	if (g_showpacks == 1) {
		printf("local: completed Alice packet\n");
		printf("guid: ");
		for (i = 0; i < GUIDSIZE; ++i) {
			printf("%02X", l_alice->guid[i]);
		}
		printf("\np: ");
		for (i = 0; i < PUBSIZE; ++i) {
			printf("%02X", l_alice->p[i]);
		}
		printf("\ng: %d", ntohs(l_alice->g));
		printf("\na: ");
		for (i = 0; i < PRIVSIZE; ++i) {
			printf("%02X", l_alice_private->key[i]);
		}
		printf("\nA: ");
		for (i = 0; i < PUBSIZE; ++i) {
			printf("%02X", l_alice->A[i]);
		}
		printf("\n");
	}
	
	// clean up
	printf("local: calling dhm_end_session...\n");
	dhm_result = dhm_end_session(l_session, 1);
	if (dhm_result != DHM_ERR_NONE) {
		fprintf(stderr, "unable to dhm_end_session: %s\n", dhm_strerror(dhm_result));
		exit(EXIT_FAILURE);
	}
	free(l_alice);
	free(l_alice_private);
	free(l_session);
}

int main(int argc, char **argv)
{
	int opt;

	printf("Diffie/Hellman/Merkle C Library Demonstration program\n");
	
	while ((opt = getopt_long(argc, argv, "dp?c:s", g_options, NULL)) != -1) {
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
			case 'c':
				{
					if (g_mode != 0)
						break; // do nothing if we already selected something else
					g_mode = 1; // client mode
					strcpy(g_host, optarg);
					printf("selecting client mode\n");
					printf("attempting to connect to: %s\n", g_host);
				}
				break;
			case 's':
				{
					if (g_mode != 0)
						break;
					g_mode = 2;
					printf("selecting server mode\n");
				}
				break;
			case '?':
				{
					printf("usage: dhmtest <options>\n");
					printf("  -d (--debug) enable debug mode\n");
					printf("  -p (--showpacks) show completed packets\n");
					printf("  -? (--help) this screen\n");
					printf("  -c (--connect) <host> select client mode, specify host\n");
					printf("  -s (--server) select server mode\n");
					exit(EXIT_SUCCESS);
				}
				break;
		}
	}
	
	switch (g_mode) {
		case 0:
			mode_local();
			break;
		case 1:
			mode_client();
			break;
		case 2:
			mode_server();
			break;
		default:
			printf("I don't know what to do!\n");
			break;
	}
	
	return 0;
}

