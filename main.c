#include <stdio.h>
#include <getopt.h>

#include "dhm.h"
#include "aes.h"

struct option g_options[] = {
	{ "debug", no_argument, NULL, 'd' },
	{ "showpacks", no_argument, NULL, 'p' },
	{ "help", no_argument, NULL, '?' },
	{ NULL, 0, NULL, 0 }
};

int g_debug = 0;
int g_showpacks = 0;

int main(int argc, char **argv)
{
	int i;
	int opt;
	while ((opt = getopt_long(argc, argv, "dp?", g_options, NULL)) != -1) {
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
			case '?':
				{
					printf("usage: dhmtest <-d/--debug> <-p/--showpacks>\n");
					exit(EXIT_SUCCESS);
				}
				break;
		}
	}
	
	printf("Diffie/Hellman/Merkle C Library Demonstration program\n");
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
		printf("p: ");
		for (i = 0; i < PUBSIZE; ++i) {
			printf("%02X", l_alice->p[i]);
		}
		printf("\n");
		printf("g: %d\n", ntohs(l_alice->g));
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
	return 0;
}

