#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#pragma pack(1)

#include "dhm.h"
#include "aes.h"

#define BUFFLEN 1024

/* protocol stuff */

const uint16_t outer_current_version = 0x0101;
const uint16_t outer_packtype_dieplease = 0xd4d2; // request the server terminate
const uint16_t outer_packtype_textecho = 0xd4d3;
const uint16_t outer_packtype_alice = 0xd4d4; // packet contains an Alice packet
const uint16_t outer_packtype_bob = 0xd4d5; // packet contains a Bob packet
const uint16_t outer_packtype_aes = 0xd4d6; // packet contains AES256/CTR encrypted data

typedef struct {
	uint16_t version;
	uint16_t packtype;
	uint16_t size; // size of payload
	uint32_t sequence; // monotonically incrementing packet counter
} outer_packet_header_t;

/* getopt */

struct option g_options[] = {
	{ "debug", no_argument, NULL, 'd' },
	{ "showpacks", no_argument, NULL, 'p' },
	{ "connect", required_argument, NULL, 'c' },
	{ "server", no_argument, NULL, 's' },
	{ "help", no_argument, NULL, '?' },
	{ "port", required_argument, NULL, 'o' },
	{ "greeting", required_argument, NULL, 'g' },
	{ "reqsd", no_argument, NULL, 'x' },
	{ NULL, 0, NULL, 0 }
};

int g_debug = 0;
int g_showpacks = 0;
char g_host[BUFFLEN];
int g_mode = 0; // 0=local, 1=client, 2=server
uint16_t g_port = 9734;
char g_greeting[BUFFLEN];
int g_reqsd = 0;

int write_packet(int a_sockfd, uint16_t a_packtype, void *a_data, size_t a_size)
{
	static uint32_t s_sequence = 1;
	int i;
	
	// allocate space for packet header + packet data
	uint8_t *l_pack = NULL;
	size_t l_pack_size = sizeof(outer_packet_header_t) + a_size;
	l_pack = malloc(l_pack_size);
	if (l_pack == NULL) {
		fprintf(stderr, "write_packet: can't allocate space for packet\n");
		exit(EXIT_FAILURE);
	}
	// fill in outer packet header
	outer_packet_header_t l_header;
	l_header.size = htons(a_size);
	l_header.packtype = htons(a_packtype);
	l_header.version = htons(outer_current_version);
	l_header.sequence = htonl(s_sequence++);
	
	// assemble packet
	memcpy(l_pack, &l_header, sizeof(outer_packet_header_t));
	memcpy(l_pack + sizeof(outer_packet_header_t), a_data, a_size);
	
	if (g_showpacks) {
		// show the packet if the showpacks flag is on
		printf("write_packet: sending packet to fd %d\n", a_sockfd);
		printf("  version: %04X\n", ntohs(l_header.version));
		printf("  packtype: %04X\n", ntohs(l_header.packtype));
		printf("  sequence: %d\n", ntohl(l_header.sequence));
		printf("  data: (size: %d)", ntohs(l_header.size));
		for (i = 0; i < l_pack_size; ++i) {
			if (i % 32 == 0)
				printf("\n");
			printf("%02X ", l_pack[i]);
		}
		printf("\n");
	}
	
	int writelen;
	writelen = write(a_sockfd, l_pack, l_pack_size);
	free(l_pack);
	return writelen;
}

int read_packet(int a_sockfd, outer_packet_header_t **a_header, uint8_t **a_data)
{
	// reads packet, returns a header block and a data packet which the user will be responsible for freeing
	// in case of error, returns -1 and internally frees any data structures it allocated.
	
	int readlen = 0;
	int i;

	outer_packet_header_t *l_header = NULL;
	l_header = malloc(sizeof(outer_packet_header_t));
	if (l_header == NULL) {
		fprintf(stderr, "read_packet: can't allocate header\n");
		return -1;
	}
	// read in the header
	readlen = read(a_sockfd, l_header, sizeof(outer_packet_header_t));
	if (readlen != sizeof(outer_packet_header_t)) {
		fprintf(stderr, "read_packet: failure reading packet header, expected %ld bytes, got %d\n", sizeof(outer_packet_header_t), readlen);
		free(l_header);
		return -1;
	}
	// allocate buffer for actual packet based on size field of header
	uint8_t *l_data = NULL;
	l_data = malloc(ntohs(l_header->size));
	if (l_data == NULL) {
		fprintf(stderr, "read_packet: can't allocate space for packet data\n");
		free(l_header);
		return -1;
	}
	// read in packet data
	readlen = read(a_sockfd, l_data, ntohs(l_header->size));
	if (readlen != ntohs(l_header->size)) {
		fprintf(stderr, "read_packet: failure to read packet data, expected %d bytes, got %d\n", l_header->size, readlen);
		free(l_header);
		free(l_data);
		return -1;
	}
	if (g_showpacks) {
		// show the packet if the showpacks flag is on
		printf("read_packet: read packet from fd %d\n", a_sockfd);
		printf("  version: %04X\n", ntohs(l_header->version));
		printf("  packtype: %04X\n", ntohs(l_header->packtype));
		printf("  sequence: %d\n", ntohl(l_header->sequence));
		printf("  data: (size: %d)", ntohs(l_header->size));
		for (i = 0; i < ntohs(l_header->size); ++i) {
			if (i % 32 == 0)
				printf("\n");
			printf("%02X ", l_data[i]);
		}
		printf("\n");
	}

	*a_header = l_header;
	*a_data = l_data;
	// user is responsible for freeing these now
	return 0;
}

void client_action(int sockfd)
{
	// read and write via sockfd
	int writelen;
	// are we requesting a shutdown?
	if (g_reqsd > 0) {
		writelen = write_packet(sockfd, outer_packtype_dieplease, g_greeting, strlen(g_greeting) + 1);
		if (writelen == 0) {
			fprintf(stderr, "client: EOF detected on reqsd write, exiting\n");
			close(sockfd);
			return;
		} else if (writelen < 0) {
			// problems writing, fatal error
			fprintf(stderr, "client: reqsd write: can't write_packet: %s\n", strerror(errno));
			close(sockfd);
			return;
		}
		close(sockfd);
		printf("client: sent termination packet to server.\n");
		return;
	}
	// write the trailing zero in our string for convenience
	writelen = write_packet(sockfd, outer_packtype_textecho, g_greeting, strlen(g_greeting) + 1);
	if (writelen == 0) {
		fprintf(stderr, "client: EOF detected, exiting\n");
		close(sockfd);
		return;
	} else if (writelen < 0) {
		// problems writing, fatal error
		fprintf(stderr, "client: can't write_packet: %s\n", strerror(errno));
		close(sockfd);
		return;
	}
	printf("client: write %d byte packet to server.\n", writelen);
	
	outer_packet_header_t *l_read_header = NULL;
	uint8_t *l_read_packet = NULL;
	int read_packet_return = read_packet(sockfd, &l_read_header, &l_read_packet);
	if (read_packet_return < 0) {
		fprintf(stderr, "client: error reading reply packet\n");
		close(sockfd);
		return;
	}
	printf("client: received packet type %04X, sequence %d from server.\n", ntohs(l_read_header->packtype), ntohl(l_read_header->sequence));
	printf("client: read string: (size=%d) %s\n", ntohs(l_read_header->size), l_read_packet);
	free(l_read_header);
	free(l_read_packet);
	close(sockfd);
}

void mode_client()
{
	printf("attempting to connect to: %s on port %d\n", g_host, g_port);
	int sockfd;
	int len;
	struct sockaddr_in address;
	int res;

	// create a socket for the client
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// name the socket as agreed with the server
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(g_host);
	address.sin_port = htons(g_port);
	len = sizeof(address);

	// connect our socket to the server's socket
	res = connect(sockfd, (struct sockaddr *)&address, len);
	if (res < 0) {
		fprintf(stderr, "client: can't connect to %s: %s\n", g_host, strerror(errno));
		exit(EXIT_FAILURE);
	}

	printf("client: connected.\n");
	client_action(sockfd);
}

int server_action(int client_sockfd)
{
	// read and write to client on client_sockfd
	outer_packet_header_t *l_read_header = NULL;
	uint8_t *l_read_packet = NULL;
	int read_packet_return = read_packet(client_sockfd, &l_read_header, &l_read_packet);
	if (read_packet_return < 0) {
		fprintf(stderr, "server: error reading incoming packet\n");
		close(client_sockfd);
		return 0;
	}
	// check if we received termination request
	if (ntohs(l_read_header->packtype) == outer_packtype_dieplease) {
		printf("server: received termination packet\n");
		printf("server: termination message: %s\n", l_read_packet);
		free(l_read_header);
		free(l_read_packet);
		close(client_sockfd);
		return -1;
	}
	printf("server: received packet type %04X, sequence %d from client.\n", ntohl(l_read_header->packtype), ntohl(l_read_header->sequence));
	printf("server: read string: (size=%d) %s\n", ntohs(l_read_header->size), l_read_packet);
	// prepare reply message
	char l_buff[BUFFLEN];
	sprintf(l_buff, "greetings from the server\nmy greeting: %s\nyou sent: %s\n", g_greeting, l_read_packet);
	free(l_read_header); // don't need these anymore
	free(l_read_packet);
	
	// echo the string back
	int writelen;
	writelen = write_packet(client_sockfd, outer_packtype_textecho, l_buff, strlen(l_buff) + 1);
	if (writelen == 0) {
		fprintf(stderr, "server: EOF detected, hanging up\n");
		close(client_sockfd);
		return 0;
	} else if (writelen < 0) {
		// problems reading, nonfatal error that will recycle the server
		fprintf(stderr, "server: can't write_packet: %s\n", strerror(errno));
		close(client_sockfd);
		return 0;
	}
	printf("server: write %d byte packet back to client.\n", writelen);

	close(client_sockfd);
	return 0;
}

void mode_server()
{
	printf("establishing a TCP server on port %d\n", g_port);

	// set up variables
	int res;
	int server_sockfd, client_sockfd;
	unsigned int server_len, client_len;
	struct sockaddr_in server_address;
	struct sockaddr_in client_address;

	// remove any old sockets and create an unnamed socket for the server
	server_sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// name the socket
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(g_port);
	server_len = sizeof(server_address);
	int reuse = 1;
	if (setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
		// can't setsockopt, this is a fatal error
		fprintf(stderr, "server: can't setsockopt: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	res = bind(server_sockfd, (struct sockaddr *)&server_address, server_len);
	if (res < 0) {
		// can't bind, this is a fatal error
		fprintf(stderr, "server: can't bind: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	// create a connection queue and wait for clients
	listen(server_sockfd, 5);
	while (1) {
		printf("server: waiting for connection...\n");
		
		// accept a connection
		client_len = sizeof(client_address);
		client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_address, &client_len);

		printf("server: client %s:%d connecting...\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));
		if (server_action(client_sockfd) < 0) {
			printf("server: gracefully shutting down...\n");
			close(server_sockfd);
			return;
		}
	}
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
	
	// set up default greeting in case user doesn't enter one
	strcpy(g_greeting, "Default greeting");
	
	while ((opt = getopt_long(argc, argv, "dp?c:so:g:x", g_options, NULL)) != -1) {
		switch (opt) {
			case 'x':
				{
					g_reqsd = 1;
					printf("requesting server shutdown.\n");
				}
				break;
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
			case 'g':
				{
					strcpy(g_greeting, optarg);
				}
				break;
			case '?':
				{
					printf("usage: dhmtest <options>\n");
					printf("  -d (--debug) enable debug mode\n");
					printf("  -p (--showpacks) show completed packets\n");
					printf("  -? (--help) this screen\n");
					printf("  -o (--port) specify IP port to use (default 9734)\n");
					printf("  -g (--greeting) specify greeting message for socket communications\n");
					printf("  -c (--connect) <IP> select client mode, specify host in dotted IP format\n");
					printf("  -x (--reqsd) client mode only: request server shut down gracefully\n");
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

