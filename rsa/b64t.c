#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "ccct.h"

int main(int argc, char **argv)
{
	char *message = "The quick brown fox jumps over the lazy dog four times I believe last thursday without question it happened and this should be a nice long message to use for our base64 test application.";
	char b64[256];
	char b64_formatted[1024];
	char b64_unformatted[256];
	char decoded[256];
	unsigned int decoded_len;

	printf("message: len %ld - %s\n", strlen(message), message);
	ccct_base64_encode((uint8_t *)message, strlen(message) + 1, b64);
	printf("encode len: %ld encoded message: %s\n", strlen(b64), b64);
	ccct_base64_format(b64, b64_formatted, "BEGIN FOXY MESSAGE", "END FOXY MESSAGE");
	printf("formatted message:\n%s\n", b64_formatted);
	ccct_base64_unformat(b64_formatted, b64_unformatted);
	printf("unformatted message: len %ld - %s\n",strlen(b64_unformatted), b64_unformatted);
	int ret = ccct_base64_decode(b64_unformatted, decoded, &decoded_len);
	printf("decode returned %d, len %d, message: %s\n", ret, decoded_len, decoded);

	unsigned long long a = 0xc0edbabedeadbeefULL;
	char beef[32];
	ccct_base64_encode((uint8_t *)&a, sizeof(a), beef);
	printf("long long: %s\n", beef);
	char ll[8];
	ccct_base64_decode(beef, ll, &decoded_len);
	printf("long long decoded: len %d - %016llX\n", decoded_len, *((unsigned long long *)ll));
	return 0;
}
