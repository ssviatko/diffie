#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>

#include "sha2.h"
#include "aes.h"

#define BUFFLEN 1024

int g_debug = 0;

char g_infile[BUFFLEN];
int g_infile_specified = 0;
int g_infile_fd;

char g_outfile[BUFFLEN];
int g_outfile_specified = 0;
int g_outfile_fd;
int g_outfile_overwrite = 0;

char g_keyfile[BUFFLEN];
int g_keyfile_specified = 0;
uint8_t g_key[32];
uint8_t g_iv[16];

int g_urandom_fd;

typedef enum {
    MODE_NONE,
    MODE_PROCESS,
    MODE_GENERATE
} operational_mode;

operational_mode g_mode = MODE_NONE;

struct option g_options[] = {
    { "help", no_argument, NULL, '?' },
    { "debug", no_argument, NULL, 1001 },
    { "in", required_argument, NULL, 'i' },
    { "out", required_argument, NULL, 'o' },
    { "key", required_argument, NULL, 'k' },
    { "process", no_argument, NULL, 'p' },
    { "generate", no_argument, NULL, 'g' },
    { "overwrite", no_argument, NULL, 'w' },
    { NULL, 0, NULL, 0 }
};

void print_hex(uint8_t *a_buffer, size_t a_len)
{
    int i;
    for (i = 0; i < a_len; ++i) {
        if (i % 32 == 0)
            printf("\n");
        printf("%02X ", a_buffer[i]);
    }
    printf("\n");
}

void progress(uint32_t a_sofar, uint32_t a_total)
{
    static size_t l_lastsize = 0;
    int i;
    char l_txt[BUFFLEN];

    // cover over our previous message
    for (i = 0; i < l_lastsize; ++i)
        printf("\b");
    for (i = 0; i < l_lastsize; ++i)
        printf(" ");
    for (i = 0; i < l_lastsize; ++i)
        printf("\b");

    // print our message
    sprintf(l_txt, "(%d of %d) ", a_sofar, a_total);
    l_lastsize = strlen(l_txt);
    printf("%s", l_txt);
}

void load_key()
{
    if (g_keyfile_specified == 0) {
        fprintf(stderr, "aesctr: this operation requires that you specify a key file.\n");
        exit(EXIT_FAILURE);
    }
    int key_fd;
    int res;
    key_fd = open(g_keyfile, O_RDONLY);
    if (key_fd < 0) {
        fprintf(stderr, "aesctr: unable to open key file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    res = read(key_fd, g_key, 32);
    if (res < 0) {
        fprintf(stderr, "aesctr: unable to read key file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    res = read(key_fd, g_iv, 16);
    if (res < 0) {
        fprintf(stderr, "aesctr: unable to read key file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    close(key_fd);
    if (g_debug > 0) {
        printf("load_key: loaded key");
        print_hex(g_key, 32);
        printf("load_key: loaded iv");
        print_hex(g_iv, 16);
    }
}

void prepare_outfile()
{
    int res;

    // find out if outfile exists
    struct stat l_outfile_stat;
    res = stat(g_outfile, &l_outfile_stat);
    if (res == 0) {
        // successfully stat-ted the file. do we want to overwrite it?
        if (g_outfile_overwrite == 0) {
            fprintf(stderr, "aesctr: output file already exists (use -w or --overwrite to write to it anyway)\n");
            exit(EXIT_FAILURE);
        } else {
            printf("aesctr: overwriting existing output file %s\n", g_outfile);
        }
    } else if ((res < 0) && (errno == ENOENT)) {
        // this is what we want
    } else {
        // some other error from stat!
        fprintf(stderr, "aesctr: unable to stat output file to check its existence: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // open the output file
    if (g_debug) printf("prepare_outfile: opening and truncating output file\n");
    g_outfile_fd = open(g_outfile, O_RDWR | O_TRUNC | O_CREAT, (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
    if (g_outfile_fd < 0) {
        fprintf(stderr, "aesctr: error opening output file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void prepare_infile()
{
    int res;

    // find out infile length
    struct stat l_infile_stat;
    res = stat(g_infile, &l_infile_stat);
    if (res < 0) {
        fprintf(stderr, "aesctr: error calling stat on input file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    // open infile
    g_infile_fd = open(g_infile, O_RDONLY);
    if (g_infile_fd < 0) {
        fprintf(stderr, "aesctr: problems opening input file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void get_random(uint8_t *a_buffer, size_t a_len)
{
    int res;
    res = read(g_urandom_fd, a_buffer, a_len);
    if (res != a_len) {
        fprintf(stderr, "rsa: problems reading /dev/urandom: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void do_process()
{
}

void do_generate()
{
    // write 32 random bytes to g_keyfile
    int res;
    int key_fd;
    struct stat l_keyfile_stat;

    res = stat(g_keyfile, &l_keyfile_stat);
    if (res == 0) {
        if (g_outfile_overwrite == 0) {
            fprintf(stderr, "aesctr: key file already exists (use -w or --overwrite to write to it anyway)\n");
            exit(EXIT_FAILURE);
        } else {
            printf("aesctr: overwriting existing key file %s\n", g_outfile);
        }
    } else if ((res < 0) && (errno == ENOENT)) {
    } else {
        fprintf(stderr, "aesctr: unable to stat key file to check its existence: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    key_fd = open(g_keyfile, O_RDWR | O_TRUNC | O_CREAT, (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
    if (key_fd < 0) {
        fprintf(stderr, "aesctr: error opening key file for writing: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    get_random(g_key, 32);
    res = write(key_fd, g_key, 32);
    if (res < 0) {
        fprintf(stderr, "aesctr: unable to write to key file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    get_random(g_iv, 16);
    res = write(key_fd, g_iv, 16);
    if (res < 0) {
        fprintf(stderr, "aesctr: unable to write to key file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (g_debug > 0) {
        printf("do_generate: generated key");
        print_hex(g_key, 32);
        printf("do_generate: generated iv");
        print_hex(g_iv, 16);
    }
}

int main(int argc, char **argv)
{
    unsigned int i;
    int res; // result variable for UNIX reads
    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:k:pg?w", g_options, NULL)) != -1) {
        switch (opt) {
            case 1001:
            {
                g_debug = 1;
            }
            break;
             case 'i':
            {
                strcpy(g_infile, optarg);
                g_infile_specified = 1;
            }
            break;
            case 'o':
            {
                strcpy(g_outfile, optarg);
                g_outfile_specified = 1;
            }
            break;
            case 'k':
            {
                strcpy(g_keyfile, optarg);
                g_keyfile_specified = 1;
            }
            break;
            case 'w':
            {
                g_outfile_overwrite = 1;
            }
            break;
            case 'p':
            {
                if (g_mode != MODE_NONE) {
                    fprintf(stderr, "aesctr: please select only one operational mode.\n");
                    exit(EXIT_FAILURE);
                }
                g_mode = MODE_PROCESS;
            }
            break;
            case 'g':
            {
                if (g_mode != MODE_NONE) {
                    fprintf(stderr, "aesctr: please select only one operational mode.\n");
                    exit(EXIT_FAILURE);
                }
                g_mode = MODE_GENERATE;
            }
            break;
            case '?':
            {
                printf("usage: aesctr <options>\n");
                printf("  -i (--in) <name> specify input file\n");
                printf("  -o (--out) <name> specify output file\n");
                printf("  -k (--key) <name> specify full name of key file to use\n");
                printf("  -w (--overwrite) force overwrite of existing output file or key file\n");
                printf("     (--debug) use debug mode\n");
                printf("  -? (--help) this screen\n");
                printf("operational modes (select only one)\n");
                printf("  -p (--process) encrypt/decrypt in->out with specified key\n");
                printf("  -g (--generate) create random AES256 key\n");
                printf("       write random key to file specified by -k or --key\n");
                printf("examples\n");
                printf("  aesctr -gk <keyfile>  Generate new key and save to <keyfile>\n");
                printf("  aesctr -p -i <infile> -o <outfile> -k <keyfile>  Process in->out\n");
                exit(EXIT_SUCCESS);
            }
            break;
        }
    }

    setbuf(stdout, NULL); // disable buffering so we can print our progress

    if (g_debug > 0)
        printf("aesctr: debug mode enabled.\n");

    if (g_infile_specified > 0) {
        printf("aesctr: input file : %s\n", g_infile);
    }
    if (g_outfile_specified > 0) {
        printf("aesctr: output file: %s\n", g_outfile);
    }
    if (g_keyfile_specified > 0) {
        printf("aesctr: key file   : %s\n", g_keyfile);
    }

    // prepare urandom
    g_urandom_fd = open("/dev/urandom", O_RDONLY);
    if (g_urandom_fd < 0) {
        fprintf(stderr, "aesctr: problems opening /dev/urandom: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    switch (g_mode) {
        case MODE_NONE:
        {
            fprintf(stderr, "aesctr: you must select one operational mode.\n");
            fprintf(stderr, "aesctr: use -? or --help for usage info.\n");
            exit(EXIT_FAILURE);
        }
        break;
        case MODE_PROCESS:
        {
            printf("aesctr: selected process mode.\n");
            load_key();
            if (g_infile_specified == 0) {
                fprintf(stderr, "aesctr: this function requires that you specify an input file.\n");
                exit(EXIT_FAILURE);
            }
            prepare_infile();
            if (g_outfile_specified == 0) {
                fprintf(stderr, "aesctr: this function requires that you specify an output file.\n");
                exit(EXIT_FAILURE);
            }
            prepare_outfile();
            do_process();
        }
        break;
        case MODE_GENERATE:
        {
            printf("aesctr: selected generate mode.\n");
            if (g_keyfile_specified == 0) {
                fprintf(stderr, "aesctr: this function requires that you specify a keyfile to write.\n");
                exit(EXIT_FAILURE);
            }
            do_generate();
        }
        break;
        default:
        {
            printf("I don't know what to do!\n");
        }
        break;
    }

    return 0;
}
