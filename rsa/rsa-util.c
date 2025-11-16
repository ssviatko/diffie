/**
 *
 * RSA Implementation
 * 2025/Nov/15 - Revision 0.80 alpha
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
 * @file rsa-util.c
 * @brief RSA file encryptor/digital signature utility
 *
 * This file implements RSA encryption/decryption of files, and digital
 * signatures and verification of files.
 *
 * Usage:
 *
 * ./rsa-util
 *
 * (see usage screen for more details using -? or --help switch)
 *
 * Build Info:
 *
 * type "make"
 *
 * Linking: RSA uses the GMP (Gnu Multi-Precision) library to compute various
 * coefficients needed for the RSA algorithms to work, and as a result of
 * this you will need to have the GMP library and its relevant headers loaded
 * onto your system in order to build.
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <gmp.h>
#include <sys/time.h>
#include <getopt.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "ccct.h"
#include "sha2.h"

#pragma pack(1)

#define MAXBITS 262144
#define MAXBYTEBUFF (MAXBITS / 8)

#define BUFFLEN 1024
#define PADDING 12 // amount of random padding per block

#define MAXTHREADS 48

struct timeval g_start_time, g_end_time;

uint8_t g_n[MAXBYTEBUFF];
int g_n_loaded = 0;
uint8_t g_e[sizeof(uint32_t)];
int g_e_loaded = 0;
uint8_t g_d[MAXBYTEBUFF];
int g_d_loaded = 0;
uint8_t g_p[MAXBYTEBUFF];
int g_p_loaded = 0;
uint8_t g_q[MAXBYTEBUFF];
int g_q_loaded = 0;
uint8_t g_dp[MAXBYTEBUFF];
int g_dp_loaded = 0;
uint8_t g_dq[MAXBYTEBUFF];
int g_dq_loaded = 0;
uint8_t g_qinv[MAXBYTEBUFF];
int g_qinv_loaded = 0;

int g_nochinese = 0; // set to 1 to disable chinese remainder theory calculations

uint8_t g_buff[MAXBYTEBUFF]; // general buffer
uint8_t g_buff2[MAXBYTEBUFF]; // auziliary buffer

const uint8_t KIHT_MODULUS = 1;
const uint8_t KIHT_PUBEXP = 2;
const uint8_t KIHT_PRIVEXP = 3;
const uint8_t KIHT_P = 4;
const uint8_t KIHT_Q = 5;
const uint8_t KIHT_DP = 6;
const uint8_t KIHT_DQ = 7;
const uint8_t KIHT_QINV = 8;

typedef struct {
    uint8_t type;
    uint32_t bit_width;
} key_item_header;

char g_infile[BUFFLEN];
int g_infile_specified = 0;
int g_infile_fd;
off_t g_infile_length;
uint32_t g_infile_crc; // calculated during encrypt and sign operations

char g_outfile[BUFFLEN];
int g_outfile_specified = 0;
int g_outfile_fd;
int g_outfile_overwrite = 0;
uint32_t g_outfile_crc; // calculated during decrypt and verify

char g_keyfile[BUFFLEN];
int g_keyfile_specified = 0;
uint32_t g_bits = 0;

char g_signaturefile[BUFFLEN];
int g_signaturefile_specified = 0;
int g_signaturefile_fd;

int g_urandom_fd;

// block related
uint32_t g_block_size;
int g_infile_block_multiple = 0; // is infile a multiple of the specified block size?
uint32_t g_block_capacity; // block size minus padding bytes, based on key size
uint32_t g_1stblock_capacity; // first block capacity minus fileinfo header
float g_latitude = 0.0;
float g_longitude = 0.0;

typedef struct {
    uint8_t flags; // high bit 1 = signed content, 0 = conventionally encrypted
    uint32_t size;
    uint32_t size_xor;
    uint32_t crc;
    uint32_t crc_xor;
    ccct_reversible_int64_t time;
    ccct_reversible_float_t latitude;
    ccct_reversible_float_t longitude;
} fileinfo_header;

int g_debug = 0;

typedef enum {
    MODE_NONE,
    MODE_ENCRYPT,
    MODE_DECRYPT,
    MODE_SIGN,
    MODE_VERIFY,
    MODE_TELL
} operational_mode;

operational_mode g_mode = MODE_NONE;;

struct option g_options[] = {
    { "help", no_argument, NULL, '?' },
    { "debug", no_argument, NULL, 1001 },
    { "in", required_argument, NULL, 'i' },
    { "out", required_argument, NULL, 'o' },
    { "key", required_argument, NULL, 'k' },
    { "signature", required_argument, NULL, 'g' },
    { "encrypt", no_argument, NULL, 'e' },
    { "decrypt", no_argument, NULL, 'd' },
    { "sign", no_argument, NULL, 's' },
    { "verify", no_argument, NULL, 'v' },
    { "tell", no_argument, NULL, 't' },
    { "overwrite", no_argument, NULL, 'w' },
    { "latitude", required_argument, NULL, 1002 },
    { "longitude", required_argument, NULL, 1003 },
    { "threads", required_argument, NULL, 1004 },
    { "nochinese", no_argument, NULL, 1005 },
    { NULL, 0, NULL, 0 }
};

// concurrency during decryption process
typedef struct {
    pthread_t thread;
    unsigned int id;
    int runflag;
    int curblock;
    pthread_mutex_t sig_mtx;
    int sigflag;
    pthread_cond_t sig_cond;
    unsigned char cipher[MAXBYTEBUFF];
    unsigned char plain[MAXBYTEBUFF];
} thread_work_area;

thread_work_area twa[MAXTHREADS];
unsigned int g_threads = 8; // default number of threads
pthread_mutex_t g_tally_mtx;
pthread_cond_t g_tally_cond;
int g_tally = 0;
pthread_mutex_t g_debug_mtx; // protect debug messages in multithreaded environment

void load_key()
{
    if (g_keyfile_specified == 0) {
        fprintf(stderr, "rsa: this operation requires that you specify a key file.\n");
        exit(EXIT_FAILURE);
    }

    // load keyfile up and populate n, e, d, etc
    int key_fd;
    key_fd = open(g_keyfile, O_RDONLY);
    if (key_fd < 0) {
        fprintf(stderr, "rsa: unable to open key file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    int l_eof = 0;
    int res;
    do {
        key_item_header l_kih;
        res = read(key_fd, &l_kih, sizeof(l_kih));
        if (res == 0) {
            l_eof = 1;
            continue;
        }
        if (res != sizeof(l_kih)) {
            fprintf(stderr, "rsa: problems reading key file: unexpected end of file.\n");
            exit(EXIT_FAILURE);
        }

        if (l_kih.type == KIHT_MODULUS) {
            // if we read the modulus, set the over bit width
            g_bits = ntohl(l_kih.bit_width);
            if (g_bits < 768) {
                printf("rsa: a 768 bit or larger key is required to use this program.\n");
                exit(EXIT_FAILURE);
            }
            printf("rsa: selected %d bit key.\n", g_bits);
            res = read(key_fd, g_n, (g_bits / 8));
            if (res != (g_bits / 8)) {
                fprintf(stderr, "rsa: problems reading key file: can't read modulus.\n");
                exit(EXIT_FAILURE);
            }
            g_n_loaded = 1;
        } else if (l_kih.type == KIHT_PUBEXP) {
            res = read(key_fd, g_e, sizeof(uint32_t));
            if (res != sizeof(uint32_t)) {
                fprintf(stderr, "rsa: problems reading key file: can't read public exponent.\n");
                exit(EXIT_FAILURE);
            }
            g_e_loaded = 1;
        } else if (l_kih.type == KIHT_PRIVEXP) {
            res = read(key_fd, g_d, (ntohl(l_kih.bit_width) / 8));
            if (res != (ntohl(l_kih.bit_width) / 8)) {
                fprintf(stderr, "rsa: problems reading key file: can't read private exponent.\n");
                exit(EXIT_FAILURE);
            }
            g_d_loaded = 1;
        } else if (l_kih.type == KIHT_P) {
            res = read(key_fd, g_p, (ntohl(l_kih.bit_width) / 8));
            if (res != (ntohl(l_kih.bit_width) / 8)) {
                fprintf(stderr, "rsa: problems reading key file: can't read prime p.\n");
                exit(EXIT_FAILURE);
            }
            g_p_loaded = 1;
        } else if (l_kih.type == KIHT_Q) {
            res = read(key_fd, g_q, (ntohl(l_kih.bit_width) / 8));
            if (res != (ntohl(l_kih.bit_width) / 8)) {
                fprintf(stderr, "rsa: problems reading key file: can't read prime q.\n");
                exit(EXIT_FAILURE);
            }
            g_q_loaded = 1;
        } else if (l_kih.type == KIHT_DP) {
            res = read(key_fd, g_dp, (ntohl(l_kih.bit_width) / 8));
            if (res != (ntohl(l_kih.bit_width) / 8)) {
                fprintf(stderr, "rsa: problems reading key file: can't read prime q.\n");
                exit(EXIT_FAILURE);
            }
            g_dp_loaded = 1;
        } else if (l_kih.type == KIHT_DQ) {
            res = read(key_fd, g_dq, (ntohl(l_kih.bit_width) / 8));
            if (res != (ntohl(l_kih.bit_width) / 8)) {
                fprintf(stderr, "rsa: problems reading key file: can't read prime q.\n");
                exit(EXIT_FAILURE);
            }
            g_dq_loaded = 1;
        } else if (l_kih.type == KIHT_QINV) {
            res = read(key_fd, g_qinv, (ntohl(l_kih.bit_width) / 8));
            if (res != (ntohl(l_kih.bit_width) / 8)) {
                fprintf(stderr, "rsa: problems reading key file: can't read prime q.\n");
                exit(EXIT_FAILURE);
            }
            g_qinv_loaded = 1;
        } else {
            // that's all we care about for now, just throw away everything else
            res = read(key_fd, g_buff, (ntohl(l_kih.bit_width) / 8));
            if (res != (ntohl(l_kih.bit_width) / 8)) {
                fprintf(stderr, "rsa: problems reading key file: can't read unspecified field.\n");
                exit(EXIT_FAILURE);
            }
        }
    } while (l_eof == 0);
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
            fprintf(stderr, "rsa: output file already exists (use -w or --overwrite to write to it anyway)\n");
            exit(EXIT_FAILURE);
        } else {
            printf("rsa: overwriting existing output file %s\n", g_outfile);
        }
    } else if ((res < 0) && (errno == ENOENT)) {
        // this is what we want
    } else {
        // some other error from stat!
        fprintf(stderr, "rsa: unable to stat output file to check its existence: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // open the output file
    if (g_debug) printf("prepare_outfile: opening and truncating output file\n");
    g_outfile_fd = open(g_outfile, O_RDWR | O_TRUNC | O_CREAT, (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
    if (g_outfile_fd < 0) {
        fprintf(stderr, "rsa: error opening output file: %s\n", strerror(errno));
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
        fprintf(stderr, "rsa: error calling stat on input file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    g_infile_length = l_infile_stat.st_size;
    if (g_debug) printf("prepare_infile: input file length: %d\n", g_infile_length);
    g_block_size = (g_bits / 8);
    if (g_debug) printf("prepare_infile: block size: %d bytes\n", g_block_size);
    uint32_t l_sizemod = (g_infile_length % g_block_size);
    if (l_sizemod > 0) g_infile_block_multiple = 1;
    if (g_debug) printf("prepare_infile: input file block multiple: %s\n", (g_infile_block_multiple ? "NO" : "YES"));
    g_block_capacity = g_block_size - PADDING;
    if (g_debug) printf("prepare_infile: block capacity: %d bytes\n", g_block_capacity);
    g_1stblock_capacity = g_block_capacity - sizeof(fileinfo_header);
    if (g_debug) printf("prepare_infile: first block capacity: %d bytes\n", g_1stblock_capacity);

    // open infile
    g_infile_fd = open(g_infile, O_RDONLY);
    if (g_infile_fd < 0) {
        fprintf(stderr, "rsa: problems opening input file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

uint32_t g_crc32_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t get_file_crc(int a_fd)
{
    uint32_t l_crc = 0;
    l_crc = l_crc ^ ~0U;

    uint8_t l_buff[4096]; // buffer our reads so this doesn't take forever'
    int res;
    int i;

    do {
        res = read(a_fd, l_buff, 4096);
        if (res == 0)
            continue; // got our EOF
        if (res < 0) {
            fprintf(stderr, "rsa: unable to compute CRC: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        // compute CRC for res number of bytes
        for (i = 0; i < res; ++i) {
            l_crc = g_crc32_tab[(l_crc ^ l_buff[i]) & 0xFF] ^ (l_crc >> 8);
        }
    } while (res != 0);

    return l_crc ^ ~0U;
}

void get_infile_crc()
{
    int res;
    g_infile_crc = get_file_crc(g_infile_fd);
    // rewind g_infile_fd
    res = lseek(g_infile_fd, 0, SEEK_SET);
    if (res < 0) {
        fprintf(stderr, "res: unable to rewind input file after computing CRC: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (g_debug > 0) printf("get_infile_crc: CRC is %08X\n", g_infile_crc);
}

void get_outfile_crc()
{
    int res;
    // rewind g_outfile_fd after writing data
    res = lseek(g_outfile_fd, 0, SEEK_SET);
    if (res < 0) {
        fprintf(stderr, "res: unable to rewind input file after computing CRC: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    g_outfile_crc = get_file_crc(g_outfile_fd);
    if (g_debug > 0) printf("get_outfile_crc: CRC is %08X\n", g_outfile_crc);
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

void do_encrypt()
{
    int lastblock = 0; // flag to indicate we have run out of data, this is the last block
    int l_block_ctr = 0;
    int res;

    // prepare first block
    l_block_ctr++;
    get_random(g_buff, g_block_size);
    // PKCS#1 style padding of first two bytes
    g_buff[0] = 0;
    // prepare fileinfo header
    fileinfo_header l_fih;
    get_random(&l_fih.flags, 1); // fill flags byte with random data
    l_fih.flags &= 0x7f; // mask off high bit, not signing this content
    l_fih.size = htonl(g_infile_length);
    l_fih.size_xor = htonl(g_infile_length ^ ~0UL);
    l_fih.crc = htonl(g_infile_crc);
    l_fih.crc_xor = htonl(g_infile_crc ^ ~0UL);
    l_fih.time.ll = time(NULL);
    if (g_debug > 0) {
        printf("embedding GMT time stamp: %s", asctime(gmtime((time_t *)&l_fih.time.ll)));
    }
    ccct_reverse_int64(&l_fih.time);
    l_fih.latitude.f = g_latitude;
    ccct_reverse_float(&l_fih.latitude);
    l_fih.longitude.f = g_longitude;
    ccct_reverse_float(&l_fih.longitude);
    if (g_debug > 0) {
        printf("embedding geolocation: latitude %.4f, longitude %.4f\n", g_latitude, g_longitude);
    }
    printf("rsa: encrypting ...");

    memcpy(g_buff + 8, &l_fih, sizeof(fileinfo_header));

    // copy data into first block; zero it then read from infile
//    memset(g_buff + 8 + sizeof(fileinfo_header), 0, g_1stblock_capacity);
    res = read(g_infile_fd, g_buff + 8 + sizeof(fileinfo_header), g_1stblock_capacity);
    if (res == 0) {
        // zero length file, nothing to do!
        if (g_debug > 0) printf("do_encrypt: zero length input file, bailing out\n");
        return;
    }
    if (res < 0) {
        // actual error
        fprintf(stderr, "rsa: unable to read from input file (fd %d) during 1st block encrypt operation: %s\n",g_infile_fd, strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (res < g_1stblock_capacity) {
        // must be a really short file
        lastblock = 1;
    }
    if (g_debug > 0) {
        printf("do_encrypt: first block (fileinfo_header + %d used of initial data capacity of %d bytes)", res, g_1stblock_capacity);
        ccct_print_hex(g_buff, g_block_size);
    }

    mpz_t l_block;
    mpz_init(l_block);
    mpz_t l_cipher;
    mpz_init(l_cipher);
    mpz_t l_e;
    mpz_init(l_e);
    mpz_t l_n;
    mpz_init(l_n);
    size_t l_written;

    // load our key data
    mpz_import(l_e, 4, 1, sizeof(unsigned char), 0, 0, g_e);
    mpz_import(l_n, g_block_size, 1, sizeof(unsigned char), 0, 0, g_n);

    // load up our 1st block we just created
    mpz_import(l_block, g_block_size, 1, sizeof(unsigned char), 0, 0, g_buff);

    // and encrypt it
    mpz_powm(l_cipher, l_block, l_e, l_n);
    if (g_debug > 0) {
        gmp_printf("n      = %Zx\ne      = %Zx\nblock  = %Zx\ncipher = %Zx\n", l_n, l_e, l_block, l_cipher);
    }

    // and export it to aux block
    mpz_export(g_buff2, &l_written, 1, sizeof(unsigned char), 0, 0, l_cipher);
    if (l_written != g_block_size) {
        ccct_right_justify(l_written, g_block_size - l_written, (char *)g_buff2);
    }
    if (g_debug > 0) {
        printf("do_encrypt: first block (encrypted)");
        ccct_print_hex(g_buff2, g_block_size);
    }

    // write it to output file
    res = write(g_outfile_fd, g_buff2, g_block_size);
    if (res < 0) {
        fprintf(stderr, "rsa: unable to write to output file during encrypt operation: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (res < g_block_size) {
        // lol what? didn't write the whole block?
        fprintf(stderr, "rsa: unable to write entire block size of %d bytes to output file during encrypt operation\n", g_block_size);
    }

    // test our encryption (if d is loaded and debug flag is on)
    if ((g_d_loaded > 0) && (g_debug > 0)) {
        mpz_t l_d;
        mpz_init(l_d);
        mpz_import(l_d, g_block_size, 1, sizeof(unsigned char), 0, 0, g_d);
        mpz_t l_decrypted;
        mpz_init(l_decrypted);
        mpz_powm(l_decrypted, l_cipher, l_d, l_n);
        gmp_printf("decr.  = %Zx\n", l_decrypted);
        mpz_export(g_buff2, &l_written, 1, sizeof(unsigned char), 0, 0, l_decrypted);
        if (l_written != g_block_size) {
            ccct_right_justify(l_written, g_block_size - l_written, (char *)g_buff2);
        }
        printf("do_encrypt: first block (decrypted)");
        ccct_print_hex(g_buff2, g_block_size);
        mpz_clear(l_d);
        mpz_clear(l_decrypted);
    }

    // now do the same for all the rest of the data
    while (lastblock == 0) {
        // prepare block
        l_block_ctr++;
        get_random(g_buff, g_block_size);
        // padding
        g_buff[0] = 0;
        // copy data into block
//        memset(g_buff + 8, 0, g_block_capacity);
        res = read(g_infile_fd, g_buff + 8, g_block_capacity);
        if (res == 0) {
            // at the EOF, so don't make any new blocks
            if (g_debug > 0) printf("do_encrypt: got EOF on input file when populating new block, bailing out\n");
            lastblock = 1;
            continue;
        }
        if (res < 0) {
            // actual error
            fprintf(stderr, "rsa: unable to read from input file (fd %d) during subsequent block encrypt operation: %s\n", g_infile_fd, strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (res < g_block_capacity) {
            lastblock = 1;
        }
        if (g_debug > 0) {
            printf("\ndo_encrypt: block #%d - %d used of block data capacity of %d bytes)", l_block_ctr, res, g_block_capacity);
            ccct_print_hex(g_buff, g_block_size);
        }
        // load up our 1st block we just created
        mpz_import(l_block, g_block_size, 1, sizeof(unsigned char), 0, 0, g_buff);

        // and encrypt it
        mpz_powm(l_cipher, l_block, l_e, l_n);
        if (g_debug > 0) {
            gmp_printf("n      = %Zx\ne      = %Zx\nblock  = %Zx\ncipher = %Zx\n", l_n, l_e, l_block, l_cipher);
        }
        // and export it to aux block
        mpz_export(g_buff2, &l_written, 1, sizeof(unsigned char), 0, 0, l_cipher);
        if (l_written != g_block_size) {
            ccct_right_justify(l_written, g_block_size - l_written, (char *)g_buff2);
        }
        if (g_debug > 0) {
            printf("do_encrypt: block (encrypted)");
            ccct_print_hex(g_buff2, g_block_size);
        }
        // write it to output file
        res = write(g_outfile_fd, g_buff2, g_block_size);
        if (res < 0) {
            fprintf(stderr, "rsa: unable to write to output file during encrypt operation: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (res < g_block_size) {
            // lol what? didn't write the whole block?
            fprintf(stderr, "rsa: unable to write entire block size of %d bytes to output file during encrypt operation\n", g_block_size);
        }
        // test our encryption (if d is loaded and debug flag is on)
        if ((g_d_loaded > 0) && (g_debug > 0)) {
            mpz_t l_d;
            mpz_init(l_d);
            mpz_import(l_d, g_block_size, 1, sizeof(unsigned char), 0, 0, g_d);
            mpz_t l_decrypted;
            mpz_init(l_decrypted);
            mpz_powm(l_decrypted, l_cipher, l_d, l_n);
            gmp_printf("decr.  = %Zx\n", l_decrypted);
            mpz_export(g_buff2, &l_written, 1, sizeof(unsigned char), 0, 0, l_decrypted);
            if (l_written != g_block_size) {
                ccct_right_justify(l_written, g_block_size - l_written, (char *)g_buff2);
            }
            printf("do_encrypt: block (decrypted)");
            ccct_print_hex(g_buff2, g_block_size);
            mpz_clear(l_d);
            mpz_clear(l_decrypted);
        }
    }
    printf(" done.\n");

    mpz_clear(l_block);
    mpz_clear(l_cipher);
    mpz_clear(l_e);
    mpz_clear(l_n);
}

void *decrypt_tf(void *arg)
{
    thread_work_area *a_twa;
    a_twa = arg;

    mpz_t l_block;
    mpz_init(l_block);
    mpz_t l_cipher;
    mpz_init(l_cipher);
    mpz_t l_d;
    mpz_init(l_d);
    mpz_t l_n;
    mpz_init(l_n);
    mpz_t l_p;
    mpz_init(l_p);
    mpz_t l_q;
    mpz_init(l_q);
    mpz_t l_dp;
    mpz_init(l_dp);
    mpz_t l_dq;
    mpz_init(l_dq);
    mpz_t l_qinv;
    mpz_init(l_qinv);
    mpz_t l_m1;
    mpz_init(l_m1);
    mpz_t l_m2;
    mpz_init(l_m2);
    mpz_t l_h;
    mpz_init(l_h);
    size_t l_written;

    // load our key data
    mpz_import(l_d, g_block_size, 1, sizeof(unsigned char), 0, 0, g_d);
    mpz_import(l_n, g_block_size, 1, sizeof(unsigned char), 0, 0, g_n);
    mpz_import(l_p, (g_block_size / 2), 1, sizeof(unsigned char), 0, 0, g_p);
    mpz_import(l_q, (g_block_size / 2), 1, sizeof(unsigned char), 0, 0, g_q);
    mpz_import(l_dp, (g_block_size / 2), 1, sizeof(unsigned char), 0, 0, g_dp);
    mpz_import(l_dq, (g_block_size / 2), 1, sizeof(unsigned char), 0, 0, g_dq);
    mpz_import(l_qinv, (g_block_size / 2), 1, sizeof(unsigned char), 0, 0, g_qinv);

    while (1) {
        // wait to get signalled
        pthread_mutex_lock(&a_twa->sig_mtx);
        while ((a_twa->sigflag == 0) && (a_twa->runflag > 0))
            pthread_cond_wait(&a_twa->sig_cond, &a_twa->sig_mtx);
        if (a_twa->runflag == 0) {
            // telling us to quit
            pthread_mutex_unlock(&a_twa->sig_mtx);

            // clean up GMP variables
            mpz_clear(l_block);
            mpz_clear(l_cipher);
            mpz_clear(l_d);
            mpz_clear(l_n);
            mpz_clear(l_m1);
            mpz_clear(l_m2);
            mpz_clear(l_h);
            mpz_clear(l_p);
            mpz_clear(l_q);
            mpz_clear(l_dp);
            mpz_clear(l_dq);
            mpz_clear(l_qinv);

            pthread_exit(NULL);
        }
        pthread_mutex_unlock(&a_twa->sig_mtx);
//        printf("tid %d: signalled\n", a_twa->id);

        // load up our cipher block
        mpz_import(l_cipher, g_block_size, 1, sizeof(unsigned char), 0, 0, a_twa->cipher);

        // and decrypt it
        if (g_nochinese > 0) {
            mpz_powm(l_block, l_cipher, l_d, l_n);
        } else {
            mpz_powm(l_m1, l_cipher, l_dp, l_p);
            mpz_powm(l_m2, l_cipher, l_dq, l_q);
            mpz_sub(l_m1, l_m1, l_m2);
            mpz_mul(l_h, l_qinv, l_m1);
            mpz_mod(l_h, l_h, l_p);
            mpz_mul(l_h, l_h, l_q);
            mpz_add(l_block, l_m2, l_h);
        }

        if (g_debug > 0) {
            pthread_mutex_lock(&g_debug_mtx);
            gmp_printf("tid %d: n      = %Zx\nd      = %Zx\ncipher = %Zx\nblock  = %Zx\n", a_twa->id, l_n, l_d, l_cipher, l_block);
            pthread_mutex_unlock(&g_debug_mtx);
        }

        // and export it to aux block
        mpz_export(a_twa->plain, &l_written, 1, sizeof(unsigned char), 0, 0, l_block);
        if (l_written != g_block_size) {
            ccct_right_justify(l_written, g_block_size - l_written, (char *)a_twa->plain);
        }
        if (g_debug > 0) {
            pthread_mutex_lock(&g_debug_mtx);
            printf("tid %d: decrypted block %d", a_twa->id, a_twa->curblock);
            ccct_print_hex(a_twa->plain, g_block_size);
            pthread_mutex_unlock(&g_debug_mtx);
        }
        a_twa->sigflag = 0;

        // signal doneness
        pthread_mutex_lock(&g_tally_mtx);
        g_tally++;
        pthread_cond_signal(&g_tally_cond);
        pthread_mutex_unlock(&g_tally_mtx);
    }
}

void do_decrypt()
{
    int i, j;
    int l_block_ctr = 0;
    int res;
    int l_eof = 0;
    int l_docontinue = 0;
    fileinfo_header l_fih;
    uint32_t l_bytes_written_tab = 0;

    do {
        g_tally = 0;
        // now read a bunch of blocks
        for (i = 0; i < g_threads; ++i) {
            l_block_ctr++;
            res = read(g_infile_fd, twa[i].cipher, g_block_size);
            if (res == 0) {
                if (g_debug > 0) printf("do_decrypt: EOF on input file, bailing out\n");
                l_eof = 1;
                if (i == 0)
                    l_docontinue = 1;
                break;
                // at this point, i contains the number of blocks successfully read
            } else if (res < 0) {
                fprintf(stderr, "rsa: unable to read from input file during decrypt operation: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            } else if (res < g_block_size) {
                // file is already supposed to be a multiple of our block size, so this should never happen
                fprintf(stderr, "rsa: unable to read full block from input file during decrypt operation: expected %d got %d\n", g_block_size, res);
                exit(EXIT_FAILURE);
            }
            if (g_debug > 0) {
                printf("\ndo_decrypt: block %d from input file", l_block_ctr);
                ccct_print_hex(twa[i].cipher, g_block_size);
            }
            // populate a thread and signal it
            pthread_mutex_lock(&twa[i].sig_mtx);
            twa[i].curblock = l_block_ctr;
            twa[i].sigflag = 1;
            pthread_cond_signal(&twa[i].sig_cond);
            pthread_mutex_unlock(&twa[i].sig_mtx);
        }
        if (l_docontinue > 0)
            continue; // go down to bottom of do loop

        // wait for threads to finish
        pthread_mutex_lock(&g_tally_mtx);
        while (g_tally < i)
            pthread_cond_wait(&g_tally_cond, &g_tally_mtx);
        pthread_mutex_unlock(&g_tally_mtx);

        // all our threads are done and the plains are all contained in the twa data structures
        int l_block_index;
        for (j = 0; j < i; j++) {
            memcpy(g_buff2, twa[j].plain, g_block_size);
            l_block_index = twa[j].curblock;
            // take care of business with the first block
            if (l_block_index == 1) {
                memcpy(&l_fih, g_buff2 + 8, sizeof(fileinfo_header));
                // get everything in host byte order
                l_fih.size = ntohl(l_fih.size);
                l_fih.size_xor = ntohl(l_fih.size_xor);
                l_fih.crc = ntohl(l_fih.crc);
                l_fih.crc_xor = ntohl(l_fih.crc_xor);
                ccct_reverse_int64(&l_fih.time);
                ccct_reverse_float(&l_fih.latitude);
                ccct_reverse_float(&l_fih.longitude);
                // check to see if we decrypted this block properly
                if (l_fih.size != (l_fih.size_xor ^ ~0U)) {
                    goto do_decrypt_keyerror;
                }
                if (l_fih.crc != (l_fih.crc_xor ^ ~0U)) {
                    goto do_decrypt_keyerror;
                }
                // assumed good fileinfo_header now
                printf("rsa: data length in input file is %d bytes.\n", l_fih.size);
                if (g_debug > 0) printf("do_decrypt: input file data CRC is %08X\n", l_fih.crc);
                printf("rsa: GMT time stamp: %s", asctime(gmtime((time_t *)&l_fih.time.ll)));
                printf("rsa: geolocation: latitude %.4f, longitude %.4f\n", l_fih.latitude.f, l_fih.longitude.f);

                // write any data contained in first block to output file
                uint32_t l_bytes_expected = g_1stblock_capacity;
                if (l_fih.size < g_1stblock_capacity)
                    l_bytes_expected = l_fih.size;
                if (g_debug > 0) printf("do_decrypt: expecting to write %d bytes in write operation\n", l_bytes_expected);
                res = write(g_outfile_fd, g_buff2 + 8 + sizeof(fileinfo_header), l_bytes_expected);
                if (res < 0) {
                    fprintf(stderr, "rsa: unable to write to output file during decrypt operation: %s\n", strerror(errno));
                    exit(EXIT_FAILURE);
                }
                if (res < l_bytes_expected) {
                    fprintf(stderr, "rsa: problems writing to output file, wrote %d bytes, expected %d\n", res, l_bytes_expected);
                    exit(EXIT_FAILURE);
                }
                l_bytes_written_tab += res;
            } else {
                // subsequent block, so just write it out
                if (l_block_index == 2) {
                    printf("rsa: decrypting ");
                    ccct_progress(l_bytes_written_tab, l_fih.size);
                }
//            } else {
//                // print ccct_progress dot every eight blocks
//                if (l_block_ctr % 8 == 0) printf(".");
//            }
                uint32_t l_bytes_expected = g_block_capacity;
                if (l_fih.size - l_bytes_written_tab < g_block_capacity)
                    l_bytes_expected = l_fih.size - l_bytes_written_tab;
                if (g_debug > 0) printf("do_decrypt: expecting to write %d bytes in write operation\n", l_bytes_expected);
                res = write(g_outfile_fd, g_buff2 + 8, l_bytes_expected);
                if (res < 0) {
                    fprintf(stderr, "rsa: unable to write to output file during decrypt operation: %s\n", strerror(errno));
                    exit(EXIT_FAILURE);
                }
                if (res < l_bytes_expected) {
                    fprintf(stderr, "rsa: problems writing to output file, wrote %d bytes, expected %d\n", res, l_bytes_expected);
                    exit(EXIT_FAILURE);
                }
                l_bytes_written_tab += res;
                if (l_block_ctr % 8 == 0) ccct_progress(l_bytes_written_tab, l_fih.size);
            }
        }
        // done writing output?
        if (l_fih.size == l_bytes_written_tab) {
            l_eof = 1;
            // don't leave our ccct_progress meter hanging
            if (l_block_ctr > 1) {
                ccct_progress(l_bytes_written_tab, l_fih.size);
                printf("\n");
            }
            if (g_debug > 0) printf("do_decrypt: finished writing input data\n");
        }
    } while (l_eof == 0);
    get_outfile_crc();
    if (g_outfile_crc == l_fih.crc) {
        printf("rsa: CRC OK\n");
    } else {
        printf("rsa: CRC failure, expected %08X, got %08X.\n", l_fih.crc, g_outfile_crc);
    }
    return;

do_decrypt_keyerror:
    fprintf(stderr, "rsa: error decrypting first block, wrong key file or damaged key.\n");
    exit(EXIT_FAILURE);
}

void do_sign_verify(int a_mode)
{
    // mode=0, sign... mode=1, verify.
    // irrespective of mode, we need to compute a sha2-512 hash on the input file
    int i;
    int res;
    uint8_t l_digest[64];
    uint8_t l_buff[4096]; // buffer our reads

    // compute sha2-512 hash
    sha512_ctx l_ctx;
    sha512_init(&l_ctx);
    do {
        res = read(g_infile_fd, l_buff, 4096);
        if (res == 0)
            continue; // got our EOF
            if (res < 0) {
                fprintf(stderr, "rsa: unable to compute sha2-512 hash of input file: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            sha512_update(&l_ctx, (const uint8_t *)l_buff, res);
    } while (res != 0);
    sha512_final(&l_ctx, l_digest);
    // rewind g_infile_fd
    res = lseek(g_infile_fd, 0, SEEK_SET);
    if (res < 0) {
        fprintf(stderr, "res: unable to rewind input file after computing sha2-512 hash: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (g_debug > 0) {
        printf("do_sign_verify: sha2-512 hash of input file");
        ccct_print_hex(l_digest, 64);
    }

    // get time and location info
    ccct_reversible_int64_t l_time;
    l_time.ll = time(NULL);
    ccct_reversible_float_t l_lat;
    l_lat.f = g_latitude;
    ccct_reversible_float_t l_long;
    l_long.f = g_longitude;

    if (a_mode == 0) {
        // create signature file
        // find out if signature file already exists
        struct stat l_signaturefile_stat;
        res = stat(g_signaturefile, &l_signaturefile_stat);
        if (res == 0) {
            if (g_outfile_overwrite == 0) {
                fprintf(stderr, "rsa: signature file already exists (use -w or --overwrite to write to it anyway)\n");
                exit(EXIT_FAILURE);
            } else {
                printf("rsa: overwriting existing signature file %s\n", g_outfile);
            }
        } else if ((res < 0) && (errno == ENOENT)) {
            // this is what we want
        } else {
            // some other error from stat!
            fprintf(stderr, "rsa: unable to stat signature file to check its existence: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        // open the output file
        if (g_debug) printf("do_sign_verify: opening and truncating signature file\n");
        g_signaturefile_fd = open(g_signaturefile, O_RDWR | O_TRUNC | O_CREAT, (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
        if (g_signaturefile_fd < 0) {
            fprintf(stderr, "rsa: error opening signature file for writing: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        // create a block in g_buff
        get_random(g_buff, g_block_size);
        g_buff[0] = 0;
        // copy our digest into this block, after the random padding
        memcpy(g_buff + 8, l_digest, 64);
        printf("rsa: embedding GMT time stamp: %s", asctime(gmtime((time_t *)&l_time.ll)));
        printf("rsa: embedding geolocation: latitude %.4f, longitude %.4f\n", l_lat.f, l_long.f);
        ccct_reverse_int64(&l_time);
        ccct_reverse_float(&l_lat);
        ccct_reverse_float(&l_long);
        memcpy(g_buff + 72, &l_time.ll, 8);
        memcpy(g_buff + 80, &l_lat.f, 4);
        memcpy(g_buff + 84, &l_long.f, 4);
        if (g_debug > 0) {
            printf("do_sign_verify: plaintext block with hash");
            ccct_print_hex(g_buff, g_block_size);
        }

        mpz_t l_block;
        mpz_init(l_block);
        mpz_t l_cipher;
        mpz_init(l_cipher);
        mpz_t l_d;
        mpz_init(l_d);
        mpz_t l_n;
        mpz_init(l_n);
        size_t l_written;

        // load our key data
        mpz_import(l_d, g_block_size, 1, sizeof(unsigned char), 0, 0, g_d);
        mpz_import(l_n, g_block_size, 1, sizeof(unsigned char), 0, 0, g_n);

        // load up our cipher block
        mpz_import(l_block, g_block_size, 1, sizeof(unsigned char), 0, 0, g_buff);

        // and encrypt it with the private exponent
        mpz_powm(l_cipher, l_block, l_d, l_n);
        if (g_debug > 0) {
            gmp_printf("n      = %Zx\nd      = %Zx\ncipher = %Zx\nblock  = %Zx\n", l_n, l_d, l_cipher, l_block);
        }

        // and export it to aux block
        mpz_export(g_buff2, &l_written, 1, sizeof(unsigned char), 0, 0, l_cipher);
        if (l_written != g_block_size) {
            ccct_right_justify(l_written, g_block_size - l_written, (char *)g_buff2);
        }
        if (g_debug > 0) {
            printf("do_sign_verify: encrypted hash");
            ccct_print_hex(g_buff2, g_block_size);
        }
        printf("rsa: writing signature file...\n");
        res = write(g_signaturefile_fd, g_buff2, g_block_size);
        if (res < 0) {
            fprintf(stderr, "rsa: problems writing to signature file: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        close(g_signaturefile_fd);

        mpz_clear(l_block);
        mpz_clear(l_cipher);
        mpz_clear(l_d);
        mpz_clear(l_n);

    } else {
        // read in and decrypt signature file
        g_signaturefile_fd = open(g_signaturefile, O_RDONLY);
        if (g_signaturefile_fd < 0) {
            fprintf(stderr, "rsa: problems opening signature file: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        res = read(g_signaturefile_fd, g_buff, g_block_size);
        if (res < 0) {
            fprintf(stderr, "rsa: problems reading signature file: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (res != g_block_size) {
            fprintf(stderr, "rsa: block size mismatch in signature, wrong key file or damaged key.\n");
            exit(EXIT_FAILURE);
        }
        close(g_signaturefile_fd);

        mpz_t l_block;
        mpz_init(l_block);
        mpz_t l_cipher;
        mpz_init(l_cipher);
        mpz_t l_e;
        mpz_init(l_e);
        mpz_t l_n;
        mpz_init(l_n);
        size_t l_written;

        // load our key data
        mpz_import(l_e, 4, 1, sizeof(unsigned char), 0, 0, g_e);
        mpz_import(l_n, g_block_size, 1, sizeof(unsigned char), 0, 0, g_n);

        // load up our cipher block
        mpz_import(l_cipher, g_block_size, 1, sizeof(unsigned char), 0, 0, g_buff);

        // and decrypt it with the public exponent
        mpz_powm(l_block, l_cipher, l_e, l_n);
        if (g_debug > 0) {
            gmp_printf("n      = %Zx\ne      = %Zx\ncipher = %Zx\nblock  = %Zx\n", l_n, l_e, l_cipher, l_block);
        }

        // and export it to aux block
        mpz_export(g_buff2, &l_written, 1, sizeof(unsigned char), 0, 0, l_block);
        if (l_written != g_block_size) {
            ccct_right_justify(l_written, g_block_size - l_written, (char *)g_buff2);
        }

        uint8_t l_digest_dec[64];
        memcpy(l_digest_dec, g_buff2 + 8, 64);
        if (g_debug > 0) {
            printf("do_sign_verify: decrypted hash from signature file");
            ccct_print_hex(l_digest_dec, 64);
            printf("do_sign_verify: computed hash of input file");
            ccct_print_hex(l_digest, 64);
        }
        if (memcmp(l_digest_dec, l_digest, 64) == 0) {
            printf("rsa: verify OK\n");
            memcpy(&l_time.ll, g_buff2 + 72, 8);
            ccct_reverse_int64(&l_time);
            printf("rsa: GMT timestamp of signature: %s", asctime(gmtime((time_t *)&l_time.ll)));
            memcpy(&l_lat.f, g_buff2 + 80, 4);
            memcpy(&l_long.f, g_buff2 + 84, 4);
            ccct_reverse_float(&l_lat);
            ccct_reverse_float(&l_long);
            printf("rsa: geolocation: latitude %.4f, longitude %.4f\n", l_lat.f, l_long.f);
        } else {
            printf("rsa: verify FAILED\n");
        }

        mpz_clear(l_block);
        mpz_clear(l_cipher);
        mpz_clear(l_e);
        mpz_clear(l_n);
    }
}

int main(int argc, char **argv)
{
    unsigned int i;
    int res; // result variable for UNIX reads
    int opt;

    // try to determine hardware concurrency
    unsigned int l_tcnt = sysconf(_SC_NPROCESSORS_ONLN);
    if (l_tcnt != 0) {
        g_threads = l_tcnt;
    }

    while ((opt = getopt_long(argc, argv, "i:o:k:g:edsv?tw", g_options, NULL)) != -1) {
        switch (opt) {
            case 1001:
            {
                g_debug = 1;
                ccct_set_debug(1);
            }
            break;
            case 1002: // latitude
            {
                g_latitude = atof(optarg);
            }
            break;
            case 1003: // longitude
            {
                g_longitude = atof(optarg);
            }
            break;
            case 1004: // force thread count
            {
                g_threads = atoi(optarg);
            }
            break;
            case 1005: // nochinese
            {
                g_nochinese = 1;
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
            case 'g':
            {
                strcpy(g_signaturefile, optarg);
                g_signaturefile_specified = 1;
            }
            break;
            case 'w':
            {
                g_outfile_overwrite = 1;
            }
            break;
            case 'e':
            {
                if (g_mode != MODE_NONE) {
                    fprintf(stderr, "rsa: please select only one operational mode.\n");
                    exit(EXIT_FAILURE);
                }
                g_mode = MODE_ENCRYPT;
            }
            break;
            case 'd':
            {
                if (g_mode != MODE_NONE) {
                    fprintf(stderr, "rsa: please select only one operational mode.\n");
                    exit(EXIT_FAILURE);
                }
                g_mode = MODE_DECRYPT;
            }
            break;
            case 's':
            {
                if (g_mode != MODE_NONE) {
                    fprintf(stderr, "rsa: please select only one operational mode.\n");
                    exit(EXIT_FAILURE);
                }
                g_mode = MODE_SIGN;
            }
            break;
            case 'v':
            {
                if (g_mode != MODE_NONE) {
                    fprintf(stderr, "rsa: please select only one operational mode.\n");
                    exit(EXIT_FAILURE);
                }
                g_mode = MODE_VERIFY;
            }
            break;
            case 't':
            {
                if (g_mode != MODE_NONE) {
                    fprintf(stderr, "rsa: please select only one operational mode.\n");
                    exit(EXIT_FAILURE);
                }
                g_mode = MODE_TELL;
            }
            break;
            case '?':
            {
                printf("RSA file encryptor/digital signature utility\n");
                printf("by Stephen Sviatko - (C) 2025 Good Neighbors LLC\n");
                printf("revision 0.80 alpha - 2025/Nov/15\n");
                printf("usage: rsa-util <options>\n");
                printf("  -i (--in) <name> specify input file\n");
                printf("  -o (--out) <name> specify output file\n");
                printf("  -w (--overwrite) force overwrite of existing output file or signature file\n");
                printf("  -k (--key) <name> specify full name of key file to use\n");
                printf("  -g (--signature) <name> specify signature file\n");
                printf("     (--latitude) <value> specify your latitude\n");
                printf("     (--longitude) <value> specify your longitude\n");
                printf("       latitude and longitude are specified as floating point numbers\n");
                printf("       will be rounded to 4 decimal places (accuracy of 11.1 meters/36.4 feet)\n");
                printf("     (--threads) <count> specify number of threads to use during decryption process\n");
                printf("     (--nochinese) defeat chinese remainder theorem calculations during decryption\n");
                printf("     (--debug) use debug mode\n");
                printf("  -? (--help) this screen\n");
                printf("operational modes (select only one)\n");
                printf("  -e (--encrypt) encrypt mode\n");
                printf("       encrypts in->out with public key\n");
                printf("       example: rsa -e -i plainfile -o encfile -k key-public.bin\n");
                printf("  -d (--decrypt) decrypt mode\n");
                printf("       decrypts in->out with private key\n");
                printf("       example: rsa -d -i encfile -o decfile -k key-private.bin\n");
                printf("  -s (--sign) sign mode (SHA2-512)\n");
                printf("       computes sha2-512 hash of in, encrypts the hash and writes to signature file\n");
                printf("       example: rsa -s -i filetosign -g sigfile -k key-private.bin\n");
                printf("  -v (--verify) verify mode\n");
                printf("       computes sha2-512 hash of in, compares with hash in decrypted signature file\n");
                printf("       example: rsa -v -i signedfile -g sigfile -k key-public.bin\n");
                printf("  -t (--tell) tell about key\n");
                printf("       show details about key specified by -k or --key\n");
                printf("       example: rsa -t -k keyfile.bin\n");
                exit(EXIT_SUCCESS);
            }
            break;
        }
    }

    setbuf(stdout, NULL); // disable buffering so we can print our ccct_progress
    ccct_get_term_size();
    ccct_discover_endianness();

    if (g_debug > 0)
        printf("rsa: debug mode enabled.\n");

    if (g_infile_specified > 0) {
        printf("rsa: input file : %s\n", g_infile);
    }
    if (g_outfile_specified > 0) {
        printf("rsa: output file: %s\n", g_outfile);
    }
    if (g_keyfile_specified > 0) {
        printf("rsa: key file   : %s\n", g_keyfile);
    }
    if (g_signaturefile_specified > 0) {
        printf("rsa: signature  : %s\n", g_signaturefile);
    }

    // prepare urandom
    g_urandom_fd = open("/dev/urandom", O_RDONLY);
    if (g_urandom_fd < 0) {
        fprintf(stderr, "rsa: problems opening /dev/urandom: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // police thread count
    if (g_threads < 1) {
        fprintf(stderr, "rsa: need to use at least 1 thread.\n");
        exit(EXIT_FAILURE);
    }
    if (g_threads > MAXTHREADS) {
        fprintf(stderr, "rsa: thread limit: %d.\n", MAXTHREADS);;
        exit(EXIT_FAILURE);
    }

    gettimeofday(&g_start_time, NULL);

    switch (g_mode) {
        case MODE_NONE:
        {
            fprintf(stderr, "rsa: you must select one operational mode.\n");
	    fprintf(stderr, "rsa: use -? or --help for usage info.\n");
            exit(EXIT_FAILURE);
        }
        break;
        case MODE_ENCRYPT:
        {
            printf("rsa: selected encryption mode.\n");
            load_key();
            if (g_n_loaded == 0) {
                fprintf(stderr, "rsa: this function requires the key file to contain a modulus.\n");
                exit(EXIT_FAILURE);
            }
            if (g_e_loaded == 0) {
                fprintf(stderr, "rsa: this function requires the key file to contain a public exponent.\n");
                exit(EXIT_FAILURE);
            }
            if (g_infile_specified == 0) {
                fprintf(stderr, "rsa: this function requires that you specify an input file.\n");
                exit(EXIT_FAILURE);
            }
            prepare_infile();
            get_infile_crc();
            if (g_outfile_specified == 0) {
                fprintf(stderr, "rsa: this function requires that you specify an output file.\n");
                exit(EXIT_FAILURE);
            }
            prepare_outfile();
            do_encrypt();
        }
        break;
        case MODE_DECRYPT:
        {
            printf("rsa: selected decryption mode.\n");
            if (g_threads > 1)
                printf("rsa: enabling %d threads.\n", g_threads);
            if (g_nochinese > 0)
                printf("rsa: defeating chinese remainder theory calculations.\n");
            load_key();
            if (g_n_loaded == 0) {
                fprintf(stderr, "rsa: this function requires the key file to contain a modulus.\n");
                exit(EXIT_FAILURE);
            }
            if (g_d_loaded == 0) {
                fprintf(stderr, "rsa: this function requires the key file to contain a private exponent.\n");
                exit(EXIT_FAILURE);
            }
            if (g_infile_specified == 0) {
                fprintf(stderr, "rsa: this function requires that you specify an input file.\n");
                exit(EXIT_FAILURE);
            }
            prepare_infile();
            if (g_infile_block_multiple > 0) {
                fprintf(stderr, "rsa: input file must be a multiple of block size to decrypt.\n");
                exit(EXIT_FAILURE);
            }
            if (g_outfile_specified == 0) {
                fprintf(stderr, "rsa: this function requires that you specify an output file.\n");
                exit(EXIT_FAILURE);
            }
            prepare_outfile();
            // initialize threaded environment
            pthread_mutex_init(&g_debug_mtx, NULL);
            pthread_mutex_init(&g_tally_mtx, NULL);
            pthread_cond_init(&g_tally_cond, NULL);
            for (i = 0; i < g_threads; ++i) {
                pthread_mutex_init(&twa[i].sig_mtx, NULL);
                pthread_cond_init(&twa[i].sig_cond, NULL);
                twa[i].id = i;
                twa[i].runflag = 1;
                pthread_create(&twa[i].thread, NULL, decrypt_tf, &twa[i]);
            }
            do_decrypt();
            // join
            for (i = 0; i < g_threads; ++i) {
                pthread_mutex_lock(&twa[i].sig_mtx);
                twa[i].runflag = 0;
                pthread_cond_signal(&twa[i].sig_cond);
                pthread_mutex_unlock(&twa[i].sig_mtx);
//                printf("joining %d...\n", i);
                pthread_join(twa[i].thread, NULL);
            }
            // clean up
            for (i = 0; i < g_threads; ++i) {
                pthread_mutex_destroy(&twa[i].sig_mtx);
                pthread_cond_destroy(&twa[i].sig_cond);
            }
            pthread_cond_destroy(&g_tally_cond);
            pthread_mutex_destroy(&g_tally_mtx);
            pthread_mutex_destroy(&g_debug_mtx);
        }
        break;
        case MODE_SIGN:
        {
            printf("rsa: selected sign mode.\n");
            load_key();
            if (g_n_loaded == 0) {
                fprintf(stderr, "rsa: this function requires the key file to contain a modulus.\n");
                exit(EXIT_FAILURE);
            }
            if (g_d_loaded == 0) {
                fprintf(stderr, "rsa: this function requires the key file to contain a private exponent.\n");
                exit(EXIT_FAILURE);
            }
            if (g_infile_specified == 0) {
                fprintf(stderr, "rsa: this function requires that you specify an input file.\n");
                exit(EXIT_FAILURE);
            }
            prepare_infile();
            if (g_signaturefile_specified == 0) {
                fprintf(stderr, "rsa: this function requires that you specify a signature file.\n");
                exit(EXIT_FAILURE);
            }
            do_sign_verify(0);
        }
        break;
        case MODE_VERIFY:
        {
            printf("rsa: selected verify mode.\n");
            load_key();
            if (g_n_loaded == 0) {
                fprintf(stderr, "rsa: this function requires the key file to contain a modulus.\n");
                exit(EXIT_FAILURE);
            }
            if (g_e_loaded == 0) {
                fprintf(stderr, "rsa: this function requires the key file to contain a public exponent.\n");
                exit(EXIT_FAILURE);
            }
            if (g_infile_specified == 0) {
                fprintf(stderr, "rsa: this function requires that you specify an input file.\n");
                exit(EXIT_FAILURE);
            }
            prepare_infile();
            if (g_signaturefile_specified == 0) {
                fprintf(stderr, "rsa: this function requires that you specify a signature file.\n");
                exit(EXIT_FAILURE);
            }
            do_sign_verify(1);
        }
        break;
        case MODE_TELL:
        {
            printf("rsa: selected tell mode.\n");
            load_key();
            if (g_n_loaded > 0) {
                printf("modulus n (%d bits):", g_bits);
                ccct_print_hex(g_n, (g_bits / 8));
            }
            if (g_e_loaded > 0) {
                printf("public exponent e:");
                ccct_print_hex(g_e, 4);
            }
            if (g_d_loaded > 0) {
                printf("private exponent d:");
                ccct_print_hex(g_d, (g_bits / 8));
            }
            if (g_p_loaded > 0) {
                printf("prime p:");
                ccct_print_hex(g_p, (g_bits / 8) / 2);
            }
            if (g_q_loaded > 0) {
                printf("prime q:");
                ccct_print_hex(g_q, (g_bits / 8) / 2);
            }
            if (g_dp_loaded > 0) {
                printf("exponent dp:");
                ccct_print_hex(g_dp, (g_bits / 8) / 2);
            }
            if (g_dq_loaded > 0) {
                printf("exponent dq:");
                ccct_print_hex(g_dq, (g_bits / 8) / 2);
            }
            if (g_qinv_loaded > 0) {
                printf("coefficient qinv:");
                ccct_print_hex(g_qinv, (g_bits / 8) / 2);
            }
        }
        break;
        default:
        {
            printf("I don't know what to do!\n");
        }
        break;
    }

    gettimeofday(&g_end_time, NULL);
    printf("rsa: completed operation in %ld seconds %ld usecs.\n",
           g_end_time.tv_sec - g_start_time.tv_sec - ((g_end_time.tv_usec - g_start_time.tv_usec < 0) ? 1 : 0), // subtract 1 if there was a usec rollover
           g_end_time.tv_usec - g_start_time.tv_usec + ((g_end_time.tv_usec - g_start_time.tv_usec < 0) ? 1000000 : 0)); // bump usecs by 1 million usec for rollover

    close(g_infile_fd);
    close(g_outfile_fd);

    return 0;
}
