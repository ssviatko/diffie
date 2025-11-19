/**
 *
 * C Common Cryptographic Tools
 * 2025/Nov/16
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
 * @file ccct.c
 * @brief C Crytographic Common Tools
 *
 * Common routines to support cryptographic software included in the
 * sscrypto library.
 *
 */

#include "ccct.h"

static unsigned int g_row = 24; ///< Terminal rows: provide a default in case user neglects to call ccct_get_term_size
static unsigned int g_col = 80; ///< Terminal columns: provide a default in case user neglects to call ccct_get_term_size
static int g_endianness = 0; ///< Endianness marker: 0=big, 1=little
static const unsigned int g_bufflen = 1024; ///< Constant to define length of common string buffers in CCCT library
static int g_debug = 0; ///< Debug flag: 0=off, 1=on
static int g_urandom_fd; ///< UNIX file descriptor of /dev/urandom
static pthread_mutex_t g_urandom_mtx; ///< mutex to protect urandom in multithreaded environments

/**
 * @brief Sets debug flag
 *
 * @param[in] a_debug The value to set
 */

void ccct_set_debug(int a_debug)
{
    g_debug = a_debug;
}

/**
 * @brief Query terminal size
 * This routine calls an ioctl to find out the rows/columns of the terminal
 */

void ccct_get_term_size()
{
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    g_row = w.ws_row;
    g_col = w.ws_col;
}

/**
 * @brief Print a hexadecimal string
 * Prints a hex string automatically formatted to the size of the terminal in 16 byte increments
 * Hex bytes are separated by a space in old-fashioned Apple ][ monitor style
 *
 * @param[in] a_buffer Pointer to buffer to print
 * @param[in] a_len Number of bytes to print
 */

void ccct_print_hex(uint8_t *a_buffer, size_t a_len)
{
    unsigned int i;
    unsigned int l_bytes_to_print = (g_col / 48) * 16;
    for (i = 0; i < a_len; ++i) {
        if (i % l_bytes_to_print == 0)
            printf("\n");
        printf("%02X ", a_buffer[i]);
    }
    printf("\n");
}

/**
 * @brief "Right justifies" a string of bytes within a set size byte buffer
 * Shifts over the data to the right and pads the data with zeros, in the
 * space on the left that was vacated by the move.
 *
 * @param[in] a_size The size of the byte buffer in bytes
 * @param[in] a_offset Number of bytes to shift the data over, i.e. the size of the buffer - the length of the data
 * @param[in] a_buff Pointer to the buffer to operate on
 */

void ccct_right_justify(size_t a_size, size_t a_offset, char *a_buff)
{
    // move a_size number of bytes over by a_offset in buffer a_buff
    int i;
    for (i = a_size - 1; i >= 0; --i) {
        a_buff[i + a_offset] = a_buff[i];
    }
    // zero out space we vacated in front
    for (i = 0; i < a_offset; ++i) {
        a_buff[i] = 0;
    }
}

/**
 * @brief Update a progress string
 * Prints (# of #) string, i.e. number of bytes so far of total. Backspaces over string on every update.
 *
 * @param[in] a_sofar The value achieved so far
 * @param[in] a_total The total/target value
 */

void ccct_progress(uint32_t a_sofar, uint32_t a_total)
{
    static size_t l_lastsize = 0;
    int i;
    char l_txt[g_bufflen];

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

/**
 * @brief Discover and set the endianness of the host machine
 */

void ccct_discover_endianness()
{
    // preform endianness test, for 64-bit and floating point values since there is no portable way to do this
    ccct_reversible_int64_t l_rev;
    l_rev.ll = 0x1234567812345678LL;
    if (l_rev.data[0] == 0x78) {
        g_endianness = 1;
        if (g_debug) printf("endianness: little\n");
    } else if (l_rev.data[0] == 0x12) {
        g_endianness = 0;
        if (g_debug) printf("endianness: big\n");
    } else {
        fprintf(stderr, "unable to determine endianness of host machine.\n");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Return the endianness factor for the host machine, after call to ccct_discover_endianness
 *
 * @return The endianness factor
 */

int ccct_endianness()
{
    return g_endianness;
}

/**
 * @brief Reverse a 64 bit integer, if we are in a little-endian machine
 * Requires call to ccct_discover_endianness before use
 */

void ccct_reverse_int64(ccct_reversible_int64_t *a_val)
{
    int i;
    char ch;

    if (g_endianness > 0) {
        for (i = 0; i <= 3; ++i) {
            ch = a_val->data[i];
            a_val->data[i] = a_val->data[7 - i];
            a_val->data[7 - i] = ch;
        }
    }
}

/**
 * @brief Reverse a float, if we are in a little-endian machine
 * Requires call to ccct_discover_endianness before use
 */

void ccct_reverse_float(ccct_reversible_float_t *a_val)
{
    int i;
    char ch;

    if (g_endianness > 0) {
        ch = a_val->data[0];
        a_val->data[0] = a_val->data[3];
        a_val->data[3] = ch;
        ch = a_val->data[1];
        a_val->data[1] = a_val->data[2];
        a_val->data[2] = ch;
    }
}

/**
 * @brief Encode a base64 string
 *
 * @param[in] a_data The binary data to be encoded
 * @param[in] a_len The length of the binary data to be encoded
 * @param[out] a_textout A buffer large enough to hold the text, typically 4/3rds the size of the input data
 */

void ccct_base64_encode(const uint8_t *a_data, size_t a_len, char *a_textout)
{
    size_t i, out_ptr;
    uint8_t l_temp[3], l_out[5];
    uint8_t l_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    out_ptr = 0;
    for (i = 0; i < a_len; i += 3) {
        int l_numbytes = (i + 3 < a_len) ? 3 : a_len - i;
        memset(l_temp, 0, 3);
        memcpy(l_temp, a_data + i, l_numbytes);
        l_out[0] = l_chars[(l_temp[0] & 0xfc) >> 2];
        l_out[1] = l_chars[((l_temp[0] & 0x03) << 4) | ((l_temp[1] & 0xf0) >> 4)];
        l_out[2] = l_chars[((l_temp[1] & 0x0f) << 2) | ((l_temp[2] & 0xc0) >> 6)];
        l_out[3] = l_chars[l_temp[2] & 0x3f];
        l_out[4] = '\0';
        if (l_numbytes < 3)
            l_out[3] = '=';
        if (l_numbytes == 1)
            l_out[2] = '=';
        memcpy(a_textout + out_ptr, l_out, 4);
        out_ptr += 4;
    }
    a_textout[out_ptr] = 0; // null terminate the string
}

/**
 * @brief Decode a base64 string
 *
 * @param[in] a_textin A char pointer to a C string containing the base64 string
 * @param[out] a_binout A buffer large enough to hold the binary data, typically 3/4ths the size of the input string
 * @param[out] a_binout_len The length of the decoded binary string
 *
 * @return Zero if successful, or -1 if input string is unjustified, -2 if illegal characters appear in string
 */

int ccct_base64_decode(const char *a_textin, char *a_binout, uint32_t *a_binout_len)
{
    size_t i, io, j;
    size_t l_textin_len = strlen(a_textin);
    // bail out if we're not justified on a 4 character boundary
    if ((l_textin_len % 4) != 0) {
        return -1; // string must be a multiple of 4 chars or this won't work'
    }

    *a_binout_len = l_textin_len * 3 / 4;

    for (i = 0, io = 0; i < l_textin_len; i += 4, io += 3) {
        uint8_t l_in[4], l_out[3];
        memset(l_out, 0, 3);
        for (int j = 0; j < 4; ++j)
            l_in[j] = a_textin[i + j];
        if (l_in[3] == '=') {
            l_in[3] = 'A'; // zero it out
            (*a_binout_len)--;
        }
        if (a_textin[i + 2] == '=') {
            l_in[2] = 'A';
            (*a_binout_len)--;
        }
        //              std::cout << "i=" << i << " decode_len=" << *decode_len << std::endl;
        for (int j = 0; j < 4; ++j) {
            if ((l_in[j] >= 'A') && (l_in[j] <= 'Z'))
                l_in[j] -= 'A';
            else if ((l_in[j] >= 'a') && (l_in[j] <= 'z'))
                l_in[j] = l_in[j] - 'a' + 26;
            else if ((l_in[j] >= '0') && (l_in[j] <= '9'))
                l_in[j] = l_in[j] - '0' + 52;
            else if (l_in[j] == '+')
                l_in[j] = 62;
            else if (l_in[j] == '/')
                l_in[j] = 63;
            else {
                // illegal char in string
                return -2;
            }
        }
        l_out[0] = (l_in[0] << 2 | l_in[1] >> 4);
        l_out[1] = (l_in[1] << 4 | l_in[2] >> 2);
        l_out[2] = (((l_in[2] << 6) & 0xc0) | l_in[3]);
        memcpy(a_binout + io, l_out, 3);
    }

    return 0;
}

/**
 * @brief Creates PEM-style formatted base64
 *
 * @param[in] a_textin The base64 message to format
 * @param[out] a_textout The outputted formatted message
 * @param[in] a_header_text Message to place in header
 * @param[in] a_footer_text Message to place in footer
 */

void ccct_base64_format(const char *a_textin, char *a_textout, char *a_header_text, char *a_footer_text)
{
    size_t i, l_textout_ptr;

    a_textout[0] = 0;
    strcpy(a_textout, "-----");
    strcat(a_textout, a_header_text);
    strcat(a_textout, "-----");

    for (i = 0; i < strlen(a_textin); ++i) {
        if (i % 64 == 0) {
            strcat(a_textout, "\n");
        }
        strncat(a_textout, &a_textin[i], 1);
    }

    strcat(a_textout, "\n-----");
    strcat(a_textout, a_footer_text);
    strcat(a_textout, "-----\n");
}

/**
 * @brief Removes PEM-style formatting from base64 message
 *
 * @param[in] a_textin The base64 message to unformat
 * @param[out] a_textout The outputted unformatted message
 */

void ccct_base64_unformat(const char *a_textin, char *a_textout)
{
    size_t l_textin_ptr = 0;

    a_textout[0] = 0; // clear our output buffer before we work
unformat_top:
    if (a_textin[l_textin_ptr] == '-') {
        // header present, throw away to next linefeed
        while (a_textin[l_textin_ptr++] != '\n');
    } else {
        // throw away spaces, tabs, linefeeds, or any character that isn't a -
        while (a_textin[l_textin_ptr++] != '-');
        goto unformat_top;
    }
    while (l_textin_ptr < strlen(a_textin)) {
        if (a_textin[l_textin_ptr] == '-')
            break; // reached footer, we're done
        if (a_textin[l_textin_ptr] == '\n') {
            l_textin_ptr++;
            continue; // throw away linefeed
        }
        strncat(a_textout, &a_textin[l_textin_ptr], 1);
        l_textin_ptr++;
    }
    strcat(a_textout, "\0");
}

/**
 * @brief Open /dev/urandom
 */

int ccct_open_urandom()
{
    g_urandom_fd = open("/dev/urandom", O_RDONLY);
    if (g_urandom_fd < 0) {
        fprintf(stderr, "ccct: problems opening /dev/urandom: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    pthread_mutex_init(&g_urandom_mtx, NULL);
}

/**
 * @brief Return a string of random bytes
 *
 * @param[in] a_buffer Buffer large enough to hold bytes
 * @param[in] a_len Number of bytes to write
 */

void ccct_get_random(uint8_t *a_buffer, size_t a_len)
{
    int res;
    pthread_mutex_lock(&g_urandom_mtx);
    res = read(g_urandom_fd, a_buffer, a_len);
    if (res != a_len) {
        fprintf(stderr, "ccct: problems reading /dev/urandom: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    pthread_mutex_unlock(&g_urandom_mtx);
}

/**
 * @brief Close /dev/urandom
 */

int ccct_close_urandom()
{
    close(g_urandom_fd);
    pthread_mutex_destroy(&g_urandom_mtx);
}
