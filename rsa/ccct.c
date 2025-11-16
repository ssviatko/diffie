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

