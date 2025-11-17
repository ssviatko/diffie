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
 * @file ccct.h
 * @brief C Crytographic Common Tools
 *
 * Common routines to support cryptographic software included in the
 * sscrypto library.
 *
 */

#ifndef CCCT_H
#define CCCT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>

/**
 * @union ccct_reversible_int64_t
 * @brief Store an int64 that can be reversed.
 * Data is mirrored in char array so data can be reversed based on endianness.
 */

typedef union {
    int64_t ll; ///< The "long long" (int64)
    char data[8]; ///< Raw byte data for int64
} ccct_reversible_int64_t;

/**
 * @union ccct_reversible_float_t
 * @brief Store a float that can be reversed.
 * Data is mirrored in char array so data can be reversed based on endianness.
 */

typedef union {
    float f; ///< The float value
    char data[4]; ///< Rw byte data for float
} ccct_reversible_float_t;

void ccct_set_debug             (int a_debug);
void ccct_get_term_size         ();
void ccct_print_hex             (uint8_t *a_buffer, size_t a_len);
void ccct_right_justify         (size_t a_size, size_t a_offset, char *a_buff);
void ccct_progress              (uint32_t a_sofar, uint32_t a_total);
void ccct_discover_endianness   ();
int  ccct_endianness            ();
void ccct_reverse_int64         (ccct_reversible_int64_t *a_val);
void ccct_reverse_float         (ccct_reversible_float_t *a_val);
void ccct_base64_encode         (const uint8_t *a_data, size_t a_len, char *a_textout);
void ccct_base64_format         (const char *a_textin, char *a_textout, char *a_header_text, char *a_footer_text);
int  ccct_base64_decode         (const char *a_textin, char *a_binout, uint32_t *a_binout_len);
void ccct_base64_unformat       (const char *a_textin, char *a_textout);

#ifdef __cplusplus
}
#endif

#endif /* CCCT_H */
