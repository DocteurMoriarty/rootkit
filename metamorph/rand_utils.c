/**
 * @file rand_utils.c
 * @brief Cryptographically random generation utilities — implementation.
 */

#include "rand_utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char hex_chars[] = "0123456789abcdef";

/**
 * @brief Fill a buffer with random bytes from /dev/urandom.
 *
 * On open or read failure, @p out is zeroed or filled with 0xAA
 * respectively as a sentinel value.
 *
 * @param out  Destination buffer.  Must be at least @p n bytes.
 * @param n    Number of random bytes to write.
 */
void rand_bytes(uint8_t *out, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("rand_bytes: open /dev/urandom");
        memset(out, 0, n);
        return;
    }
    ssize_t r = read(fd, out, n);
    if (r < 0 || (size_t)r != n)
        memset(out, 0xAA, n);
    close(fd);
}

/**
 * @brief Return a random 32-bit unsigned integer.
 *
 * @return Random uint32_t sourced from /dev/urandom.
 */
uint32_t rand_u32(void)
{
    uint32_t v;
    rand_bytes((uint8_t *)&v, sizeof(v));
    return v;
}

/**
 * @brief Return a random value in the half-open interval [min, max).
 *
 * Returns @p min if @p max is less than or equal to @p min.
 *
 * @param min  Inclusive lower bound.
 * @param max  Exclusive upper bound.
 * @return     Random value in [min, max).
 */
uint32_t rand_range(uint32_t min, uint32_t max)
{
    if (max <= min)
        return min;
    return min + (rand_u32() % (max - min));
}

/**
 * @brief Write a random lowercase hex string of exactly @p len characters.
 *
 * Reads ceil(len/2) random bytes and maps each nibble to a hex digit.
 * @p out must point to a buffer of at least @p len + 1 bytes.
 *
 * @param out  Destination buffer (at least len + 1 bytes).
 * @param len  Number of hex characters to generate.
 */
void rand_hex_str(char *out, size_t len)
{
    uint8_t tmp[(len / 2) + 1];
    rand_bytes(tmp, sizeof(tmp));
    for (size_t i = 0; i < len; i++)
        out[i] = hex_chars[(tmp[i / 2] >> (i % 2 ? 0 : 4)) & 0xF];
    out[len] = '\0';
}
