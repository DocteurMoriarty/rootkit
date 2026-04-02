/**
 * @file rand_utils.h
 * @brief Cryptographically random generation utilities.
 *
 * All entropy is sourced from /dev/urandom.  These functions are
 * intended for build-time randomisation (symbol names, padding sizes,
 * build identifiers) and must not be used for cryptographic keys.
 */

#ifndef RAND_UTILS_H
#define RAND_UTILS_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Fill a buffer with random bytes from /dev/urandom.
 *
 * On read failure, @p out is filled with 0xAA as a sentinel value.
 *
 * @param out  Destination buffer.  Must be at least @p n bytes.
 * @param n    Number of random bytes to write.
 */
void rand_bytes(uint8_t *out, size_t n);

/**
 * @brief Return a random 32-bit unsigned integer.
 *
 * @return Random uint32_t sourced from /dev/urandom.
 */
uint32_t rand_u32(void);

/**
 * @brief Return a random value in the half-open interval [min, max).
 *
 * Returns @p min if @p max is less than or equal to @p min.
 *
 * @param min  Inclusive lower bound.
 * @param max  Exclusive upper bound.
 * @return     Random value in [min, max).
 */
uint32_t rand_range(uint32_t min, uint32_t max);

/**
 * @brief Write a random lowercase hex string of exactly @p len characters.
 *
 * @p out must point to a buffer of at least @p len + 1 bytes.
 * The string is null-terminated.  Example: rand_hex_str(buf, 6) -> "a3f90c".
 *
 * @param out  Destination buffer (at least len + 1 bytes).
 * @param len  Number of hex characters to generate (excluding null terminator).
 */
void rand_hex_str(char *out, size_t len);

#endif /* RAND_UTILS_H */
