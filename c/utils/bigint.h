/**
 * @file bigint.h
 * @brief Arbitrary-precision integer arithmetic library.
 */

#ifndef BIGINT_H
#define BIGINT_H

#include <stdint.h>
#include <stdlib.h>

/**
 * @brief Structure representing a multiple-precision integer.
 */
typedef struct {
    uint32_t *limbs;  /**< Array of 32-bit limbs in Little-Endian order */
    int8_t sign;      /**< Sign of the number: 1 (positive), -1 (negative), 0 (zero) */
    size_t size;      /**< Number of allocated 32-bit limbs */
} bigint_t;

/* Memory Management */

/**
 * @brief Allocates a new bigint_t structure.
 * 
 * @param sign The sign of the newly allocated number (1, -1, or 0).
 * @param byte_length The anticipated size of the number in bytes.
 * @return A new bigint_t structure passed by value.
 */
bigint_t bigint_alloc(int8_t sign, size_t byte_length);

/**
 * @brief Frees the internal memory of a bigint_t structure.
 * 
 * @param bignum Pointer to the bigint_t to be freed.
 */
void bigint_free(bigint_t *bignum);

/* Conversions */

/**
 * @brief Constructs a bigint_t from a Big-Endian byte array.
 * 
 * @param sign The sign to apply to the resulting number.
 * @param num_bytes The length of the byte array.
 * @param bytes Pointer to the array of unsigned bytes.
 * @return The constructed bigint_t.
 */
bigint_t bigint_from_be_bytes(int8_t sign, size_t num_bytes, const uint8_t *bytes);

/**
 * @brief Constructs a bigint_t from a Little-Endian byte array.
 * 
 * @param sign The sign to apply to the resulting number.
 * @param num_bytes The length of the byte array.
 * @param bytes Pointer to the array of unsigned bytes.
 * @return The constructed bigint_t.
 */
bigint_t bigint_from_le_bytes(int8_t sign, size_t num_bytes, const uint8_t *bytes);

/**
 * @brief Constructs a bigint_t from a Big-Endian hexadecimal string.
 * 
 * @param sign The sign to apply to the resulting number.
 * @param hex Null-terminated string containing hexadecimal characters.
 * @return The constructed bigint_t. Returns a 0-value bigint on invalid input.
 */
bigint_t bigint_from_be_hex(int8_t sign, const char *hex);

/**
 * @brief Constructs a bigint_t from a Little-Endian hexadecimal string.
 * 
 * @param sign The sign to apply to the resulting number.
 * @param hex Null-terminated string containing hexadecimal characters.
 * @return The constructed bigint_t. Returns a 0-value bigint on invalid input.
 */
bigint_t bigint_from_le_hex(int8_t sign, const char *hex);

/**
 * @brief Constructs a bigint_t from a decimal string.
 * 
 * @param dec Null-terminated string containing a decimal number.
 * @return The constructed bigint_t. Returns a 0-value bigint on invalid input.
 */
bigint_t bigint_from_dec(const char *dec);

/* Utility Operations */

/**
 * @brief Deep copies a bigint_t structure.
 * 
 * @param dest Pointer to the destination bigint_t.
 * @param src Pointer to the source bigint_t to copy from.
 * @return 0 on success, non-zero on allocation failure.
 */
int bigint_copy(bigint_t *dest, const bigint_t *src);

/* Absolute Value Operations */

/**
 * @brief Compares the absolute values (magnitudes) of two big integers.
 * 
 * @param a Pointer to the first bigint_t.
 * @param b Pointer to the second bigint_t.
 * @return 1 if |a| > |b|, -1 if |a| < |b|, and 0 if |a| == |b|.
 */
int bigint_cmp_abs(const bigint_t *a, const bigint_t *b);

/**
 * @brief Adds the absolute values of two big integers: |dest| = |a| + |b|.
 * 
 * @param dest Pointer to the destination bigint_t.
 * @param a Pointer to the first operand.
 * @param b Pointer to the second operand.
 * @return 0 on success, non-zero on allocation failure.
 */
int bigint_add_abs(bigint_t *dest, const bigint_t *a, const bigint_t *b);

/**
 * @brief Subtracts the absolute values of two big integers: |dest| = |a| - |b|.
 * @note Requires |a| >= |b|.
 * 
 * @param dest Pointer to the destination bigint_t.
 * @param a Pointer to the first operand.
 * @param b Pointer to the second operand.
 * @return 0 on success, non-zero on allocation failure.
 */
int bigint_sub_abs(bigint_t *dest, const bigint_t *a, const bigint_t *b);

/**
 * @brief Multiplies the absolute values of two big integers: |dest| = |a| * |b|.
 * 
 * @param dest Pointer to the destination bigint_t.
 * @param a Pointer to the first operand.
 * @param b Pointer to the second operand.
 * @return 0 on success, non-zero on allocation failure.
 */
int bigint_mul_abs(bigint_t *dest, const bigint_t *a, const bigint_t *b);

/* Signed Arithmetic Operations */

/**
 * @brief Adds two big integers considering their signs: dest = a + b.
 * 
 * @param dest Pointer to the destination bigint_t.
 * @param a Pointer to the first operand.
 * @param b Pointer to the second operand.
 * @return 0 on success, non-zero on error/allocation failure.
 */
int bigint_add(bigint_t *dest, const bigint_t *a, const bigint_t *b);

/**
 * @brief Subtracts two big integers considering their signs: dest = a - b.
 * 
 * @param dest Pointer to the destination bigint_t.
 * @param a Pointer to the first operand.
 * @param b Pointer to the second operand.
 * @return 0 on success, non-zero on error/allocation failure.
 */
int bigint_sub(bigint_t *dest, const bigint_t *a, const bigint_t *b);

/**
 * @brief Multiplies two big integers considering their signs: dest = a * b.
 * 
 * @param dest Pointer to the destination bigint_t.
 * @param a Pointer to the first operand.
 * @param b Pointer to the second operand.
 * @return 0 on success, non-zero on error/allocation failure.
 */
int bigint_mul(bigint_t *dest, const bigint_t *a, const bigint_t *b);

/**
 * @brief Computes the quotient and remainder (modulo) of two big integers.
 * @note You can pass NULL for quotient or remainder if you only need one of them.
 * 
 * @param quotient Pointer to the destination bigint_t for the quotient
 * (optional).
 * @param remainder Pointer to the destination bigint_t for the remainder/modulo
 * (optional).
 * @param numerator Pointer to the dividend.
 * @param denominator Pointer to the divisor.
 * @return 0 on success, -1 on division by zero, positive non-zero on allocation
 * failure.
 */
int bigint_div_mod(bigint_t *quotient, bigint_t *remainder,
                   const bigint_t *numerator, const bigint_t *denominator);

/**
 * @brief Divides two big integers: dest = a / b.
 * 
 * @param dest Pointer to the destination bigint_t.
 * @param a Pointer to the numerator.
 * @param b Pointer to the denominator.
 * @return 0 on success, -1 on division by zero, positive non-zero on allocation
 * failure.
 */
int bigint_div(bigint_t *dest, const bigint_t *a, const bigint_t *b);

/**
 * @brief Computes the modulo of two big integers: dest = a % b.
 * 
 * @param dest Pointer to the destination bigint_t.
 * @param a Pointer to the numerator.
 * @param b Pointer to the denominator.
 * @return 0 on success, -1 on division by zero, positive non-zero on allocation
 * failure.
 */
int bigint_mod(bigint_t *dest, const bigint_t *a, const bigint_t *b);

/**
 * @brief Computes the strictly positive Euclidean modulo: dest = a mod b.
 * 
 * @param dest Pointer to the destination bigint_t.
 * @param a Pointer to the numerator.
 * @param b Pointer to the denominator.
 * @return 0 on success, -1 on division by zero, positive non-zero on allocation
 * failure.
 */
int bigint_mod_crypto(bigint_t *dest, const bigint_t *a, const bigint_t *b);

#endif /* BIGINT_H */