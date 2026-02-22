#ifndef __CHACHA20__
#define __CHACHA20__

#include <stdint.h>
#include <stddef.h>

/**
 * @brief chacha20_applys or decrypts data using the ChaCha20 stream cipher.
 * 
 * @param key         The 32-byte key.
 * @param nonce       The 12-byte nonce.
 * @param counter     The 4-byte initial counter.
 * @param data        Pointer to data buffer.
 * @param data_length Length of the data to process in bytes.
 */
void chacha20_apply(uint8_t key[32], uint8_t nonce[12], uint8_t counter[4],
                    uint8_t *data, size_t data_length);

/**
 * @brief Converts four bytes into a 32-bit little-endian word.
 * 
 * @param b3 The most significant byte.
 * @param b2 The third byte.
 * @param b1 The second byte.
 * @param b0 The least significant byte.
 * @return   The composed 32-bit unsigned integer.
 */
static inline uint32_t be_to_le(uint32_t b3, uint32_t b2, uint32_t b1,
                                uint32_t b0)
{
    return ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) | ((uint32_t)b2 << 8) | 
           (uint32_t)b3;
}

/**
 * @brief Performs a bitwise circular left rotation.
 * 
 * @param word  The 32-bit integer to rotate.
 * @param shift The number of bit positions to rotate left.
 * @return      The rotated 32-bit integer.
 */
static inline uint32_t rotl(uint32_t word, uint8_t shift)
{
    return (word << shift) | (word >> (32 - shift));
}

/**
 * @brief Performs ChaCha20 quarter round on four state words.
 * 
 * @param a Pointer to the first state word.
 * @param b Pointer to the second state word.
 * @param c Pointer to the third state word.
 * @param d Pointer to the fourth state word.
 */
static inline void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c,
                                 uint32_t *d)
{
    *a += *b; *d ^= *a; *d = rotl(*d, 16);
    *c += *d; *b ^= *c; *b = rotl(*b, 12);
    *a += *b; *d ^= *a; *d = rotl(*d, 8);
    *c += *d; *b ^= *c; *b = rotl(*b, 7);
}

#endif /* __CHACHA20__ */