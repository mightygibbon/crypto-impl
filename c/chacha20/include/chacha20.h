#ifndef __CHACHA20__
#define __CHACHA20__

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Generates a 64-byte keystream block for a given key, counter, and nonce.
 *  
 * @param[in]  key       The 32-byte (256-bit) symmetric key.
 * @param[in]  counter   The 32-bit block counter.
 * @param[in]  nonce     The 12-byte (96-bit) nonce.
 * @param[out] keystream The output buffer to receive the 64-byte keystream.
 * @return               0 on success, non-zero on failure.
 */
int chacha20_block(const uint8_t key[32], uint32_t counter,
                   const uint8_t nonce[12], uint8_t keystream[64]);

/**
 * @brief Encrypts or decrypts data in place using the ChaCha20 stream cipher.
 * 
 * @param[in]     key         The 32-byte (256-bit) symmetric key.
 * @param[in]     counter     The 4-byte (16-bit) counter.
 * @param[in]     nonce       The 12-byte (96-bit) nonce.
 * @param[in]     data_in     Pointer to the data buffer to encrypt/decrypt.
 * @param[in]     data_length The length of the data buffer in bytes.
 * @param[out]    data_out    Pointer to the result obtained after the application.
 * @return                    0 on success, 1 if an invalid data_length is provided.
 */
int chacha20_apply(const uint8_t key[32], uint32_t counter,
                   const uint8_t nonce[12], const uint8_t *data_in,
                   size_t data_length, uint8_t *data_out);

/**
 * @brief Packs four individual bytes into a 32-bit little-endian word.
 * 
 * @param[in] b3 The most significant byte (byte 3).
 * @param[in] b2 The third byte (byte 2).
 * @param[in] b1 The second byte (byte 1).
 * @param[in] b0 The least significant byte (byte 0).
 * @return       The composed 32-bit unsigned integer.
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
 * @param[in] word  The 32-bit integer to rotate.
 * @param[in] shift The number of bit positions to rotate left.
 * @return          The rotated 32-bit integer.
 */
static inline uint32_t rotl(uint32_t word, uint8_t shift)
{
    return (word << shift) | (word >> (32 - shift));
}

/**
 * @brief Performs the ChaCha20 quarter round operation on four state words.
 * 
 * @param[in,out] a Pointer to the first state word.
 * @param[in,out] b Pointer to the second state word.
 * @param[in,out] c Pointer to the third state word.
 * @param[in,out] d Pointer to the fourth state word.
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