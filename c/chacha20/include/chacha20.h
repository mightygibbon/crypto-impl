#ifndef __CHACHA20__
#define __CHACHA20__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define STATE_WORD_NO 16
#define CONSTANT0 0x61707865
#define CONSTANT1 0x3320646e
#define CONSTANT2 0x79622d32
#define CONSTANT3 0x6b206574
#define TO_LE_WORD(b0, b1, b2, b3) \
    (((uint32_t)(b3) << 24) | ((uint32_t)(b2) << 16) | \
    ((uint32_t)(b1) << 8) | (uint32_t)(b0))
#define ROTL32(word, shift) ((word << shift) | (word >> (32-shift)))

/*
 * Encrypt data using ChaCha20 stream cipher
 * 
 * It is the caller responsibility to:
 *  - Ensure that key is 32 bytes, nonce is 12 bytes, counter is 4 bytes
 *  - Provide a valid ciphertext buffer of at least length bytes
 */
void encrypt(uint8_t * key, uint8_t * nonce, uint8_t * counter,
        uint8_t * plaintext, uint8_t * ciphertext, size_t length);

#endif
