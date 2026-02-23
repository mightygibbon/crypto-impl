#ifndef __POLY1305__
#define __POLY1305__

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Computes the Poly1305 Message Authentication Code (MAC) for a given message.
 * 
 * @param[in]  key     The 32-byte one-time Poly1305 key.
 * @param[in]  msg     Pointer to the message buffer to authenticate.
 * @param[in]  msg_len The length of the message in bytes.
 * @param[out] tag     The 16-byte output buffer to receive the computed MAC.
 * @return             0 on success, non-zero on failure.
 */
int poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t msg_len,
                 uint8_t tag[16]);

/**
 * @brief Generates a one-time Poly1305 key using a ChaCha20 block.
 * 
 * @param[in]  chacha_key The 32-byte (256-bit) ChaCha20 key.
 * @param[in]  nonce      The 12-byte (96-bit) nonce.
 * @param[out] poly_key   The 32-byte output buffer for the generated Poly1305 key.
 * @return                0 on success, non-zero on failure.
 */
int poly1305_key_gen(const uint8_t chacha_key[32], const uint8_t nonce[12],
                     uint8_t poly_key[32]);

/**
 * @brief Clamps the 'r' half of the Poly1305 key to meet RFC 8439 requirements.
 * 
 * @param[in,out] r The 16-byte 'r' key part to clamp in place.
 */
static inline void poly1305_clamp(uint8_t r[16]) {
    r[3] &= 0x0f; r[7] &= 0x0f; r[11] &= 0x0f; r[15] &= 0x0f;
    r[4] &= 0xfc; r[8] &= 0xfc; r[12] &= 0xfc;
}

#endif /* __POLY1305__ */