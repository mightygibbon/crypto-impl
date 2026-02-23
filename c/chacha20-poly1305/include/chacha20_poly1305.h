#ifndef __CHACHA20_POLY1305__
#define __CHACHA20_POLY1305__

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Encrypts and authenticates data using ChaCha20-Poly1305 AEAD.
 *  
 * @param[in]  key        The 32-byte (256-bit) symmetric key.
 * @param[in]  iv         The 8-byte initialization vector (nonce part).
 * @param[in]  constant   The 4-byte constant (nonce part).
 * @param[in]  pt         Pointer to the plaintext data.
 * @param[in]  pt_len     Length of the plaintext in bytes.
 * @param[in]  aad        Pointer to the Additional Authenticated Data (AAD).
 * @param[in]  aad_len    Length of the AAD in bytes.
 * @param[out] ct         The output buffer for the encrypted data.
 * @param[out] tag        The 16-byte output buffer for the authentication tag.
 * @return                0 on success, non-zero on memory allocation failure.
 */
int chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t iv[8],
                              const uint8_t constant[4], const uint8_t *pt,
                              size_t pt_len, const uint8_t *aad, size_t aad_len,
                              uint8_t *ct, uint8_t tag[16]);

/**
 * @brief Decrypts and verifies data using ChaCha20-Poly1305 AEAD.
 *
 * @param[in]  key        The 32-byte (256-bit) symmetric key.
 * @param[in]  iv         The 8-byte initialization vector (nonce part).
 * @param[in]  constant   The 4-byte constant (nonce part).
 * @param[in]  ct         Pointer to the ciphertext data.
 * @param[in]  ct_len     Length of the ciphertext in bytes.
 * @param[in]  aad        Pointer to the Additional Authenticated Data (AAD).
 * @param[in]  aad_len    Length of the AAD in bytes.
 * @param[in]  tag        The 16-byte expected authentication tag to verify.
 * @param[out] pt         The output buffer for the decrypted data. Must be at least `ct_len` bytes.
 * @return                0 on successful verification and decryption, -1 if the tag is invalid, positive on allocation failure.
 */
int chacha20_poly1305_decrypt(const uint8_t key[32],  const uint8_t iv[8],
                              const uint8_t constant[4], const uint8_t *ct,
                              size_t ct_len, const uint8_t *aad, size_t aad_len,
                              const uint8_t tag[16], uint8_t *pt);

#endif /* __CHACHA20_POLY1305__ */