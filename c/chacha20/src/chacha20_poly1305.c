#include "chacha20_poly1305.h"
#include "chacha20.h"
#include "poly1305.h"
#include <stdlib.h>
#include <string.h>

/* Converts a 64-bit length into an 8-byte Little-Endian array */
static void uint64_to_le_bytes(uint8_t out[8], uint64_t val)
{
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

/* Helper to assemble the Poly1305 MAC payload:
 * AAD | pad(AAD) | Ciphertext | pad(Ciphertext) | len(AAD) | len(Ciphertext) */
static int compute_poly1305_tag(const uint8_t poly_key[32], const uint8_t *ct,
                                size_t ct_len, const uint8_t *aad, size_t aad_len,
                                uint8_t tag[16])
{
    /* Padding required to align to 16-byte. */
    size_t aad_pad_len = (16 - (aad_len % 16)) % 16;
    size_t ct_pad_len  = (16 - (ct_len % 16)) % 16;

    size_t mac_data_len = aad_len + aad_pad_len + ct_len + ct_pad_len + 16;
    uint8_t *mac_data = calloc(1, mac_data_len);
    if (!mac_data) {
        return 1;
    }

    size_t offset = 0;

    /* 1. AAD + padding. */
    memcpy(mac_data, aad, aad_len);
    offset += aad_len + aad_pad_len;

    /* 2. Ciphertext + padding. */
    memcpy(mac_data + offset, ct, ct_len);
    offset += ct_len + ct_pad_len;

    /* 3. Original length of AAD and Ciphertext. */
    uint64_to_le_bytes(mac_data + offset, (uint64_t)aad_len);
    uint64_to_le_bytes(mac_data + offset + 8, (uint64_t)ct_len);

    /* 4. MAC computation. */
    poly1305_mac(poly_key, mac_data, mac_data_len, tag);

    free(mac_data);

    return 0;
}

int chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t iv[8],
                              const uint8_t constant[4], const uint8_t *pt,
                              size_t pt_len, const uint8_t *aad, size_t aad_len,
                              uint8_t *ct, uint8_t tag[16])
{
    uint8_t poly_key[32];
    uint8_t nonce[12];

    for (int i = 0; i < 4; i++) {
        nonce[i] = constant[i];
    }

    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = iv[i];
    }

    poly1305_key_gen(key, nonce, poly_key);

    if (pt && pt_len > 0) {
        chacha20_apply(key, 1, nonce, pt, pt_len, ct);
    }

    return compute_poly1305_tag(poly_key, ct, pt_len, aad, aad_len, tag);
}


int chacha20_poly1305_decrypt(const uint8_t key[32],  const uint8_t iv[8],
                              const uint8_t constant[4], const uint8_t *ct,
                              size_t ct_len, const uint8_t *aad, size_t aad_len,
                              const uint8_t tag[16], uint8_t *pt)
{
    uint8_t poly_key[32];
    uint8_t expected_tag[16];
    uint8_t nonce[12];

    for (int i = 0; i < 4; i++) {
        nonce[i] = constant[i];
    }

    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = iv[i];
    }

    poly1305_key_gen(key, nonce, poly_key);

    int ret = compute_poly1305_tag(poly_key, ct, ct_len, aad, aad_len, expected_tag);
    if (ret != 0) {
        return ret; /* Allocation failed. */
    }

    if (memcmp(expected_tag, tag, 16) != 0) {
        return -1; /* Forgery detected, aborting. */
    }

    if (ct && ct_len > 0) {
        chacha20_apply(key, 1, nonce, ct, ct_len, pt);
    }

    return 0;
}