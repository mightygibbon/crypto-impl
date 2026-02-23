#include "poly1305.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "bigint.h"
#include "chacha20.h"

int poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t msg_len,
                 uint8_t tag[16])
{
    /* Creation of (r, s). */
    uint8_t r[16];
    uint8_t s[16];

    for (size_t i = 0; i < 16; i++) {
        r[i] = key[i];
        s[i] = key[16 + i];
    }

    /* Clamping of r. */
    poly1305_clamp(r);

    /* Setup bigint_t numbers. */
    bigint_t r_num = bigint_from_le_bytes(1, 16, r);
    bigint_t s_num = bigint_from_le_bytes(1, 16, s);
    bigint_t acc = bigint_alloc(0, 0);
    bigint_t P = bigint_from_be_hex(1, "3fffffffffffffffffffffffffffffffb");

    size_t full_blocks_no = msg_len / 16;
    size_t remaining = msg_len % 16;

    for (size_t i = 0; i < full_blocks_no; i++) {
        uint8_t coeff[17] = {0};
        for (size_t j = 0; j < 16; j++) {
            coeff[j] = msg[i * 16 + j];
        }
        coeff[16] = 0x01;

        bigint_t n = bigint_from_le_bytes(1, 17, coeff);
        bigint_add(&acc, &acc, &n);         // acc += n
        bigint_mul(&acc, &acc, &r_num);     // acc *= r
        bigint_mod(&acc, &acc, &P);         // acc %= P
        bigint_free(&n);
    }

    if (remaining) {
        uint8_t coeff[17] = {0};
        for (size_t j = 0; j < remaining; j++) {
            coeff[j] = msg[full_blocks_no * 16 + j];
        }
        coeff[remaining] = 0x01;

        bigint_t n = bigint_from_le_bytes(1, 17, coeff);
        bigint_add(&acc, &acc, &n);
        bigint_mul(&acc, &acc, &r_num);
        bigint_mod(&acc, &acc, &P);
        bigint_free(&n);
    }

    bigint_add(&acc, &acc, &s_num);

    bigint_to_le_bytes(&acc, tag, 16);

    bigint_free(&r_num);
    bigint_free(&s_num);
    bigint_free(&acc);
    bigint_free(&P);

    return 0;
}

int poly1305_key_gen(const uint8_t chacha_key[32], const uint8_t nonce[12],
                     uint8_t poly_key[32])
{
    uint8_t keystream[64];

    chacha20_block(chacha_key, 0, nonce, keystream);

    for (int i = 0; i < 32; i++) {
        poly_key[i] = keystream[i];
    }

    return 0;
}