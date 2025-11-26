#include "chacha20.h"

static void init_state(uint32_t * state, uint8_t * key, uint8_t * nonce,
        uint32_t counter)
{
    state[0] = CONSTANT0;
    state[1] = CONSTANT1;
    state[2] = CONSTANT2;
    state[3] = CONSTANT3;

    state[4] = TO_LE_WORD(key[0], key[1], key[2], key[3]);
    state[5] = TO_LE_WORD(key[4], key[5], key[6], key[7]);
    state[6] = TO_LE_WORD(key[8], key[9], key[10], key[11]);
    state[7] = TO_LE_WORD(key[12], key[13], key[14], key[15]);
    
    state[8] = TO_LE_WORD(key[16], key[17], key[18], key[19]);
    state[9] = TO_LE_WORD(key[20], key[21], key[22], key[23]);
    state[10] = TO_LE_WORD(key[24], key[25], key[26], key[27]);
    state[11] = TO_LE_WORD(key[28], key[29], key[30], key[31]);

    state[12] = counter;
    state[13] = TO_LE_WORD(nonce[0], nonce[1], nonce[2], nonce[3]);
    state[14] = TO_LE_WORD(nonce[4], nonce[5], nonce[6], nonce[7]);
    state[15] = TO_LE_WORD(nonce[8], nonce[9], nonce[10], nonce[11]);
}

static void quarter_round(uint32_t * state, size_t idx1, size_t idx2,
        size_t idx3, size_t idx4)
{
    uint32_t a = state[idx1];
    uint32_t b = state[idx2];
    uint32_t c = state[idx3];
    uint32_t d = state[idx4];

    a += b;
    d ^= a;
    d = ROTL32(d, 16);

    c += d;
    b ^= c;
    b = ROTL32(b, 12);

    a += b;
    d ^= a;
    d = ROTL32(d, 8);

    c += d;
    b ^= c;
    b = ROTL32(b, 7);

    state[idx1] = a;
    state[idx2] = b;
    state[idx3] = c;
    state[idx4] = d;
}

static void get_keystream(uint8_t * keystream, uint8_t * key, uint8_t * nonce,
        uint32_t counter)
{
    uint32_t state[STATE_WORD_NO];
    uint32_t working_state[STATE_WORD_NO];

    init_state(state, key, nonce, counter);
    memcpy(working_state, state, STATE_WORD_NO * sizeof(uint32_t));

    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        quarter_round(working_state, 0, 4, 8, 12);
        quarter_round(working_state, 1, 5, 9, 13);
        quarter_round(working_state, 2, 6, 10, 14);
        quarter_round(working_state, 3, 7, 11, 15);

        /* Diagonal rounds */
        quarter_round(working_state, 0, 5, 10, 15);
        quarter_round(working_state, 1, 6, 11, 12);
        quarter_round(working_state, 2, 7, 8, 13);
        quarter_round(working_state, 3, 4, 9, 14);
    }

    for (int i = 0; i < 16; i++) {
        uint32_t final_word = state[i] + working_state[i];
        keystream[i*4 + 0] = final_word & 0xff;
        keystream[i*4 + 1] = (final_word >> 8) & 0xff;
        keystream[i*4 + 2] = (final_word >> 16) & 0xff;
        keystream[i*4 + 3] = (final_word >> 24) & 0xff;
    }
}

void encrypt(uint8_t * key, uint8_t * nonce, uint8_t * counter,
        uint8_t * plaintext, uint8_t * ciphertext, size_t length)
{
    uint32_t count = TO_LE_WORD(counter[0], counter[1], counter[2], 
            counter[3]);
    uint8_t keystream[64];
    size_t full_blocks = length / 64;
    size_t remaining = length % 64;

    for (size_t i = 0; i < full_blocks; i++) {
        get_keystream(keystream, key, nonce, count + (uint32_t)i);

        for (size_t j = 0; j < 64; j++) {
            ciphertext[i*64 + j] = plaintext[i*64 + j] ^ keystream[j];
        }
    }

    if (remaining > 0) {
        size_t i = full_blocks;
        get_keystream(keystream, key, nonce, count + (uint32_t)i);

        for (size_t j = 0; j < remaining; j++) {
            ciphertext[i*64 + j] = plaintext[i*64 + j] ^ keystream[j];
        }
    }
}
