#include "chacha20.h"
#include <string.h>

/**
 * @brief Initializes the 16-word ChaCha20 state matrix.
 * 
 * @param state   The 16-word (64-byte) state array.
 * @param key     The 32-byte key.
 * @param nonce   The 12-byte nonce.
 * @param counter The 4-byte counter word.
 */
static void init_state(uint32_t state[16], const uint8_t key[32],
                       const uint8_t nonce[12], uint32_t counter)
{
    /* RFC 8439 Constants */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    /* 32-byte Key */
    state[4] = be_to_le(key[0], key[1], key[2], key[3]);
    state[5] = be_to_le(key[4], key[5], key[6], key[7]);
    state[6] = be_to_le(key[8], key[9], key[10], key[11]);
    state[7] = be_to_le(key[12], key[13], key[14], key[15]);
    state[8] = be_to_le(key[16], key[17], key[18], key[19]);
    state[9] = be_to_le(key[20], key[21], key[22], key[23]);
    state[10] = be_to_le(key[24], key[25], key[26], key[27]);
    state[11] = be_to_le(key[28], key[29], key[30], key[31]);

    /* Counter word */
    state[12] = counter;

    /* 12-byte Nonce */
    state[13] = be_to_le(nonce[0], nonce[1], nonce[2], nonce[3]);
    state[14] = be_to_le(nonce[4], nonce[5], nonce[6], nonce[7]);
    state[15] = be_to_le(nonce[8], nonce[9], nonce[10], nonce[11]);
}

int chacha20_block(const uint8_t key[32], uint32_t counter,
                   const uint8_t nonce[12], uint8_t keystream[64])
{
    uint32_t state[16];
    uint32_t w_state[16];

    init_state(state, key, nonce, counter);
    memcpy(w_state, state, 16 * sizeof(uint32_t));

    /* 20 rounds (10 column rounds, 10 diagonal rounds) */
    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        quarter_round(&w_state[0], &w_state[4], &w_state[8], &w_state[12]);
        quarter_round(&w_state[1], &w_state[5], &w_state[9], &w_state[13]);
        quarter_round(&w_state[2], &w_state[6], &w_state[10], &w_state[14]);
        quarter_round(&w_state[3], &w_state[7], &w_state[11], &w_state[15]);

        /* Diagonal rounds */
        quarter_round(&w_state[0], &w_state[5], &w_state[10], &w_state[15]);
        quarter_round(&w_state[1], &w_state[6], &w_state[11], &w_state[12]);
        quarter_round(&w_state[2], &w_state[7], &w_state[8], &w_state[13]);
        quarter_round(&w_state[3], &w_state[4], &w_state[9], &w_state[14]);
    }

    /* Add original state to working state and serialize */
    for (int i = 0; i < 16; i++) {
        uint32_t final_word = state[i] + w_state[i];
        
        keystream[i * 4 + 0] = final_word & 0xff;
        keystream[i * 4 + 1] = (final_word >> 8) & 0xff;
        keystream[i * 4 + 2] = (final_word >> 16) & 0xff;
        keystream[i * 4 + 3] = (final_word >> 24) & 0xff;
    }

    return 0;
}

int chacha20_apply(const uint8_t key[32], uint32_t counter,
                   const uint8_t nonce[12], const uint8_t *data_in,
                   size_t data_length, uint8_t *data_out)
{
    /* 2^32 blocks * 64 bytes/block = 274877906944 bytes */
    if (data_length > 274877906944ull) {
        return 1; 
    }

    uint8_t keystream[64];
    size_t full_blocks_no = data_length / 64;
    size_t remaining = data_length % 64;

    for (size_t i = 0; i < full_blocks_no; i++) {
        chacha20_block(key, counter, nonce, keystream);
        for (size_t j = 0; j < 64; j++) {
            data_out[i * 64 + j] = data_in[i * 64 + j] ^ keystream[j];
        }
        counter += 1;
    }

    if (remaining) {
        chacha20_block(key, counter, nonce, keystream);
        for (size_t i = 0; i < remaining; i++) {
            data_out[full_blocks_no * 64 + i] = data_in[full_blocks_no * 64 + i] ^ keystream[i];
        }
    }

    return 0;
}