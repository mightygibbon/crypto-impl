#ifndef __POLY1305__
#define __POLY1305__

#include <stdint.h>
#include <stddef.h>
#include "bigint.h"

int poly1305_mac(uint8_t key[32], uint8_t *msg, size_t msg_len, uint8_t tag[16]);

static inline void poly1305_clamp(uint8_t r[16]) {
    r[3] &= 0x0f; r[7] &= 0x0f; r[11] &= 0x0f; r[15] &= 0x0f;
    r[4] &= 0xfc; r[8] &= 0xfc; r[12] &= 0xfc;
}

#endif /* __POLY1305__ */