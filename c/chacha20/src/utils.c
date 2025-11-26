#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

static uint8_t hex_to_nibble(char c)
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + (c - 'a');
    if ('A' <= c && c <= 'F') return 10 + (c - 'A');
    fprintf(stderr, "Invalid hex character: %c\n", c);
    exit(EXIT_FAILURE);
}

void hex_to_bytes(const char * hex, uint8_t * out, size_t out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) {
        fprintf(stderr, "Hex string length does not match expected byte \
                length\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < out_len; i++) {
        out[i] = (hex_to_nibble(hex[i*2]) << 4) | hex_to_nibble(hex[i*2 + 1]);
    }
}

void print_usage(const char * prog)
{
    printf("Usage: %s <key-hex> <nonce-hex> <counter-hex> <plaintext-hex>\n",
            prog);
    printf("  key:       64 hex characters (32 bytes)\n");
    printf("  nonce:     24 hex characters (12 bytes)\n");
    printf("  counter:   8 hex characters  (4 bytes)\n");
    printf("  plaintext: hex-encoded plaintext\n");
}
