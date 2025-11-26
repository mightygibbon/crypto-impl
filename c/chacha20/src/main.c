#include <stdio.h>
#include <stdlib.h>
#include "chacha20.h"
#include "utils.h"

int main(int argc, char ** argv)
{
    if (argc != 5 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    uint8_t key[32], nonce[12], counter[4];
    size_t plaintext_len = strlen(argv[4]) / 2;
    uint8_t * plaintext = malloc(plaintext_len);
    uint8_t * ciphertext = malloc(plaintext_len);
    if (!plaintext || !ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    hex_to_bytes(argv[1], key, sizeof(key));
    hex_to_bytes(argv[2], nonce, sizeof(nonce));
    hex_to_bytes(argv[3], counter, sizeof(counter));
    hex_to_bytes(argv[4], plaintext, plaintext_len);

    encrypt(key, nonce, counter, plaintext, ciphertext, plaintext_len);

    for (size_t i = 0; i < plaintext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    free(plaintext);
    free(ciphertext);
    return 0;
}
