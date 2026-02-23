# ChaCha20-Poly1305 AEAD

Dependency-free implementation of the ChaCha20 stream cipher, the Poly1305 message authentication code, and the combined ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) construction, as defined in RFC 8439.

## Features

* **ChaCha20**: 256-bit key, 96-bit nonce, 32-bit counter stream cipher.
* **Poly1305**: One-time message authentication code (MAC).
* **AEAD ChaCha20-Poly1305**: Authenticated Encryption with Associated Data, ensuring both data confidentiality and integrity.
* **Zero Dependencies**: Relies exclusively on standard C library functions.

## Repository Structure

```text
├── include/
│   ├── chacha20.h              # Stream cipher API
│   ├── poly1305.h              # MAC API
│   └── chacha20_poly1305.h     # AEAD API
├── src/
│   ├── main.c                  # Test vectors and validation suite
│   ├── chacha20.c              # Stream cipher implementation
│   ├── poly1305.c              # MAC implementation
│   └── chacha20_poly1305.c     # AEAD implementation
└── Makefile                    # Build automation
```

## Build and Test

The project includes an automated test suite validating the implementations against official RFC 8439 test vectors.

```bash
# Compile the project
make

# Run the test suite
make test

# Clean build artifacts
make clean
```

## Usage Example

### AEAD Encryption

```c
#include "chacha20_poly1305.h"

uint8_t key[32] = { /* ... 256-bit key ... */ };
uint8_t iv[8] = { /* ... 64-bit IV ... */ };
uint8_t constant[4] = { /* ... 32-bit constant ... */ };
uint8_t pt[] = "Secret Message";
uint8_t aad[] = "Public Header Data";

uint8_t ct[sizeof(pt)];
uint8_t tag[16];

// Encrypt plaintext and generate authentication tag
chacha20_poly1305_encrypt(
    key, iv, constant, 
    pt, sizeof(pt), 
    aad, sizeof(aad), 
    ct, tag
);
```

### AEAD Decryption

```c
#include "chacha20_poly1305.h"

uint8_t decrypted[sizeof(ct)];

// Decrypt ciphertext and verify authentication tag
int result = chacha20_poly1305_decrypt(
    key, iv, constant, 
    ct, sizeof(ct), 
    aad, sizeof(aad), 
    tag, decrypted
);

if (result == 0) {
    // Decryption successful and message is authentic
} else {
    // Forgery detected or invalid tag (do not trust the output)
}
```