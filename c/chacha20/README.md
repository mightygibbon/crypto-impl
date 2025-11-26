# ChaCha20

This directory contains a C implementation of the ChaCha20 stream cipher, fully compliant with [RFC 8439](https://datatracker.ietf.org/doc/html/\rfc8439/). The implementation has eben verified against the test vector from the section [2.4.2](https://datatracker.ietf.org/doc/html/rfc7539#section-2.4.2) of the same RFC:

- Key: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- Nonce: `000000000000004a00000000`
- Counter: `01000000`
- Plaintext: `"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."`
