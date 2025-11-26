#ifndef __UTILS__
#define __UTILS__

#include <stddef.h>
#include <stdint.h>

void hex_to_bytes(const char * hex, uint8_t * out, size_t out_len);
void print_usage(const char * prog);

#endif

