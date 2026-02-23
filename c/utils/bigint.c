#include "bigint.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Converts a hex character to its integer value. */
static int hex_char_to_int(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bigint_t bigint_alloc(int8_t sign, size_t byte_length)
{
    bigint_t bignum;

    bignum.sign = sign;
    /* Ceiling division. */
    bignum.size = (byte_length + 3) / 4;

    if (bignum.size > 0) {
        /* Aall limbs are initialized to zero to prevent undefined behaviors. */
        bignum.limbs = calloc(bignum.size, sizeof(uint32_t));
        if (bignum.limbs == NULL) {
            bignum.size = 0;
        }
    } else {
        bignum.limbs = NULL;
    }

    return bignum;
}

void bigint_free(bigint_t *bignum)
{
    /* Check for NULL pointers to safely allow double-frees or freeing 
     * uninitialized structs. */
    if (bignum && bignum->limbs) {
        free(bignum->limbs);
        bignum->limbs = NULL;
        bignum->size = 0;
    }
}

bigint_t bigint_from_be_bytes(int8_t sign, size_t num_bytes, const uint8_t *bytes)
{
    bigint_t bignum = bigint_alloc(sign, num_bytes);
    
    if ((bignum.limbs == NULL) && (bignum.size > 0)) {
        return bignum;
    }

    size_t limb_index = 0;
    int bit_shift = 0;

    /* Big-Endian arrays have the least significant byte at the highest index.
     * Backward iteration to populate the Little-Endian internal limbs starting
     * from index 0. */
    for (int i = num_bytes - 1; i >= 0; i--) {
        bignum.limbs[limb_index] |= ((uint32_t)bytes[i] << bit_shift);
        
        bit_shift += 8;
        if (bit_shift == 32) {
            bit_shift = 0;
            limb_index++;
        }
    }

    return bignum;
}

bigint_t bigint_from_le_bytes(int8_t sign, size_t num_bytes, const uint8_t *bytes)
{
    bigint_t bignum = bigint_alloc(sign, num_bytes);

    if ((bignum.limbs == NULL) && (bignum.size > 0)) {
        return bignum;
    }

    size_t limb_index = 0;
    int bit_shift = 0;

    /* Little-Endian arrays have the least significant byte at index 0.
     * Forward iteration, mapping directly to the Little-Endian limbs. */
    for (size_t i = 0; i < num_bytes; i++) {
        bignum.limbs[limb_index] |= ((uint32_t)bytes[i] << bit_shift);
        bit_shift += 8;
        
        if (bit_shift == 32) {
            bit_shift = 0;
            limb_index++;
        }
    }

    return bignum;
}

bigint_t bigint_from_be_hex(int8_t sign, const char *hex)
{
    if (!hex) {
        return bigint_alloc(0, 0);
    }

    size_t hex_len = strlen(hex);
    size_t byte_len = (hex_len + 1) / 2;

    bigint_t bignum = bigint_alloc(sign, byte_len);
    if ((bignum.limbs == NULL) && (bignum.size > 0)) {
        return bignum;
    }

    size_t limb_index = 0;
    int bit_shift = 0;

    /* The hex string is read from right to left */
    for (int i = (int)hex_len; i > 0; i -= 2) {
        int low_nibble = hex_char_to_int(hex[i - 1]);
        int high_nibble = (i - 1 > 0) ? hex_char_to_int(hex[i - 2]) : 0;

        if (low_nibble < 0 || high_nibble < 0) {
            bigint_free(&bignum);
            return bigint_alloc(0, 0);
        }

        uint8_t byte_val = (uint8_t)((high_nibble << 4) | low_nibble);

        bignum.limbs[limb_index] |= ((uint32_t)byte_val << bit_shift);
        
        bit_shift += 8;
        if (bit_shift == 32) {
            bit_shift = 0;
            limb_index++;
        }
    }

    return bignum;
}

bigint_t bigint_from_le_hex(int8_t sign, const char *hex)
{
    if (!hex) {
        return bigint_alloc(0, 0);
    }

    size_t hex_len = strlen(hex);
    size_t byte_len = (hex_len + 1) / 2;

    bigint_t bignum = bigint_alloc(sign, byte_len);
    if ((bignum.limbs == NULL) && (bignum.size > 0)) {
        return bignum;
    }

    size_t limb_index = 0;
    int bit_shift = 0;

    /* The hex string is read from right to left */
    for (size_t i = 0; i < hex_len; i += 2) {
        int low_nibble = (i + 1 < hex_len) ? hex_char_to_int(hex[i + 1]) : 0;
        int high_nibble = hex_char_to_int(hex[i]);

        if (low_nibble < 0 || high_nibble < 0) {
            bigint_free(&bignum);
            return bigint_alloc(0, 0);
        }

        uint8_t byte_val = (uint8_t)((high_nibble << 4) | low_nibble);

        bignum.limbs[limb_index] |= ((uint32_t)byte_val << bit_shift);
        
        bit_shift += 8;
        if (bit_shift == 32) {
            bit_shift = 0;
            limb_index++;
        }
    }

    return bignum;
}

bigint_t bigint_from_dec(const char *dec) {
    if (dec == NULL || *dec == '\0') {
        return bigint_alloc(0, 0);
    }

    /* Sign handling. */
    int8_t sign = 1;
    if (*dec == '-') {
        sign = -1;
        dec++;
    } else if (*dec == '+') {
        sign = 1;
        dec++;
    }

    /* Check if the string was just "+" or "-". */
    if (*dec == '\0') {
        return bigint_alloc(0, 0);
    }

    size_t dec_len = strlen(dec);
    /* A limb contains up to 9 decimal digits, since 2^32 = 4294967296. */
    size_t max_limbs = (dec_len / 9) + 2;

    bigint_t bignum;
    bignum.sign = sign;
    bignum.size = 0;
    bignum.limbs = calloc(max_limbs, sizeof(uint32_t));

    if (bignum.limbs == NULL) {
        bignum.size = 0;
        return bignum;
    }

    /* Process digits */
    for (size_t i = 0; i < dec_len; i++) {
        /* Abort if char is invalid. */
        if (dec[i] < '0' || dec[i] > '9') {
            free(bignum.limbs);
            return bigint_alloc(0, 0);
        }

        uint64_t carry = dec[i] - '0';

        /* Multiple the current accumulated value by 10 and add the new digit. */
        for (size_t j = 0; j < bignum.size; j++) {
            uint64_t res = (uint64_t)bignum.limbs[j] * 10 + carry;
            bignum.limbs[j] = (uint32_t)res;
            carry = res >> 32;
        }

        /* If an overflow of the current limb size occurred, expand bignum. */
        if (carry > 0) {
            bignum.limbs[bignum.size] = (uint32_t)carry;
            bignum.size++;
        }
    }

    /* Handle the edge case where the string was "0" or "-000" */
    if (bignum.size == 0) {
        free(bignum.limbs);
        return bigint_alloc(0, 0);
    } 

    /* Shrink the allocated array to free unused memory */
    if (bignum.size < max_limbs) {
        uint32_t *shrunk = realloc(bignum.limbs, bignum.size * sizeof(uint32_t));
        if (shrunk) {
            bignum.limbs = shrunk;
        }
    }

    return bignum;
}

void bigint_to_be_bytes(const bigint_t *a, uint8_t *out, size_t out_len)
{
    if (!out) {
        return;
    }

    for (size_t i = 0; i < out_len; i++) {
        size_t limb_idx = i / 4;
        size_t bit_shift = (i % 4) * 8;
        size_t byte_idx = out_len - 1 - i;

        if (a != NULL && limb_idx < a->size) {
            out[byte_idx] = (uint8_t)((a->limbs[limb_idx] >> bit_shift) & 0xFF);
        } else {
            out[byte_idx] = 0x00; /* Zero-pad if out_len exceeds a byte length. */
        }
    }
}

void bigint_to_le_bytes(const bigint_t *a, uint8_t *out, size_t out_len)
{
    if (!out) {
        return;
    }

    for (size_t i = 0; i < out_len; i++) {
        size_t limb_idx = i / 4;
        size_t bit_shift = (i % 4) * 8;

        if (a != NULL && limb_idx < a->size) {
            out[i] = (uint8_t)((a->limbs[limb_idx] >> bit_shift) & 0xFF);
        } else {
            out[i] = 0x00; /* Zero-pad if out_len exceeds a byte length. */
        }
    }
}

int bigint_copy(bigint_t *dest, const bigint_t *src) 
{
    /* If the source is zero, just allocate a zeroed destination and return. */
    if (src->size == 0 || src->sign == 0) {
        bigint_free(dest);
        *dest = bigint_alloc(0, 0);
        return 0;
    }

    bigint_t temp = bigint_alloc(src->sign, src->size * sizeof(uint32_t));
    if ((temp.limbs == NULL) && (temp.size > 0)) {
        return 1;
    }

    /* Perform limb-by-limb memory copy. */
    for (size_t i = 0; i < src->size; i++) {
        temp.limbs[i] = src->limbs[i];
    }

    bigint_free(dest);
    *dest = temp;

    return 0;
}

size_t bigint_size_bytes(const bigint_t *a)
{
    if (a == NULL || a->size == 0 || a->sign == 0) {
        return 0;
    }

    size_t bytes = (a->size - 1) * 4;

    uint32_t msl = a->limbs[a->size - 1];
    if (msl >= 0x01000000) {
        bytes += 4;
    } else if (msl >= 0x00010000) {
        bytes += 3;
    } else if (msl >= 0x00000100) {
        bytes += 2;
    } else {
        bytes += 1;
    }

    return bytes;
}

int bigint_cmp_abs(const bigint_t *a, const bigint_t *b)
{
    /* A number with more limbs is inherently larger in absolute value */
    if (a->size > b->size) {
        return 1;
    }
    if (a->size < b->size) {
        return -1;
    }

    /* If sizes are equal, compare limb by limb starting from the most 
     * significant. */
    for (size_t i = a->size; i > 0; i--) {
        if (a->limbs[i - 1] > b->limbs[i - 1]) {
            return 1;
        }
        if (a->limbs[i - 1] < b->limbs[i - 1]) {
            return -1;
        }
    }

    return 0;
}

int bigint_add_abs(bigint_t *dest, const bigint_t *a, const bigint_t *b)
{
    size_t max_size = (a->size > b->size) ? a->size : b->size;
    
    /* Allocate space for the largest operand plus 1 extra limb to hold a
     * potential final carry. */
    bigint_t temp = bigint_alloc(1, (max_size + 1) * sizeof(uint32_t));
    if ((temp.limbs == NULL) && (temp.size > 0)) {
        return 1;
    }

    uint64_t carry = 0;
    for (size_t i = 0; i < max_size; i++) {
        uint64_t sum = carry;
        
        /* Safely add limbs if they exist. */
        sum += (i < a->size) ? a->limbs[i] : 0;
        sum += (i < b->size) ? b->limbs[i] : 0;
        
        /* Lower 32 bits represent the addition result for the current limb. */
        temp.limbs[i] = (uint32_t)sum;
        /* Upper 32 bits represent the carry for the next limb. */
        carry = sum >> 32;
    }

    temp.limbs[max_size] = (uint32_t)carry;
    
    /* Strip leading zeroes. */
    if (carry == 0) {
        temp.size--;
    }

    bigint_free(dest);
    *dest = temp;

    return 0;
}

int bigint_sub_abs(bigint_t *dest, const bigint_t *a, const bigint_t *b)
{
    /* The result can never be larger than the largest operand ('a') */
    bigint_t temp = bigint_alloc(1, a->size * sizeof(uint32_t));

    if ((temp.limbs == NULL) && (temp.size > 0)) {
        return 1;
    }

    uint32_t borrow = 0;
    for (size_t i = 0; i < a->size; i++) {
        uint32_t a_val = a->limbs[i];
        uint32_t b_val = (i < b->size) ? b->limbs[i] : 0;
        
        /* Perform subtraction inside a 64-bit integer. If a_val is smaller
         * than b_val + borrow, this will naturally underflow and wrap around. */
        uint64_t diff = (uint64_t)a_val - b_val - borrow;
        
        /* Store the lower 32 bits of the difference */
        temp.limbs[i] = (uint32_t)diff;
        
        /* If underflow occurred, the 32nd bit of diff will be 1, so it must be
         * considered as borrow. */
        borrow = (diff >> 32) & 1;
    }

    /* Strip leading zeroes. */
    while ((temp.size > 0) && (temp.limbs[temp.size - 1] == 0)) {
        temp.size--;
    }
    
    /* If the size shrunk to 0, the result is 0, so clear the sign. */
    if (temp.size == 0) {
        temp.sign = 0;
    }

    bigint_free(dest);
    *dest = temp;

    return 0;
}

int bigint_mul_abs(bigint_t *dest, const bigint_t *a, const bigint_t *b)
{
    /* Multiplication by 0 case. */
    if (a->sign == 0 || b->sign == 0) {
        bigint_free(dest);
        *dest = bigint_alloc(0, 0);
        return 0;
    }

    /* Result allocation. */
    size_t result_size = a->size + b->size;
    bigint_t temp = bigint_alloc(1, result_size * sizeof(uint32_t));
    if ((temp.limbs == NULL) && (temp.size > 0)) {
        return 1;
    }

    for (size_t i = 0; i < a->size; i++) {
        uint64_t carry = 0;

        for (size_t j = 0; j < b->size; j++) {
            uint64_t product = (uint64_t)a->limbs[i] * b->limbs[j] 
                               + temp.limbs[i + j] + carry;
            
            /* Save the lower 32 bits as result. */
            temp.limbs[i + j] = (uint32_t)product;

            /* Save the upper 32 bits as carry for the next position. */
            carry = product >> 32;
        }

        temp.limbs[i + b->size] = (uint32_t)carry;
    }

    /* Strip leading zeros. */
    while ((temp.size > 0) && (temp.limbs[temp.size - 1] == 0)) {
        temp.size--;
    }

    if (temp.size == 0) {
        temp.sign = 0;
    }

    bigint_free(dest);
    *dest = temp;

    return 0;
}

int bigint_add(bigint_t *dest, const bigint_t *a, const bigint_t *b)
{
    /* 0 + X = X case. */
    if (a->sign == 0) { 
        return bigint_copy(dest, b); 
    }
    /* X + 0 = X case. */
    if (b->sign == 0) { 
        return bigint_copy(dest, a); 
    }

    int ret;

    if (a->sign == b->sign) {
        /* If signs are identical, just add magnitudes and keep the sign. */
        ret = bigint_add_abs(dest, a, b);
        dest->sign = a->sign;
    } else {
        /* If signs differ, it's a subtraction, so the smaller absolute is
         * subtracted value from the larger. The larger magnitude will decide
         * the final sign. */
        if (bigint_cmp_abs(a, b) >= 0) {
            ret = bigint_sub_abs(dest, a, b);
            dest->sign = a->sign;
        } else {
            ret = bigint_sub_abs(dest, b, a);
            dest->sign = b->sign;
        }
        
        /* If magnitudes were equal, the sign and result is 0. */
        if (dest->size == 0) {
            dest->sign = 0;
        }
    }

    return ret;
}

int bigint_sub(bigint_t *dest, const bigint_t *a, const bigint_t *b) {
    /* X - 0 = X case. */
    if (b->sign == 0) {
        return bigint_copy(dest, a);
    }
    /* 0 - X = -X case. The sign is set to the sign of b flipped. */
    if (a->sign == 0) {
        int ret = bigint_copy(dest, b);
        dest->sign = -(b->sign);
        return ret;
    }

    int ret;

    if (a->sign == b->sign) {
        /* If signs are the same, it resolves to a magnitude subtraction. If a
         * larger magnitude is subtracted, the operands must be swapped and the
         * result's sign flipped */
        if (bigint_cmp_abs(a, b) >= 0) {
            ret = bigint_sub_abs(dest, a, b);
            dest->sign = a->sign;
        } else {
            ret = bigint_sub_abs(dest, b, a);
            dest->sign = -a->sign;
        }
        
        /* If magnitudes were equal, the sign and result is 0. */
        if (dest->size == 0) {
            dest->sign = 0;
        }
    } else {
        /* If signs differ, it resolves to a magnitude addition. */
        ret = bigint_add_abs(dest, a, b);
        dest->sign = a->sign;
    }

    return ret;
}

int bigint_mul(bigint_t *dest, const bigint_t *a, const bigint_t *b)
{
    /* Multiplication by 0 case. */
    if (a->sign == 0 || b->sign == 0) {
        bigint_free(dest);
        *dest = bigint_alloc(0, 0);
        return 0;
    }

    int ret = bigint_mul_abs(dest, a, b);

    if (ret == 0 && dest->size > 0) {
        dest->sign = a->sign * b->sign;
    }

    return ret;
}

int bigint_div_mod(bigint_t *quotient, bigint_t *remainder,
                   const bigint_t *numerator, const bigint_t *denominator)
{
    /* Division by 0 error. */
    if (denominator->sign == 0 || denominator->size == 0) {
        return 1;
    }

    /* |numerator| < |denominator| case. */
    if (bigint_cmp_abs(numerator, denominator) < 0) {
        if (quotient) {
            bigint_free(quotient);
            *quotient = bigint_alloc(0, 0);
        }
        if (remainder) {
            return bigint_copy(remainder, numerator);
        }
        return 0;
    }

    bigint_t q = bigint_alloc(1, numerator->size * sizeof(uint32_t));
    bigint_t r = bigint_alloc(0, 0);
    if ((q.limbs == NULL) && (q.size > 0)) {
        return 1;
    }

    /* Find the number of bits in the numerator to know where to start dividing. */
    size_t total_bits = 0;
    if (numerator->size > 0) {
        total_bits = (numerator->size - 1) * 32;
        uint32_t msl = numerator->limbs[numerator->size - 1];
        while (msl > 0) {
            total_bits++;
            msl >>= 1;
        }
    }

    /* Binary division */
    for (size_t i = total_bits; i > 0; i--) {
        /* 1. Shift remainder left by 1. */
        if (r.sign != 0) {
            uint32_t carry = 0;
            for (size_t j = 0; j < r.size; j++) {
                uint32_t next_carry = r.limbs[j] >> 31;
                r.limbs[j] = (r.limbs[j] << 1) | carry;
                carry = next_carry;
            }

            /* If the left shift overflowed the current limb count, expand r. */
            if (carry > 0) {
                uint32_t *new_limbs = calloc(r.size + 1, sizeof(uint32_t));
                if (!new_limbs) {
                    bigint_free(&q);
                    bigint_free(&r);
                    return 1;
                }
                for (size_t j = 0; j < r.size; j++) {
                    new_limbs[j] = r.limbs[j];
                }
                new_limbs[r.size] = carry;
                free(r.limbs);
                r.limbs = new_limbs;
                r.size++;
            }
        }

        /* 2. Extract the (i-1)-th bit of the numerator. */
        size_t limb_idx = (i-1) / 32;
        size_t bit_idx = (i-1) % 32;
        uint32_t bit = (numerator->limbs[limb_idx] >> bit_idx) & 1;

        /* 3. Drop the bit into the LSB of the remainder. */
        if (bit) {
            if (r.size == 0 || r.sign == 0) {
                bigint_free(&r);
                r = bigint_alloc(1, sizeof(uint32_t));
                r.limbs[0] = 1;
            } else {
                r.limbs[0] |= 1;
            }
        }

        /* 4. remainder >= denominator, subtract and set the quotient bit to 1. */
        if (bigint_cmp_abs(&r, denominator) >= 0) {
            bigint_sub_abs(&r, &r, denominator);
            q.limbs[limb_idx] |= (1U << bit_idx);
        }
    }

    /* Strip leading zeros from quotient. */
    while (q.size > 0 && q.limbs[q.size - 1] == 0) {
        q.size--;
    }

    /* Assign signs based on standard C division rules. */
    if (q.size == 0) {
        q.sign = 0;
    } else {
        q.sign = numerator->sign * denominator->sign;
    }

    /* Modulo takes the sign of the numerator. */
    if (r.size > 0) {
        r.sign = numerator->sign;
    } else {
        r.sign = 0;
    }

    /* Assign back to user pointers or clean up if they passed NULL */
    if (quotient) {
        bigint_free(quotient);
        *quotient = q;
    } else {
        bigint_free(&q);
    }

    if (remainder) {
        bigint_free(remainder);
        *remainder = r;
    } else {
        bigint_free(&r);
    }

    return 0;
}

int bigint_div(bigint_t *dest, const bigint_t *a, const bigint_t *b)
{
    return bigint_div_mod(dest, NULL, a, b);
}

int bigint_mod(bigint_t *dest, const bigint_t *a, const bigint_t *b)
{
    return bigint_div_mod(NULL, dest, a, b);
}

int bigint_mod_crypto(bigint_t *dest, const bigint_t *a, const bigint_t *b)
{
    int ret = bigint_div_mod(NULL, dest, a, b);
    if (ret != 0) {
        return ret;
    }

    /* If the remainder is negative, add the positive denominator */
    if (dest->sign < 0) {
        bigint_t b_pos = bigint_alloc(0, 0);
        bigint_copy(&b_pos, b);
        b_pos.sign = 1;
        
        bigint_add(dest, dest, &b_pos);
        bigint_free(&b_pos);
    }

    return 0;
}