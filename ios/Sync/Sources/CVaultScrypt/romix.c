// scrypt's ROMix, BlockMix and Salsa20/8 core, written from RFC 7914.
// Debug builds compile Swift at -Onone, which makes a Swift ROMix far too slow
// for a 128 MiB derivation; this C stays usable even unoptimised.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "CVaultScrypt.h"

#define SALSA_WORDS 16

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

// Salsa20/8 core (RFC 7914, section 3), in place.
static void salsa20_8(uint32_t b[SALSA_WORDS]) {
    uint32_t x0 = b[0], x1 = b[1], x2 = b[2], x3 = b[3], x4 = b[4], x5 = b[5], x6 = b[6], x7 = b[7];
    uint32_t x8 = b[8], x9 = b[9], x10 = b[10], x11 = b[11], x12 = b[12], x13 = b[13], x14 = b[14];
    uint32_t x15 = b[15];
    for (int i = 0; i < 8; i += 2) {
        // Columns
        x4 ^= R(x0 + x12, 7);
        x8 ^= R(x4 + x0, 9);
        x12 ^= R(x8 + x4, 13);
        x0 ^= R(x12 + x8, 18);
        x9 ^= R(x5 + x1, 7);
        x13 ^= R(x9 + x5, 9);
        x1 ^= R(x13 + x9, 13);
        x5 ^= R(x1 + x13, 18);
        x14 ^= R(x10 + x6, 7);
        x2 ^= R(x14 + x10, 9);
        x6 ^= R(x2 + x14, 13);
        x10 ^= R(x6 + x2, 18);
        x3 ^= R(x15 + x11, 7);
        x7 ^= R(x3 + x15, 9);
        x11 ^= R(x7 + x3, 13);
        x15 ^= R(x11 + x7, 18);
        // Rows
        x1 ^= R(x0 + x3, 7);
        x2 ^= R(x1 + x0, 9);
        x3 ^= R(x2 + x1, 13);
        x0 ^= R(x3 + x2, 18);
        x6 ^= R(x5 + x4, 7);
        x7 ^= R(x6 + x5, 9);
        x4 ^= R(x7 + x6, 13);
        x5 ^= R(x4 + x7, 18);
        x11 ^= R(x10 + x9, 7);
        x8 ^= R(x11 + x10, 9);
        x9 ^= R(x8 + x11, 13);
        x10 ^= R(x9 + x8, 18);
        x12 ^= R(x15 + x14, 7);
        x13 ^= R(x12 + x15, 9);
        x14 ^= R(x13 + x12, 13);
        x15 ^= R(x14 + x13, 18);
    }
    b[0] += x0;
    b[1] += x1;
    b[2] += x2;
    b[3] += x3;
    b[4] += x4;
    b[5] += x5;
    b[6] += x6;
    b[7] += x7;
    b[8] += x8;
    b[9] += x9;
    b[10] += x10;
    b[11] += x11;
    b[12] += x12;
    b[13] += x13;
    b[14] += x14;
    b[15] += x15;
}

#undef R

// scryptBlockMix (RFC 7914, section 4). `in` holds 2r Salsa blocks; `out`
// receives the even-numbered results, then the odd-numbered ones.
static void block_mix(const uint32_t *in, uint32_t *out, size_t r) {
    uint32_t x[SALSA_WORDS];
    memcpy(x, &in[(2 * r - 1) * SALSA_WORDS], sizeof(x));
    for (size_t i = 0; i < 2 * r; i++) {
        const uint32_t *chunk = &in[i * SALSA_WORDS];
        for (int k = 0; k < SALSA_WORDS; k++) x[k] ^= chunk[k];
        salsa20_8(x);
        size_t target = i / 2 + (i % 2 ? r : 0);
        memcpy(&out[target * SALSA_WORDS], x, sizeof(x));
    }
}

// Integerify (RFC 7914, section 5): the last Salsa block's first two words,
// little-endian. n is at most 2^64, so these 64 bits are enough.
static uint64_t integerify(const uint32_t *x, size_t r) {
    const uint32_t *last = &x[(2 * r - 1) * SALSA_WORDS];
    return ((uint64_t)last[1] << 32) | last[0];
}

// memset, then a barrier telling the compiler the memory may still be read,
// so the clearing survives optimisation before free (as BoringSSL's
// OPENSSL_cleanse does).
static void wipe(void *p, size_t length) {
    memset(p, 0, length);
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

int vault_scrypt_romix(uint8_t *block, uint32_t r, uint64_t n) {
    if (block == NULL || r == 0 || n < 2 || (n & (n - 1)) != 0) return -1;
    const size_t rows = (size_t)r;
    if (rows > SIZE_MAX / 32) return -1;
    const size_t words = 32 * rows;
    if (n > SIZE_MAX / sizeof(uint32_t) / words) return -1;
    const size_t block_bytes = words * sizeof(uint32_t);
    const size_t count = (size_t)n;
    uint32_t *v = malloc(count * block_bytes);
    uint32_t *x = malloc(block_bytes);
    uint32_t *y = malloc(block_bytes);
    if (v == NULL || x == NULL || y == NULL) {
        free(v);
        free(x);
        free(y);
        return -2;
    }

    for (size_t k = 0; k < words; k++) x[k] = load32(&block[4 * k]);
    // Two steps per pass, alternating buffers, so no block is copied back.
    for (size_t i = 0; i < count; i += 2) {
        memcpy(&v[i * words], x, block_bytes);
        block_mix(x, y, rows);
        memcpy(&v[(i + 1) * words], y, block_bytes);
        block_mix(y, x, rows);
    }
    for (size_t i = 0; i < count; i += 2) {
        const uint32_t *vj = &v[(size_t)(integerify(x, rows) & (n - 1)) * words];
        for (size_t k = 0; k < words; k++) x[k] ^= vj[k];
        block_mix(x, y, rows);
        vj = &v[(size_t)(integerify(y, rows) & (n - 1)) * words];
        for (size_t k = 0; k < words; k++) y[k] ^= vj[k];
        block_mix(y, x, rows);
    }
    for (size_t k = 0; k < words; k++) store32(&block[4 * k], x[k]);

    wipe(v, count * block_bytes);
    wipe(x, block_bytes);
    wipe(y, block_bytes);
    free(v);
    free(x);
    free(y);
    return 0;
}
