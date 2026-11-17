#ifndef CVAULTSCRYPT_H
#define CVAULTSCRYPT_H

#include <stdint.h>

/*
 * scrypt's ROMix (RFC 7914, section 5) over one 128 * r byte block, in place.
 * The caller runs PBKDF2-HMAC-SHA256 before and after, as scrypt specifies.
 * n must be a power of two greater than 1, and 128 * r * n bytes must be
 * allocatable. Returns 0 on success, -1 on invalid parameters and -2 when the
 * memory cannot be allocated; on failure the block is unchanged.
 */
int vault_scrypt_romix(uint8_t *block, uint32_t r, uint64_t n);

#endif
