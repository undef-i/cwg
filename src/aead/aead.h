#ifndef CWG_AEAD_H
#define CWG_AEAD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool aead_enc (uint8_t *ct, size_t *ct_len, const uint8_t *pt, size_t pt_len,
               const void *ad, size_t ad_len, uint64_t nonce,
               const uint8_t key[32]);
bool aead_dec (uint8_t *pt, size_t *pt_len, const uint8_t *ct, size_t ct_len,
               const void *ad, size_t ad_len, uint64_t nonce,
               const uint8_t key[32]);

#endif