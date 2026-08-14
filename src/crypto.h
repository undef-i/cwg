#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HASH_LEN 32U
#define TAG_LEN 16U
#define NONCE_LEN 12U

void hash (uint8_t out[HASH_LEN], const void *in, size_t len);
void hash2 (uint8_t out[HASH_LEN], const void *a, size_t alen, const void *b,
            size_t blen);
void mac (uint8_t out[HASH_LEN], const uint8_t key[HASH_LEN], size_t key_len,
          const void *in, size_t len);
void kdf1 (uint8_t t0[HASH_LEN], const uint8_t key[HASH_LEN], size_t key_len,
           const void *in, size_t len);
void kdf2 (uint8_t t0[HASH_LEN], uint8_t t1[HASH_LEN],
           const uint8_t key[HASH_LEN], size_t key_len, const void *in,
           size_t len);
void kdf3 (uint8_t t0[HASH_LEN], uint8_t t1[HASH_LEN], uint8_t t2[HASH_LEN],
           const uint8_t key[HASH_LEN], size_t key_len, const void *in,
           size_t len);
bool dh (uint8_t out[32], const uint8_t sk[32], const uint8_t pk[32]);
bool aead_enc (uint8_t *ct, size_t *ct_len, const uint8_t *pt, size_t pt_len,
               const void *ad, size_t ad_len, uint64_t nonce,
               const uint8_t key[32]);
bool aead_dec (uint8_t *pt, size_t *pt_len, const uint8_t *ct, size_t ct_len,
               const void *ad, size_t ad_len, uint64_t nonce,
               const uint8_t key[32]);
