#include "aead.h"

#include <sodium.h>
#include <string.h>

#if defined(__x86_64__) || defined(__aarch64__)

union seal_data
{
  struct
  {
    uint8_t key[32];
    uint32_t counter;
    uint8_t nonce[12];
    const uint8_t *extra_ciphertext;
    size_t extra_ciphertext_len;
  } in;
  struct
  {
    uint8_t tag[16];
  } out;
};

union open_data
{
  struct
  {
    uint8_t key[32];
    uint32_t counter;
    uint8_t nonce[12];
  } in;
  struct
  {
    uint8_t tag[16];
  } out;
};

#if defined(__x86_64__)
void chacha20_poly1305_seal_sse41 (uint8_t *out_ciphertext,
                                   const uint8_t *plaintext,
                                   size_t plaintext_len, const uint8_t *ad,
                                   size_t ad_len, union seal_data *data);
void chacha20_poly1305_seal_avx2 (uint8_t *out_ciphertext,
                                  const uint8_t *plaintext,
                                  size_t plaintext_len, const uint8_t *ad,
                                  size_t ad_len, union seal_data *data);
void chacha20_poly1305_open_sse41 (uint8_t *out_plaintext,
                                   const uint8_t *ciphertext,
                                   size_t plaintext_len, const uint8_t *ad,
                                   size_t ad_len, union open_data *data);
void chacha20_poly1305_open_avx2 (uint8_t *out_plaintext,
                                  const uint8_t *ciphertext,
                                  size_t plaintext_len, const uint8_t *ad,
                                  size_t ad_len, union open_data *data);
#else
void chacha20_poly1305_seal (uint8_t *out_ciphertext,
                             const uint8_t *plaintext, size_t plaintext_len,
                             const uint8_t *ad, size_t ad_len,
                             union seal_data *data);
void chacha20_poly1305_open (uint8_t *out_plaintext,
                             const uint8_t *ciphertext, size_t plaintext_len,
                             const uint8_t *ad, size_t ad_len,
                             union open_data *data);
#endif

static void
nonce_set (uint8_t out[12], uint64_t n)
{
  memset (out, 0, 12);
  for (size_t i = 0; i < sizeof (n); i++)
    out[4 + i] = (uint8_t)(n >> (i * 8U));
}

static void
seal_asm (uint8_t *ct, const uint8_t *pt, size_t pt_len, const uint8_t *ad,
          size_t ad_len, uint64_t nonce, const uint8_t key[32])
{
  union seal_data d;
  memset (&d, 0, sizeof (d));
  memcpy (d.in.key, key, 32);
  d.in.counter = 0;
  nonce_set (d.in.nonce, nonce);
  d.in.extra_ciphertext = NULL;
  d.in.extra_ciphertext_len = 0;
#if defined(__x86_64__)
  if (__builtin_cpu_supports ("avx2") && __builtin_cpu_supports ("bmi2"))
    chacha20_poly1305_seal_avx2 (ct, pt, pt_len, ad, ad_len, &d);
  else
    chacha20_poly1305_seal_sse41 (ct, pt, pt_len, ad, ad_len, &d);
#else
  chacha20_poly1305_seal (ct, pt, pt_len, ad, ad_len, &d);
#endif
  memcpy (ct + pt_len, d.out.tag, 16);
}

static bool
open_asm (uint8_t *pt, const uint8_t *ct, size_t ct_len, const uint8_t *ad,
          size_t ad_len, uint64_t nonce, const uint8_t key[32])
{
  union open_data d;
  uint8_t diff = 0;
  memset (&d, 0, sizeof (d));
  memcpy (d.in.key, key, 32);
  d.in.counter = 0;
  nonce_set (d.in.nonce, nonce);
#if defined(__x86_64__)
  if (__builtin_cpu_supports ("avx2") && __builtin_cpu_supports ("bmi2"))
    chacha20_poly1305_open_avx2 (pt, ct, ct_len - 16, ad, ad_len, &d);
  else
    chacha20_poly1305_open_sse41 (pt, ct, ct_len - 16, ad, ad_len, &d);
#else
  chacha20_poly1305_open (pt, ct, ct_len - 16, ad, ad_len, &d);
#endif
  for (size_t i = 0; i < 16; i++)
    diff |= d.out.tag[i] ^ ct[ct_len - 16 + i];
  return diff == 0;
}

static bool
asm_capable (void)
{
#if defined(__x86_64__)
  return __builtin_cpu_supports ("sse4.1");
#elif defined(__aarch64__)
  return true;
#else
  return false;
#endif
}

#endif

bool
aead_enc (uint8_t *ct, size_t *ct_len, const uint8_t *pt, size_t pt_len,
          const void *ad, size_t ad_len, uint64_t nonce, const uint8_t key[32])
{
#if defined(__x86_64__) || defined(__aarch64__)
  if (asm_capable ())
    {
      seal_asm (ct, pt, pt_len, ad, ad_len, nonce, key);
      *ct_len = pt_len + 16;
      return true;
    }
#endif
  unsigned long long n;
  uint8_t iv[12];
  nonce_set (iv, nonce);
  int rc = crypto_aead_chacha20poly1305_ietf_encrypt (ct, &n, pt, pt_len, ad,
                                                      ad_len, NULL, iv, key);
  *ct_len = (size_t)n;
  return rc == 0;
}

bool
aead_dec (uint8_t *pt, size_t *pt_len, const uint8_t *ct, size_t ct_len,
          const void *ad, size_t ad_len, uint64_t nonce, const uint8_t key[32])
{
#if defined(__x86_64__) || defined(__aarch64__)
  if (asm_capable ())
    {
      if (ct_len < 16)
        {
          *pt_len = 0;
          return false;
        }
      if (open_asm (pt, ct, ct_len, ad, ad_len, nonce, key))
        {
          *pt_len = ct_len - 16;
          return true;
        }
      *pt_len = 0;
      return false;
    }
#endif
  unsigned long long n;
  uint8_t iv[12];
  nonce_set (iv, nonce);
  int rc = crypto_aead_chacha20poly1305_ietf_decrypt (pt, &n, NULL, ct, ct_len,
                                                      ad, ad_len, iv, key);
  *pt_len = rc ? 0 : (size_t)n;
  return rc == 0;
}