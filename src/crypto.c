#include "crypto.h"

#include "blake2.h"

#include <sodium.h>
#include <string.h>

void
hash (uint8_t out[HASH_LEN], const void *in, size_t len)
{
  blake2s (out, HASH_LEN, in, len, NULL, 0);
}

void
hash2 (uint8_t out[HASH_LEN], const void *a, size_t alen, const void *b,
       size_t blen)
{
  blake2s_state s;
  blake2s_init (&s, HASH_LEN);
  blake2s_update (&s, a, alen);
  blake2s_update (&s, b, blen);
  blake2s_final (&s, out, HASH_LEN);
}

void
mac (uint8_t out[HASH_LEN], const uint8_t key[HASH_LEN], size_t key_len,
     const void *in, size_t len)
{
  uint8_t ipad[64], opad[64], inner[HASH_LEN], k[64];
  blake2s_state s;
  memset (ipad, 0x36, sizeof (ipad));
  memset (opad, 0x5c, sizeof (opad));
  if (key_len > sizeof (k))
    {
      hash (k, key, key_len);
      key_len = HASH_LEN;
    }
  else
    {
      memcpy (k, key, key_len);
      memset (k + key_len, 0, sizeof (k) - key_len);
    }
  for (size_t i = 0; i < sizeof (k); i++)
    {
      ipad[i] ^= k[i];
      opad[i] ^= k[i];
    }
  blake2s_init (&s, HASH_LEN);
  blake2s_update (&s, ipad, sizeof (ipad));
  blake2s_update (&s, in, len);
  blake2s_final (&s, inner, sizeof (inner));
  blake2s_init (&s, HASH_LEN);
  blake2s_update (&s, opad, sizeof (opad));
  blake2s_update (&s, inner, sizeof (inner));
  blake2s_final (&s, out, HASH_LEN);
  sodium_memzero (ipad, sizeof (ipad));
  sodium_memzero (opad, sizeof (opad));
  sodium_memzero (inner, sizeof (inner));
  sodium_memzero (k, sizeof (k));
}

static void
mac2 (uint8_t out[HASH_LEN], const uint8_t key[HASH_LEN], size_t key_len,
      const void *a, size_t alen, uint8_t last)
{
  uint8_t buf[HASH_LEN + 1];
  memcpy (buf, a, alen);
  buf[alen] = last;
  mac (out, key, key_len, buf, alen + 1U);
  sodium_memzero (buf, sizeof (buf));
}

void
kdf1 (uint8_t t0[HASH_LEN], const uint8_t key[HASH_LEN], size_t key_len,
      const void *in, size_t len)
{
  uint8_t prk[HASH_LEN], one = 1;
  mac (prk, key, key_len, in, len);
  mac (t0, prk, sizeof (prk), &one, 1);
  sodium_memzero (prk, sizeof (prk));
}

void
kdf2 (uint8_t t0[HASH_LEN], uint8_t t1[HASH_LEN], const uint8_t key[HASH_LEN],
      size_t key_len, const void *in, size_t len)
{
  uint8_t prk[HASH_LEN], one = 1;
  mac (prk, key, key_len, in, len);
  mac (t0, prk, sizeof (prk), &one, 1);
  mac2 (t1, prk, sizeof (prk), t0, HASH_LEN, 2);
  sodium_memzero (prk, sizeof (prk));
}

void
kdf3 (uint8_t t0[HASH_LEN], uint8_t t1[HASH_LEN], uint8_t t2[HASH_LEN],
      const uint8_t key[HASH_LEN], size_t key_len, const void *in, size_t len)
{
  uint8_t prk[HASH_LEN], one = 1;
  mac (prk, key, key_len, in, len);
  mac (t0, prk, sizeof (prk), &one, 1);
  mac2 (t1, prk, sizeof (prk), t0, HASH_LEN, 2);
  mac2 (t2, prk, sizeof (prk), t1, HASH_LEN, 3);
  sodium_memzero (prk, sizeof (prk));
}

bool
dh (uint8_t out[32], const uint8_t sk[32], const uint8_t pk[32])
{
  return crypto_scalarmult_curve25519 (out, sk, pk) == 0
         && !sodium_is_zero (out, 32);
}
