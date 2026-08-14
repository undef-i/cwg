#include "noise.h"

#include <endian.h>
#include <sodium.h>
#include <string.h>
#include <time.h>

static const char proto[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char ident[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";

static void
mix_hash (uint8_t h[32], const void *in, size_t len)
{
  hash2 (h, h, 32, in, len);
}

static void
mix_key (uint8_t ck[32], const void *in, size_t len)
{
  kdf1 (ck, ck, 32, in, len);
}

static void
start (Noise *n, const uint8_t rpk[32])
{
  hash (n->ck, proto, sizeof (proto) - 1U);
  hash2 (n->h, n->ck, 32, ident, sizeof (ident) - 1U);
  mix_hash (n->h, rpk, 32);
}

void
tai64n_stamp (uint8_t out[12], uint64_t sec, uint32_t ns)
{
  sec = htobe64 (0x400000000000000aULL + sec);
  ns = htobe32 (ns & ~UINT32_C (0x00ffffff));
  memcpy (out, &sec, 8);
  memcpy (out + 8, &ns, 4);
}

static void
tai (uint8_t out[12])
{
  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  tai64n_stamp (out, (uint64_t)ts.tv_sec, (uint32_t)ts.tv_nsec);
}

static bool
enc (uint8_t *out, const uint8_t *in, size_t len, uint8_t key[32],
     uint8_t h[32])
{
  size_t n;
  if (!aead_enc (out, &n, in, len, h, 32, 0, key) || n != len + 16U)
    return false;
  mix_hash (h, out, n);
  return true;
}

static bool
dec (uint8_t *out, const uint8_t *in, size_t len, uint8_t key[32],
     uint8_t h[32])
{
  size_t n;
  if (!aead_dec (out, &n, in, len, h, 32, 0, key) || n + 16U != len)
    return false;
  mix_hash (h, in, len);
  return true;
}

bool
noise_init (Noise *n, const uint8_t sk[32], const uint8_t rpk[32],
            const uint8_t psk[32])
{
  memset (n, 0, sizeof (*n));
  memcpy (n->sk, sk, 32);
  memcpy (n->rpk, rpk, 32);
  memcpy (n->psk, psk, 32);
  return crypto_scalarmult_curve25519_base (n->pk, n->sk) == 0;
}

bool
noise_init_make (Noise *n, MsgInit *m, uint32_t idx)
{
  uint8_t epk[32], ss[32], key[32], ts[12];
  memset (m, 0, sizeof (*m));
  m->type = htole32 (MSG_INIT);
  m->sender = htole32 (idx);
  start (n, n->rpk);
  randombytes_buf (n->e, sizeof (n->e));
  crypto_scalarmult_curve25519_base (epk, n->e);
  memcpy (m->eph, epk, 32);
  mix_key (n->ck, epk, 32);
  mix_hash (n->h, epk, 32);
  if (!dh (ss, n->e, n->rpk))
    return false;
  kdf2 (n->ck, key, n->ck, 32, ss, 32);
  if (!enc (m->stat, n->pk, 32, key, n->h))
    return false;
  if (!dh (ss, n->sk, n->rpk))
    return false;
  kdf2 (n->ck, key, n->ck, 32, ss, 32);
  tai (ts);
  if (!enc (m->time, ts, sizeof (ts), key, n->h))
    return false;
  n->li = idx;
  n->state = NS_INIT_MADE;
  sodium_memzero (ss, sizeof (ss));
  sodium_memzero (key, sizeof (key));
  return true;
}

bool
noise_init_get (Noise *n, const MsgInit *m)
{
  uint8_t ck[32], h[32], ss[32], key[32], pk[32], ts[12];
  if (le32toh (m->type) != MSG_INIT)
    return false;
  start (n, n->pk);
  memcpy (ck, n->ck, 32);
  memcpy (h, n->h, 32);
  mix_key (ck, m->eph, 32);
  mix_hash (h, m->eph, 32);
  if (!dh (ss, n->sk, m->eph))
    return false;
  kdf2 (ck, key, ck, 32, ss, 32);
  if (!dec (pk, m->stat, sizeof (m->stat), key, h)
      || sodium_memcmp (pk, n->rpk, 32))
    return false;
  if (!dh (ss, n->sk, n->rpk))
    return false;
  kdf2 (ck, key, ck, 32, ss, 32);
  if (!dec (ts, m->time, sizeof (m->time), key, h)
      || memcmp (ts, n->last, sizeof (ts)) <= 0)
    return false;
  memcpy (n->last, ts, sizeof (ts));
  memcpy (n->ck, ck, 32);
  memcpy (n->h, h, 32);
  memcpy (n->re, m->eph, 32);
  n->ri = le32toh (m->sender);
  n->state = NS_INIT_GOT;
  sodium_memzero (ss, sizeof (ss));
  sodium_memzero (key, sizeof (key));
  return true;
}

bool
noise_resp_make (Noise *n, MsgResp *m, uint32_t idx)
{
  uint8_t epk[32], ss[32], tau[32], key[32];
  size_t z;
  if (n->state != NS_INIT_GOT)
    return false;
  memset (m, 0, sizeof (*m));
  m->type = htole32 (MSG_RESP);
  m->sender = htole32 (idx);
  m->recv = htole32 (n->ri);
  randombytes_buf (n->e, sizeof (n->e));
  crypto_scalarmult_curve25519_base (epk, n->e);
  memcpy (m->eph, epk, 32);
  mix_hash (n->h, epk, 32);
  mix_key (n->ck, epk, 32);
  if (!dh (ss, n->e, n->re))
    return false;
  mix_key (n->ck, ss, 32);
  if (!dh (ss, n->e, n->rpk))
    return false;
  mix_key (n->ck, ss, 32);
  kdf3 (n->ck, tau, key, n->ck, 32, n->psk, 32);
  mix_hash (n->h, tau, 32);
  if (!aead_enc (m->empty, &z, NULL, 0, n->h, 32, 0, key) || z != 16)
    return false;
  mix_hash (n->h, m->empty, 16);
  n->li = idx;
  n->state = NS_RESP_MADE;
  return true;
}

bool
noise_resp_get (Noise *n, const MsgResp *m)
{
  uint8_t ck[32], h[32], ss[32], tau[32], key[32], empty[1];
  size_t z;
  if (n->state != NS_INIT_MADE || le32toh (m->type) != MSG_RESP
      || le32toh (m->recv) != n->li)
    return false;
  memcpy (ck, n->ck, 32);
  memcpy (h, n->h, 32);
  mix_hash (h, m->eph, 32);
  mix_key (ck, m->eph, 32);
  if (!dh (ss, n->e, m->eph))
    return false;
  mix_key (ck, ss, 32);
  if (!dh (ss, n->sk, m->eph))
    return false;
  mix_key (ck, ss, 32);
  kdf3 (ck, tau, key, ck, 32, n->psk, 32);
  mix_hash (h, tau, 32);
  if (!aead_dec (empty, &z, m->empty, 16, h, 32, 0, key) || z)
    return false;
  mix_hash (h, m->empty, 16);
  memcpy (n->ck, ck, 32);
  memcpy (n->h, h, 32);
  memcpy (n->re, m->eph, 32);
  n->ri = le32toh (m->sender);
  n->state = NS_RESP_GOT;
  return true;
}

bool
noise_keys (Noise *n, uint8_t tx[32], uint8_t rx[32])
{
  uint8_t a[32], b[32];
  if (n->state != NS_RESP_MADE && n->state != NS_RESP_GOT)
    return false;
  kdf2 (a, b, n->ck, 32, NULL, 0);
  if (n->state == NS_RESP_GOT)
    {
      memcpy (tx, a, 32);
      memcpy (rx, b, 32);
    }
  else
    {
      memcpy (rx, a, 32);
      memcpy (tx, b, 32);
    }
  sodium_memzero (n->e, sizeof (n->e));
  sodium_memzero (n->ck, sizeof (n->ck));
  sodium_memzero (n->h, sizeof (n->h));
  n->state = NS_ZERO;
  return true;
}
