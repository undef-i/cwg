#include "awg.h"

#include "wire.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const size_t msg_size[] = {
  sizeof (MsgInit), sizeof (MsgResp), sizeof (MsgCookie),
  sizeof (MsgData) + 16U,
};

static uint32_t
rand_u32 (void)
{
  uint32_t n;
  randombytes_buf (&n, sizeof (n));
  return n;
}

static uint32_t
range_pick (const AwgRange *r)
{
  uint64_t span = (uint64_t)r->hi - r->lo + 1U;
  return r->lo + (uint32_t)((uint64_t)rand_u32 () % span);
}

void
awg_init (Awg *a)
{
  memset (a, 0, sizeof (*a));
  for (unsigned i = 0; i < AWG_TYPE_N; i++)
    a->h[i].lo = a->h[i].hi = i + 1U;
}

int
awg_range_set (AwgRange *r, const char *value)
{
  char *end;
  unsigned long lo, hi;
  if (!value || !*value)
    return -EINVAL;
  errno = 0;
  lo = strtoul (value, &end, 10);
  if (errno || end == value || lo > UINT32_MAX)
    return -EINVAL;
  hi = lo;
  if (*end == '-')
    {
      const char *s = end + 1;
      errno = 0;
      hi = strtoul (s, &end, 10);
      if (errno || end == s || hi > UINT32_MAX)
        return -EINVAL;
    }
  if (*end || hi < lo)
    return -EINVAL;
  r->lo = (uint32_t)lo;
  r->hi = (uint32_t)hi;
  return 0;
}

int
awg_hex_set (uint8_t *out, size_t *out_len, const char *value)
{
  static const char hex[] = "0123456789abcdef";
  size_t n;
  if (!value)
    return -EINVAL;
  n = strlen (value);
  if ((n & 1U) || n / 2U > 1024U)
    return -EINVAL;
  for (size_t i = 0; i < n / 2U; i++)
    {
      const char *hi = strchr (hex, tolower ((unsigned char)value[i * 2U]));
      const char *lo
          = strchr (hex, tolower ((unsigned char)value[i * 2U + 1U]));
      if (!hi || !lo)
        return -EINVAL;
      out[i] = (uint8_t)(((hi - hex) << 4) | (lo - hex));
    }
  *out_len = n / 2U;
  return 0;
}

int
awg_set (Awg *a, const char *key, const char *value)
{
  unsigned n;
  if (!strcmp (key, "h1") || !strcmp (key, "h2") || !strcmp (key, "h3")
      || !strcmp (key, "h4"))
    return awg_range_set (&a->h[key[1] - '1'], value);
  if (!strcmp (key, "s1") || !strcmp (key, "s2") || !strcmp (key, "s3")
      || !strcmp (key, "s4"))
    {
      char *end;
      unsigned long v;
      errno = 0;
      v = strtoul (value, &end, 10);
      n = key[1] - '1';
      if (errno || end == value || *end || v > AWG_PAD_MAX)
        return -EINVAL;
      a->s[n] = (uint32_t)v;
      return 0;
    }
  if (!strcmp (key, "jc") || !strcmp (key, "jmin") || !strcmp (key, "jmax"))
    {
      char *end;
      unsigned long v;
      errno = 0;
      v = strtoul (value, &end, 10);
      if (errno || end == value || *end || v > UINT32_MAX)
        return -EINVAL;
      if (!strcmp (key, "jc"))
        {
          if (v > AWG_JUNK_COUNT_MAX)
            return -EINVAL;
          a->jc = (uint32_t)v;
        }
      else if (!strcmp (key, "jmin"))
        {
          if (v > AWG_JUNK_MAX)
            return -EINVAL;
          a->jmin = (uint32_t)v;
        }
      else
        {
          if (v > AWG_JUNK_MAX)
            return -EINVAL;
          a->jmax = (uint32_t)v;
        }
      return 0;
    }
  if (!strcmp (key, "header_protection_key"))
    {
      size_t len;
      if (strlen (value) != KEY_LEN * 2U
          || awg_hex_set (a->hp_key, &len, value) < 0 || len != KEY_LEN)
        return -EINVAL;
      a->hp = sodium_is_zero (a->hp_key, sizeof (a->hp_key)) == 0;
      return 0;
    }
  if (!strcmp (key, "content_padding_addition"))
    {
      int rc = awg_range_set (&a->content_pad, value);
      return rc < 0 || a->content_pad.hi > AWG_PAD_MAX ? -EINVAL : 0;
    }
  if (key[0] == 'i' && key[1] >= '1' && key[1] <= '5' && !key[2])
    {
      uint8_t check[AWG_JUNK_MAX];
      size_t len;
      if (strlen (value) >= sizeof (a->i[0]))
        return -EINVAL;
      strcpy (a->i[key[1] - '1'], value);
      return awg_i_make (a, key[1] - '1', check, &len, sizeof (check));
    }
  return -ENOENT;
}

size_t
awg_content_pad (const Awg *a, size_t len, size_t mtu)
{
  size_t pad;
  if (a->content_pad.lo || a->content_pad.hi)
    {
      pad = range_pick (&a->content_pad);
      return mtu && len + pad > mtu ? mtu - len : pad;
    }
  return (16U - (len & 15U)) & 15U;
}

int
awg_validate (const Awg *a)
{
  for (unsigned i = 0; i < AWG_TYPE_N; i++)
    for (unsigned j = i + 1; j < AWG_TYPE_N; j++)
      if (a->h[i].lo <= a->h[j].hi && a->h[j].lo <= a->h[i].hi)
        return -EINVAL;
  if (a->jmin > a->jmax || a->jmax > AWG_JUNK_MAX
      || a->jc > AWG_JUNK_COUNT_MAX || (a->jc && !a->jmax))
    return -EINVAL;
  if (a->hp)
    for (unsigned i = 0; i < AWG_TYPE_N; i++)
      if (a->s[i] < 12U)
        return -EINVAL;
  return 0;
}

const char *
awg_range_get (const AwgRange *r, char buf[32])
{
  if (r->lo == r->hi)
    snprintf (buf, 32, "%u", r->lo);
  else
    snprintf (buf, 32, "%u-%u", r->lo, r->hi);
  return buf;
}

void
awg_type_set (const Awg *a, unsigned type, void *msg)
{
  uint32_t magic = htole32 (range_pick (&a->h[type]));
  memcpy (msg, &magic, sizeof (magic));
}

void
awg_type_normalize (void *msg, unsigned type)
{
  uint32_t magic = htole32 (type + 1U);
  memcpy (msg, &magic, sizeof (magic));
}

static void
protect (const Awg *a, uint8_t *buf, size_t len, const uint8_t *prefix)
{
  uint8_t nonce[12];
  if (!a->hp)
    return;
  memcpy (nonce, prefix, sizeof (nonce));
  crypto_stream_chacha20_ietf_xor (buf, buf, len, nonce, a->hp_key);
  sodium_memzero (nonce, sizeof (nonce));
}

int
awg_wrap (const Awg *a, unsigned type, uint8_t *buf, size_t *len, size_t cap)
{
  size_t old, pad;
  if (!a || !buf || !len || type >= AWG_TYPE_N || *len < 4U)
    return -EINVAL;
  pad = a->s[type];
  old = *len;
  if (old + pad > cap)
    return -EMSGSIZE;
  memmove (buf + pad, buf, old);
  randombytes_buf (buf, pad);
  protect (a, buf + pad, type == AWG_DATA ? 16U : old, buf);
  *len = old + pad;
  return 0;
}

int
awg_unwrap (const Awg *a, uint8_t *buf, size_t *len, unsigned *type)
{
  uint8_t mask[4] = { 0 };
  uint8_t nonce[12];
  uint32_t wire, mask32, got;
  size_t pad = 0;
  unsigned found = AWG_TYPE_N;
  if (!a || !buf || !len || !type || *len < 4U)
    return -EINVAL;
  for (unsigned i = 0; i < AWG_TYPE_N; i++)
    {
      size_t need = msg_size[i];
      if (i == AWG_DATA ? *len < a->s[i] + need : *len != a->s[i] + need)
        continue;
      memset (mask, 0, sizeof (mask));
      if (a->hp)
        {
          if (a->s[i] < sizeof (nonce))
            continue;
          memcpy (nonce, buf, sizeof (nonce));
          crypto_stream_chacha20_ietf_xor (mask, mask, sizeof (mask), nonce,
                                           a->hp_key);
        }
      memcpy (&wire, buf + a->s[i], sizeof (wire));
      memcpy (&mask32, mask, sizeof (mask32));
      got = le32toh (wire) ^ le32toh (mask32);
      if (a->h[i].lo <= got && got <= a->h[i].hi)
        {
          found = i;
          pad = a->s[i];
          break;
        }
    }
  if (found == AWG_TYPE_N)
    return -EPROTO;
  if (a->hp)
    {
      memcpy (nonce, buf, sizeof (nonce));
      crypto_stream_chacha20_ietf_xor (buf + pad, buf + pad,
                                       found == AWG_DATA ? 16U : msg_size[found],
                                       nonce, a->hp_key);
    }
  memmove (buf, buf + pad, *len - pad);
  /* Keep the AWG header for MAC validation; callers normalize after it. */
  *len -= pad;
  *type = found;
  return 0;
}

static int
arg_get (const char *s, unsigned *value)
{
  char *end;
  unsigned long n;
  errno = 0;
  n = strtoul (s, &end, 10);
  if (errno || end == s || *end || n > 1024U)
    return -EINVAL;
  *value = (unsigned)n;
  return 0;
}

int
awg_i_make (const Awg *a, unsigned index, uint8_t *out, size_t *len,
            size_t cap)
{
  const char *p;
  size_t used = 0;
  if (!a || !out || !len || index >= 5U)
    return -EINVAL;
  p = a->i[index];
  while (*p)
    {
      char tag[4] = { 0 }, arg[1025] = { 0 };
      const char *end;
      size_t n;
      unsigned count;
      while (*p && *p != '<')
        p++;
      if (!*p)
        break;
      end = strchr (++p, '>');
      if (!end || (n = (size_t)(end - p)) >= sizeof (arg))
        return -EINVAL;
      memcpy (arg, p, n);
      p = end + 1;
      if (sscanf (arg, "%3s", tag) != 1)
        return -EINVAL;
      char *v = arg + strlen (tag);
      while (*v == ' ')
        v++;
      if (!strcmp (tag, "b"))
        {
          size_t wrote;
          if (!strncmp (v, "0x", 2))
            v += 2;
          size_t chars = strlen (v);
          if ((chars & 1U) || used + chars / 2U > cap
              || awg_hex_set (out + used, &wrote, v) < 0)
            return -EINVAL;
          used += wrote;
        }
      else if (!strcmp (tag, "r") || !strcmp (tag, "rc")
               || !strcmp (tag, "rd"))
        {
          if (arg_get (v, &count) < 0 || used + count > cap)
            return -EINVAL;
          randombytes_buf (out + used, count);
          for (unsigned i = 0; i < count; i++)
            {
              if (!strcmp (tag, "rc"))
                out[used + i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    [out[used + i] % 52U];
              else if (!strcmp (tag, "rd"))
                out[used + i] = "0123456789"[out[used + i] % 10U];
            }
          used += count;
        }
      else if (!strcmp (tag, "t"))
        {
          uint32_t now = htonl ((uint32_t)time (NULL));
          if (used + sizeof (now) > cap)
            return -EMSGSIZE;
          memcpy (out + used, &now, sizeof (now));
          used += sizeof (now);
        }
      else if (!strcmp (tag, "dz"))
        {
          if (arg_get (v, &count) < 0 || used + count > cap)
            return -EINVAL;
          memset (out + used, 0, count);
          used += count;
        }
      else if (strcmp (tag, "d") && strcmp (tag, "ds"))
        return -EINVAL;
    }
  *len = used;
  return 0;
}
