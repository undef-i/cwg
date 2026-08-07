#include "utils.h"

#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>

static int
hex_v (char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

void
key_hex (char out[HEX_LEN + 1], const uint8_t key[KEY_LEN])
{
  static const char h[] = "0123456789abcdef";
  for (size_t i = 0; i < KEY_LEN; i++)
    {
      out[i * 2] = h[key[i] >> 4];
      out[i * 2 + 1] = h[key[i] & 15];
    }
  out[HEX_LEN] = '\0';
}

bool
key_get (uint8_t out[KEY_LEN], const char *hex)
{
  if (!hex || strlen (hex) != HEX_LEN)
    return false;
  for (size_t i = 0; i < KEY_LEN; i++)
    {
      int hi = hex_v (hex[i * 2]);
      int lo = hex_v (hex[i * 2 + 1]);
      if (hi < 0 || lo < 0)
        return false;
      out[i] = (uint8_t)((hi << 4) | lo);
    }
  return true;
}

bool
if_ok (const char *name)
{
  size_t n = name ? strlen (name) : 0;
  return n > 0 && n < IFNAMSIZ && !strchr (name, '/');
}

bool
u64_get (const char *s, uint64_t max, uint64_t *out)
{
  char *end;
  unsigned long long v;
  if (!s || !*s)
    return false;
  errno = 0;
  v = strtoull (s, &end, 10);
  if (errno || *end || v > max)
    return false;
  *out = v;
  return true;
}
