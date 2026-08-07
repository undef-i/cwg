#include "aip.h"
#include "device.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static size_t
af_len (int af)
{
  return af == AF_INET ? 4U : af == AF_INET6 ? 16U : 0U;
}

static void
ip_mask (uint8_t dst[16], const uint8_t src[16], uint8_t cidr)
{
  size_t n = cidr / 8U;
  uint8_t rem = cidr % 8U;

  memset (dst, 0, 16);
  memcpy (dst, src, n);
  if (rem)
    dst[n] = src[n] & (uint8_t)(0xffU << (8U - rem));
}

static bool
ip_eq (const Aip *a, int af, const uint8_t ip[16], uint8_t cidr)
{
  uint8_t net[16];
  size_t n = af_len (af);

  if (!n || cidr > n * 8U || a->af != af || a->cidr != cidr)
    return false;
  ip_mask (net, ip, cidr);
  return !memcmp (a->ip, net, n);
}

static bool
ip_has (const Aip *a, const uint8_t ip[16])
{
  size_t n = a->cidr / 8U;
  uint8_t rem = a->cidr % 8U;

  if (n && memcmp (a->ip, ip, n))
    return false;
  return !rem || a->ip[n] == (ip[n] & (uint8_t)(0xffU << (8U - rem)));
}

int
aip_add (Dev *d, Peer *p, int af, const uint8_t ip[16], uint8_t cidr)
{
  size_t n = af_len (af);
  Aip *a;

  if (!d || !p || !ip || !n || cidr > n * 8U)
    return -EINVAL;
  for (a = d->aip; a; a = a->next)
    if (ip_eq (a, af, ip, cidr))
      {
        a->peer = p;
        return 0;
      }
  a = calloc (1, sizeof (*a));
  if (!a)
    return -ENOMEM;
  a->af = af;
  a->cidr = cidr;
  a->peer = p;
  ip_mask (a->ip, ip, cidr);
  a->next = d->aip;
  d->aip = a;
  return 0;
}

void
aip_del (Dev *d, const Peer *p, int af, const uint8_t ip[16], uint8_t cidr)
{
  Aip **pp, *a;

  if (!d || !p || !ip)
    return;
  for (pp = &d->aip; (a = *pp); pp = &a->next)
    if (a->peer == p && ip_eq (a, af, ip, cidr))
      {
        *pp = a->next;
        free (a);
        return;
      }
}

void
aip_del_peer (Dev *d, const Peer *p)
{
  Aip **pp, *a;

  if (!d || !p)
    return;
  pp = &d->aip;
  while ((a = *pp))
    if (a->peer == p)
      {
        *pp = a->next;
        free (a);
      }
    else
      pp = &a->next;
}

Peer *
aip_fnd (const Dev *d, int af, const uint8_t ip[16])
{
  const Aip *a, *best = NULL;

  if (!d || !ip || !af_len (af))
    return NULL;
  for (a = d->aip; a; a = a->next)
    if (a->af == af && (!best || a->cidr > best->cidr) && ip_has (a, ip))
      best = a;
  return best ? best->peer : NULL;
}
