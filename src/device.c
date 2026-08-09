#include "device.h"
#include "work.h"

#include <errno.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t
mono (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec;
}

static void
peer_destroy (Peer *p)
{
  sodium_memzero (p, sizeof (*p));
  free (p);
}

static void
peer_cookie_reset (Peer *p)
{
  sodium_memzero (p->cookie, sizeof (p->cookie));
  sodium_memzero (p->last_mac1, sizeof (p->last_mac1));
  p->cookie_birth = 0;
  p->cookie_ok = false;
  p->mac1_ok = false;
  cookie_mac1_key (p->mac1_key, p->pk);
  cookie_key (p->cookie_key, p->pk);
}

void
dev_peer_reset (Dev *d, Peer *p)
{
  if (!d || !p)
    return;
  if (p->hs.li)
    idx_del (&d->idx, p->hs.li);
  if (p->kp.li && p->kp.li != p->hs.li)
    idx_del (&d->idx, p->kp.li);
  if (p->prev.li && p->prev.li != p->hs.li && p->prev.li != p->kp.li)
    idx_del (&d->idx, p->prev.li);
  if (p->pending.li && p->pending.li != p->hs.li && p->pending.li != p->kp.li
      && p->pending.li != p->prev.li)
    idx_del (&d->idx, p->pending.li);
  sodium_memzero (&p->hs, sizeof (p->hs));
  sodium_memzero (&p->kp, sizeof (p->kp));
  sodium_memzero (&p->prev, sizeof (p->prev));
  sodium_memzero (&p->pending, sizeof (p->pending));
  peer_cookie_reset (p);
  for (size_t i = 0; i < p->qn; i++)
    {
      sodium_memzero (p->q[i], sizeof (*p->q[i]) + p->q[i]->len);
      free (p->q[i]);
    }
  p->qn = 0;
  p->last_tx = 0;
  p->last_rx = 0;
  p->ka_due = 0;
  p->pka_due = 0;
  p->hs_start = 0;
  p->hs_next = 0;
  p->hs_attempts = 0;
  p->hs_max_attempts = 0;
  p->hs_pending = false;
  if (d->has_sk)
    noise_init (&p->hs, d->sk, p->pk, p->psk);
}

Dev *
dev_new (const char *name)
{
  Dev *d = calloc (1, sizeof (*d));
  if (!d)
    return NULL;
  snprintf (d->name, sizeof (d->name), "%s", name);
  d->tun = -1;
  d->uapi = -1;
  d->udp4 = -1;
  d->udp6 = -1;
  awg_init (&d->awg);
  if (pthread_rwlock_init (&d->lock, NULL)
      || pthread_mutex_init (&d->data_lock, NULL))
    {
      free (d);
      return NULL;
    }
  randombytes_buf (d->cookie_secret, sizeof (d->cookie_secret));
  d->cookie_birth = mono ();
  return d;
}

void
dev_peer_del (Dev *d, Peer *p)
{
  if (!d || !p)
    return;
  aip_del_peer (d, p);
  HASH_DEL (d->peer, p);
  dev_peer_reset (d, p);
  p->retired = true;
  p->retired_next = d->retired;
  d->retired = p;
}

void
dev_reap (Dev *d)
{
  Peer **pp = &d->retired;
  while (*pp)
    {
      Peer *p = *pp;
      if (atomic_load_explicit (&p->work_ref, memory_order_acquire))
        {
          pp = &p->retired_next;
          continue;
        }
      *pp = p->retired_next;
      peer_destroy (p);
    }
}

void
dev_peer_clr (Dev *d)
{
  Peer *p, *tmp;
  HASH_ITER (hh, d->peer, p, tmp) dev_peer_del (d, p);
}

void
dev_free (Dev *d)
{
  if (!d)
    return;
  work_drain ();
  dev_peer_clr (d);
  dev_reap (d);
  idx_clr (&d->idx);
  udp_close (d->udp4, d->udp6);
  pthread_mutex_destroy (&d->data_lock);
  pthread_rwlock_destroy (&d->lock);
  sodium_memzero (d, sizeof (*d));
  free (d);
}

Peer *
dev_peer_fnd (Dev *d, const uint8_t pk[KEY_LEN])
{
  Peer *p = NULL;
  HASH_FIND (hh, d->peer, pk, KEY_LEN, p);
  return p;
}

Peer *
dev_peer_get (Dev *d, const uint8_t pk[KEY_LEN], bool *is_new)
{
  Peer *p = dev_peer_fnd (d, pk);
  if (is_new)
    *is_new = p == NULL;
  if (p)
    return p;
  p = calloc (1, sizeof (*p));
  if (!p)
    return NULL;
  memcpy (p->pk, pk, KEY_LEN);
  peer_cookie_reset (p);
  if (d->has_sk)
    noise_init (&p->hs, d->sk, p->pk, p->psk);
  HASH_ADD (hh, d->peer, pk, KEY_LEN, p);
  return p;
}

void
dev_key_set (Dev *d, const uint8_t sk[KEY_LEN])
{
  Peer *p, *tmp;
  memcpy (d->sk, sk, KEY_LEN);
  d->has_sk = !sodium_is_zero (sk, KEY_LEN);
  if (d->has_sk)
    {
      crypto_scalarmult_curve25519_base (d->pk, d->sk);
      cookie_mac1_key (d->mac1_key, d->pk);
      cookie_key (d->cookie_key, d->pk);
    }
  else
    {
      sodium_memzero (d->pk, sizeof (d->pk));
      sodium_memzero (d->mac1_key, sizeof (d->mac1_key));
      sodium_memzero (d->cookie_key, sizeof (d->cookie_key));
    }
  sodium_memzero (d->cookie_secret, sizeof (d->cookie_secret));
  randombytes_buf (d->cookie_secret, sizeof (d->cookie_secret));
  d->cookie_birth = mono ();
  d->hs_window = 0;
  d->hs_count = 0;
  HASH_ITER (hh, d->peer, p, tmp)
  {
    if (d->has_sk && !sodium_memcmp (p->pk, d->pk, KEY_LEN))
      dev_peer_del (d, p);
    else
      dev_peer_reset (d, p);
  }
}

int
dev_bind (Dev *d, uint16_t port, uint32_t mark)
{
  int fd4, fd6;
  uint16_t actual = port;
  if (udp_open (&fd4, &fd6, &actual) < 0)
    return -1;
  if (udp_mark (fd4, fd6, mark) < 0)
    {
      int e = errno;
      udp_close (fd4, fd6);
      errno = e;
      return -1;
    }
  udp_close (d->udp4, d->udp6);
  d->udp4 = fd4;
  d->udp6 = fd6;
  d->port = actual;
  d->bind_port = actual;
  d->mark = mark;
  d->udp_gen++;
  return 0;
}

int
dev_up (Dev *d, bool up)
{
  if (d->up == up)
    return 0;
  if (!up)
    {
      d->up = false;
      udp_close (d->udp4, d->udp6);
      d->udp4 = d->udp6 = -1;
      d->udp_gen++;
      return 0;
    }
  if (dev_bind (d, d->bind_port, d->mark) < 0)
    return -1;
  d->up = true;
  return 0;
}
