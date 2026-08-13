#include "data.h"

#include "awg.h"
#include "cookie.h"
#include "crypto.h"
#include "tun.h"
#include "wire.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <net/if.h>
#include <sodium.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum
{
  IDX_HS = 1,
  IDX_KP = 2,
  REKEY_MS = 120000,
  REJECT_MS = 180000,
  RETRY_MS = 5000,
  RETRY_JITTER_MS = 334,
  KEEPALIVE_MS = 10000,
  HANDSHAKE_INIT_MS = 1000U / 50U,
};

static const uint64_t rekey_msg_limit = UINT64_C (1) << 60;

static uint64_t
awg_ms (const AwgRange *r, uint32_t fallback)
{
  return (uint64_t)awg_range_pick (r, fallback / 1000U) * 1000U;
}

static uint64_t
awg_lo_ms (const AwgRange *r, uint32_t fallback)
{
  return (uint64_t)(r->lo || r->hi ? r->lo : fallback / 1000U) * 1000U;
}

static uint64_t
awg_hi_ms (const AwgRange *r, uint32_t fallback)
{
  return (uint64_t)(r->lo || r->hi ? r->hi : fallback / 1000U) * 1000U;
}

static uint64_t
new_handshake_ms (const Dev *d)
{
  return awg_hi_ms (&d->awg.keepalive_timeout, KEEPALIVE_MS)
         + awg_ms (&d->awg.rekey_timeout, RETRY_MS);
}

static uint64_t
refresh_receiving_ms (const Dev *d)
{
  uint64_t reject = awg_ms (&d->awg.reject_after, REJECT_MS);
  uint64_t keepalive = awg_lo_ms (&d->awg.keepalive_timeout, KEEPALIVE_MS);
  uint64_t rekey = awg_lo_ms (&d->awg.rekey_timeout, RETRY_MS);
  return reject > keepalive + rekey ? reject - keepalive - rekey : 0;
}

static void
pka_arm (Peer *p, uint64_t now)
{
  if (p->ka.lo || p->ka.hi)
    atomic_store_explicit (&p->pka_due,
                           now + (uint64_t)awg_range_pick (&p->ka, 0) * 1000U,
                           memory_order_relaxed);
}

static void
ka_received (Dev *d, Peer *p, uint64_t now)
{
  if (atomic_load_explicit (&p->ka_due, memory_order_relaxed))
    p->ka_again = true;
  else
    atomic_store_explicit (&p->ka_due,
                           now + awg_ms (&d->awg.keepalive_timeout,
                                         KEEPALIVE_MS),
                           memory_order_relaxed);
}

uint64_t
data_now (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static int
sock (const Dev *d, const Ep *ep)
{
  return ep->sa.ss_family == AF_INET    ? d->udp4
         : ep->sa.ss_family == AF_INET6 ? d->udp6
                                        : -1;
}

static bool
send_pkt (Dev *d, Peer *p, const void *buf, size_t len, bool auth)
{
  int fd = sock (d, &p->addr);
  ssize_t n = fd < 0 ? -1 : udp_send (fd, &p->addr, buf, len);
  if (n == (ssize_t)len)
    {
      atomic_fetch_add_explicit (&p->tx, len, memory_order_relaxed);
      if (auth)
        {
          uint64_t now = data_now ();
          atomic_store_explicit (&p->last_tx, now,
                                 memory_order_relaxed);
          atomic_store_explicit (&p->ka_due, 0, memory_order_relaxed);
          pka_arm (p, now);
        }
      return true;
    }
  return false;
}

static void
awg_handshake_preamble (Dev *d, Peer *p)
{
  uint8_t *buf = malloc (AWG_PACKET_MAX);
  if (!buf)
    return;
  for (unsigned i = 0; i < 5; i++)
    {
      size_t len;
      if (d->awg.i[i]
          && awg_i_make (&d->awg, i, buf, &len, AWG_PACKET_MAX) == 0 && len)
        send_pkt (d, p, buf, len, false);
    }
  if (d->awg.jc && d->awg.jmax)
    for (uint32_t i = 0; i < d->awg.jc; i++)
      {
        size_t len = d->awg.jmin;
        if (d->awg.jmax > d->awg.jmin)
          len += randombytes_uniform (d->awg.jmax - d->awg.jmin + 1U);
        randombytes_buf (buf, len);
        send_pkt (d, p, buf, len, false);
      }
  sodium_memzero (buf, AWG_PACKET_MAX);
  free (buf);
}

static void
roam (Peer *p, const Ep *ep)
{
  p->addr = *ep;
  if (ep_fmt (ep, p->ep, sizeof (p->ep)) < 0)
    p->ep[0] = '\0';
}

static void
clear_src (Peer *p)
{
  p->addr.src_len = 0;
  p->addr.ifindex = 0;
}

static uint64_t
mono (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec;
}

static void
mac_add (Peer *p, void *msg, size_t mac_off, size_t mac2_off)
{
  cookie_mac1 ((uint8_t *)msg + mac_off, p->mac1_key, msg, mac_off);
  memcpy (p->last_mac1, (uint8_t *)msg + mac_off, COOKIE_LEN);
  p->mac1_ok = true;
  if (p->cookie_ok && mono () - p->cookie_birth < COOKIE_VALID_AGE)
    cookie_mac2 ((uint8_t *)msg + mac2_off, p->cookie, msg, mac2_off);
  else
    memset ((uint8_t *)msg + mac2_off, 0, COOKIE_LEN);
}

static bool
hs_under_load (Dev *d, uint64_t now)
{
  bool busy;
  pthread_mutex_lock (&d->hs_lock);
  busy = now < d->hs_busy_until;
  pthread_mutex_unlock (&d->hs_lock);
  return busy;
}

static bool
hs_rate_key (uint8_t key[17], const Ep *ep)
{
  memset (key, 0, 17);
  if (ep->sa.ss_family == AF_INET)
    {
      key[0] = AF_INET;
      memcpy (key + 1, &((const struct sockaddr_in *)&ep->sa)->sin_addr, 4);
      return true;
    }
  if (ep->sa.ss_family == AF_INET6)
    {
      key[0] = AF_INET6;
      memcpy (key + 1, &((const struct sockaddr_in6 *)&ep->sa)->sin6_addr,
              8);
      return true;
    }
  return false;
}

static bool
hs_rate_ok (Dev *d, const Ep *ep, uint64_t now)
{
  enum { RATE_MS = 1000U / 20U, BURST_MS = RATE_MS * 5U };
  HsRate *rate;
  uint8_t key[17];
  if (!hs_rate_key (key, ep))
    return false;
  HASH_FIND (hh, d->hs_rate, key, sizeof (key), rate);
  if (!rate)
    {
      rate = calloc (1, sizeof (*rate));
      if (!rate)
        {
          free (rate);
          return false;
        }
      memcpy (rate->key, key, sizeof (key));
      rate->last = now;
      rate->tokens = BURST_MS - RATE_MS;
      HASH_ADD (hh, d->hs_rate, key, sizeof (rate->key), rate);
      return true;
    }
  rate->tokens += now - rate->last;
  rate->last = now;
  if (rate->tokens > BURST_MS)
    rate->tokens = BURST_MS;
  if (rate->tokens >= RATE_MS)
    {
      rate->tokens -= RATE_MS;
      return true;
    }
  return false;
}

static void
hs_rate_prune (Dev *d, uint64_t now)
{
  HsRate *rate, *tmp;
  HASH_ITER (hh, d->hs_rate, rate, tmp)
    if (now - rate->last > 1000U)
      {
        HASH_DEL (d->hs_rate, rate);
        free (rate);
      }
}

static bool
cookie_make (Dev *d, const Ep *src, uint8_t out[COOKIE_LEN])
{
  uint64_t now = mono ();
  if (now - d->cookie_birth >= COOKIE_SECRET_AGE)
    {
      randombytes_buf (d->cookie_secret, sizeof (d->cookie_secret));
      d->cookie_birth = now;
    }
  return cookie_src (out, d->cookie_secret, (const struct sockaddr *)&src->sa);
}

static bool
mac_ok (Dev *d, const Ep *src, const void *msg, size_t mac_off,
        size_t mac2_off, uint32_t sender, uint64_t now)
{
  size_t cap;
  uint8_t *out;
  MsgCookie *r;
  uint8_t cookie[COOKIE_LEN];
  int fd;
  if (!d->has_sk
       || !cookie_mac1_check ((const uint8_t *)msg + mac_off, d->mac1_key, msg,
                               mac_off))
    return false;
  if (!hs_under_load (d, now))
    return true;
  if (!cookie_make (d, src, cookie))
    return false;
  if (cookie_mac2_check ((const uint8_t *)msg + mac2_off, cookie, msg,
                         mac2_off))
    {
      sodium_memzero (cookie, sizeof (cookie));
      return hs_rate_ok (d, src, now);
    }
  cap = sizeof (MsgCookie) + d->awg.s[AWG_COOKIE];
  out = malloc (cap);
  if (!out)
    goto out;
  r = (void *)out;
  awg_type_set (&d->awg, AWG_COOKIE, r);
  r->recv = sender;
  randombytes_buf (r->nonce, sizeof (r->nonce));
  if (cookie_reply_encrypt (r->cookie, cookie, (const uint8_t *)msg + mac_off,
                            r->nonce, d->cookie_key))
    {
      fd = sock (d, src);
      if (fd >= 0)
        {
          size_t len = sizeof (*r);
          if (awg_wrap (&d->awg, AWG_COOKIE, out, &len, cap) == 0)
            udp_send (fd, src, out, len);
        }
    }
  sodium_memzero (out, cap);
  free (out);
out:
  sodium_memzero (cookie, sizeof (cookie));
  return false;
}

static void
hs_time (Peer *p)
{
  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  p->hs_s = (uint64_t)ts.tv_sec;
  p->hs_ns = (uint64_t)ts.tv_nsec;
}

static void
kp_drop (Dev *d, Kp *k)
{
  if (k->li)
    idx_del (&d->idx, k->li);
  sodium_memzero (k, sizeof (*k));
}

static void
kp_move (Dev *d, Kp *dst, Kp *src)
{
  Idx *e;
  kp_drop (d, dst);
  *dst = *src;
  sodium_memzero (src, sizeof (*src));
  if (dst->li && (e = idx_fnd (d->idx, dst->li)))
    e->ptr = dst;
}

static bool
kp_promote (Dev *d, Peer *p, Kp *k)
{
  if (k != &p->pending)
    return false;
  kp_move (d, &p->prev, &p->kp);
  kp_move (d, &p->kp, &p->pending);
  return true;
}

static bool
kp_set (Dev *d, Peer *p, bool initiator)
{
  Idx *e;
  Kp k = { 0 };
  Kp *dst = initiator ? &p->kp : &p->pending;
  k.li = p->hs.li;
  k.ri = p->hs.ri;
  if (!k.li || !(e = idx_fnd (d->idx, k.li))
      || !noise_keys (&p->hs, k.tx, k.rx))
    return false;
  k.born = data_now ();
  k.peer = p;
  k.initiator = initiator;
  k.ok = true;
  if (initiator)
    {
      if (p->pending.ok)
        {
          kp_move (d, &p->prev, &p->pending);
          kp_drop (d, &p->kp);
        }
      else
        kp_move (d, &p->prev, &p->kp);
    }
  kp_drop (d, dst);
  *dst = k;
  e->ptr = dst;
  e->type = IDX_KP;
  p->hs.li = 0;
  p->rekey_due = initiator
                     ? k.born + awg_ms (&d->awg.rekey_after, REKEY_MS)
                     : 0;
  atomic_store_explicit (&p->zero_due,
                         k.born + awg_ms (&d->awg.reject_after, REJECT_MS) * 3U,
                         memory_order_relaxed);
  return true;
}

static bool
kp_live (const Dev *d, const Kp *k, uint64_t now)
{
  return k->ok && now - k->born < awg_hi_ms (&d->awg.reject_after, REJECT_MS)
         && atomic_load_explicit (&k->cnt, memory_order_relaxed)
                < REPLAY_LIMIT;
}

static void init_send (Dev *, Peer *, bool);
static void purge (Peer *);

static void
key_clear (Dev *d, Peer *p)
{
  uint8_t last[sizeof (p->hs.last)];
  memcpy (last, p->hs.last, sizeof (last));
  if (p->hs.li)
    idx_del (&d->idx, p->hs.li);
  kp_drop (d, &p->kp);
  kp_drop (d, &p->prev);
  kp_drop (d, &p->pending);
  noise_init (&p->hs, d->sk, p->pk, p->psk);
  memcpy (p->hs.last, last, sizeof (last));
  sodium_memzero (last, sizeof (last));
  p->hs_pending = false;
  p->hs_start = 0;
  p->hs_next = 0;
  p->rekey_due = 0;
  p->hs_attempts = 0;
  p->hs_max_attempts = 0;
  p->rekey_sent = false;
  purge (p);
}

static bool
data_send (Dev *d, Peer *p, const uint8_t *in, size_t len)
{
  uint8_t *out;
  MsgData *m;
  size_t pad = len + awg_content_pad (&d->awg, len, d->mtu), n;
  uint8_t key[KEY_LEN];
  Ep ep;
  uint64_t cnt;
  uint32_t ri;
  int fd;
  if (sizeof (*m) + pad + TAG_LEN + d->awg.s[AWG_DATA] > PKT_MAX
      || !(out = malloc (sizeof (*m) + pad + TAG_LEN + d->awg.s[AWG_DATA])))
    return false;
  m = (void *)out;
  pthread_mutex_lock (&d->data_lock);
  if (!kp_live (d, &p->kp, data_now ()))
    {
      pthread_mutex_unlock (&d->data_lock);
      free (out);
      return false;
    }
  cnt = atomic_fetch_add_explicit (&p->kp.cnt, 1, memory_order_relaxed);
  if (cnt >= REPLAY_LIMIT)
    {
      pthread_mutex_unlock (&d->data_lock);
      free (out);
      return false;
    }
  ri = p->kp.ri;
  memcpy (key, p->kp.tx, sizeof (key));
  ep = p->addr;
  fd = sock (d, &ep);
  pthread_mutex_unlock (&d->data_lock);
  awg_type_set (&d->awg, AWG_DATA, m);
  m->recv = htole32 (ri);
  m->cnt = htole64 (cnt);
  memcpy (out + sizeof (*m), in, len);
  memset (out + sizeof (*m) + len, 0, pad - len);
  if (!aead_enc (out + sizeof (*m), &n, out + sizeof (*m), pad, NULL, 0, cnt,
                 key))
    {
      free (out);
      return false;
    }
  sodium_memzero (key, sizeof (key));
  size_t outlen = sizeof (*m) + n;
  if (awg_wrap (&d->awg, AWG_DATA, out, &outlen,
                sizeof (*m) + pad + TAG_LEN + d->awg.s[AWG_DATA]) < 0)
    {
      sodium_memzero (out, sizeof (*m) + n);
      free (out);
      return false;
    }
  bool sent = fd >= 0 && udp_send (fd, &ep, out, outlen) == (ssize_t)outlen;
  sodium_memzero (out, outlen);
  free (out);
  if (!sent)
    return false;
  atomic_fetch_add_explicit (&p->tx, outlen, memory_order_relaxed);
  uint64_t now = data_now ();
  atomic_store_explicit (&p->last_tx, now, memory_order_relaxed);
  atomic_store_explicit (&p->ka_due, 0, memory_order_relaxed);
  if (len && !atomic_load_explicit (&p->hs_due, memory_order_relaxed))
    atomic_store_explicit (&p->hs_due,
                           now + new_handshake_ms (d)
                               + randombytes_uniform (RETRY_JITTER_MS),
                           memory_order_relaxed);
  if (p->kp.initiator && p->rekey_due && now >= p->rekey_due)
    atomic_store_explicit (&p->hs_due, now, memory_order_relaxed);
  pka_arm (p, now);
  if (cnt >= rekey_msg_limit)
    init_send (d, p, false);
  return true;
}

static bool
out_job (Dev *d, Peer *p, const uint8_t *buf, size_t len, WorkJob *j)
{
  uint64_t cnt;
  size_t pad = len + awg_content_pad (&d->awg, len, d->mtu);
  if (sizeof (MsgData) + pad + TAG_LEN + d->awg.s[AWG_DATA]
      > sizeof (j->buf))
    return false;
  memset (j, 0, offsetof (WorkJob, buf));
  pthread_mutex_lock (&d->data_lock);
  if (!kp_live (d, &p->kp, data_now ()))
    {
      pthread_mutex_unlock (&d->data_lock);
      return false;
    }
  cnt = atomic_fetch_add_explicit (&p->kp.cnt, 1, memory_order_relaxed);
  if (cnt >= REPLAY_LIMIT)
    {
      pthread_mutex_unlock (&d->data_lock);
      return false;
    }
  j->dev = d;
  j->type = WORK_OUT;
  j->awg = d->awg;
  memset (j->awg.i, 0, sizeof (j->awg.i));
  j->mtu = d->mtu;
  j->ep = p->addr;
  memcpy (j->peer, p->pk, sizeof (j->peer));
  memcpy (j->key, p->kp.tx, sizeof (j->key));
  j->cnt = cnt;
  j->index = p->kp.li;
  j->receiver = p->kp.ri;
  j->data_sent = len != 0;
  j->len = len;
  if (len)
    memcpy (j->buf, buf, len);
  pthread_mutex_unlock (&d->data_lock);
  return true;
}

static void
stage (Peer *p, const uint8_t *buf, size_t len)
{
  Pkt *q;
  if (len > PKT_MAX || !(q = malloc (sizeof (*q) + len)))
    return;
  q->len = len;
  if (len)
    memcpy (q->buf, buf, len);
  if (p->qn == STAGE_MAX)
    {
      sodium_memzero (p->q[0], sizeof (*p->q[0]) + p->q[0]->len);
      free (p->q[0]);
      memmove (p->q, p->q + 1, (STAGE_MAX - 1U) * sizeof (*p->q));
      p->qn--;
    }
  p->q[p->qn++] = q;
}

static void
purge (Peer *p)
{
  for (size_t i = 0; i < p->qn; i++)
    {
      sodium_memzero (p->q[i], sizeof (*p->q[i]) + p->q[i]->len);
      free (p->q[i]);
    }
  p->qn = 0;
}

static void
flush (Dev *d, Peer *p)
{
  size_t n = p->qn;
  p->qn = 0;
  for (size_t i = 0; i < n; i++)
    {
      data_send (d, p, p->q[i]->buf, p->q[i]->len);
      sodium_memzero (p->q[i], sizeof (*p->q[i]) + p->q[i]->len);
      free (p->q[i]);
    }
}

static void
init_send (Dev *d, Peer *p, bool retry)
{
  size_t cap = sizeof (MsgInit) + d->awg.s[AWG_INIT];
  uint8_t *buf = malloc (cap);
  MsgInit *m = (void *)buf;
  uint8_t last[sizeof (p->hs.last)];
  uint32_t li;
  uint64_t now = data_now ();
  if (!buf || !d->has_sk || !p->addr.len)
    goto out;
  if (p->hs_pending && !retry)
    goto out;
  if (p->hs_last_sent
      && now - p->hs_last_sent
             < awg_lo_ms (&d->awg.rekey_timeout, RETRY_MS))
    goto out;
  if (p->hs.li)
    idx_del (&d->idx, p->hs.li);
  memcpy (last, p->hs.last, sizeof (last));
  noise_init (&p->hs, d->sk, p->pk, p->psk);
  memcpy (p->hs.last, last, sizeof (last));
  sodium_memzero (last, sizeof (last));
  li = idx_add (&d->idx, p, IDX_HS);
  if (!li || !noise_init_make (&p->hs, m, li))
    {
      idx_del (&d->idx, li);
      p->hs.li = 0;
      goto out;
    }
  awg_type_set (&d->awg, AWG_INIT, m);
  mac_add (p, m, offsetof (MsgInit, mac1), offsetof (MsgInit, mac2));
  size_t len = sizeof (*m);
  awg_handshake_preamble (d, p);
  if (awg_wrap (&d->awg, AWG_INIT, buf, &len, cap) == 0)
    send_pkt (d, p, buf, len, true);
  p->hs_last_sent = now;
  if (!p->hs_pending)
    {
      p->hs_start = now;
      p->hs_attempts = 0;
      p->hs_max_attempts
          = awg_range_pick (&d->awg.max_handshake_attempts, 18);
    }
  p->hs_pending = true;
  p->hs_next = now + awg_ms (&d->awg.rekey_timeout, RETRY_MS)
               + randombytes_uniform (RETRY_JITTER_MS);
out:
  if (buf)
    {
      sodium_memzero (buf, cap);
      free (buf);
    }
}

void
data_tun (Dev *d, const uint8_t *buf, size_t len)
{
  const uint8_t *dst;
  int af;
  Peer *p;
  WorkJob j;
  WorkJob *job;
  if (len >= 20 && (buf[0] >> 4) == 4)
    af = AF_INET, dst = buf + 16;
  else if (len >= 40 && (buf[0] >> 4) == 6)
    af = AF_INET6, dst = buf + 24;
  else
    return;
  if (!d->up)
    return;
  pthread_rwlock_rdlock (&d->lock);
  p = aip_fnd (d, af, dst);
  if (!p)
    {
      pthread_rwlock_unlock (&d->lock);
      return;
    }
  job = work_reserve (WORK_OUT);
  if (job && out_job (d, p, buf, len, job))
    {
      job->owner = p;
      atomic_fetch_add_explicit (&p->work_ref, 1, memory_order_relaxed);
      work_submit (job);
      pthread_rwlock_unlock (&d->lock);
      return;
  }
  work_release (job, WORK_OUT);
  if (out_job (d, p, buf, len, &j))
    {
      data_work (&j);
      data_commit (&j);
      pthread_rwlock_unlock (&d->lock);
      return;
    }
  pthread_rwlock_unlock (&d->lock);
  pthread_rwlock_wrlock (&d->lock);
  p = aip_fnd (d, af, dst);
  if (!p)
    {
      pthread_rwlock_unlock (&d->lock);
      return;
    }
  if (p->kp.ok && data_send (d, p, buf, len))
    {
      pthread_rwlock_unlock (&d->lock);
      return;
    }
  stage (p, buf, len);
  init_send (d, p, false);
  pthread_rwlock_unlock (&d->lock);
}

static void
init_get (Dev *d, const Ep *src, MsgInit *m)
{
  Peer *p, *tmp;
  uint64_t now = data_now ();
  if (!mac_ok (d, src, m, offsetof (MsgInit, mac1), offsetof (MsgInit, mac2),
               m->sender, now))
    return;
  awg_type_normalize (m, AWG_INIT);
  HASH_ITER (hh, d->peer, p, tmp)
  {
    Noise n = p->hs;
    size_t cap = sizeof (MsgResp) + d->awg.s[AWG_RESP];
    uint8_t *buf = malloc (cap);
    MsgResp *r = (void *)buf;
    uint32_t li;
    if (!buf || !noise_init_get (&n, m)
        || (p->last_init_ms && now - p->last_init_ms <= HANDSHAKE_INIT_MS))
      {
        free (buf);
        continue;
      }
    if (p->hs.li)
      idx_del (&d->idx, p->hs.li);
    p->hs = n;
    p->last_init_ms = now;
    li = idx_add (&d->idx, p, IDX_HS);
    if (!li || !noise_resp_make (&p->hs, r, li))
      {
        idx_del (&d->idx, li);
        p->hs.li = 0;
        sodium_memzero (buf, cap);
        free (buf);
        return;
      }
    roam (p, src);
    atomic_fetch_add_explicit (&p->rx, sizeof (*m), memory_order_relaxed);
    atomic_store_explicit (&p->last_rx, now, memory_order_relaxed);
    atomic_store_explicit (&p->hs_due, 0, memory_order_relaxed);
    pka_arm (p, now);
    awg_type_set (&d->awg, AWG_RESP, r);
    mac_add (p, r, offsetof (MsgResp, mac1), offsetof (MsgResp, mac2));
    if (!idx_fnd (d->idx, li) || !kp_set (d, p, false))
      {
        idx_del (&d->idx, li);
        sodium_memzero (buf, cap);
        free (buf);
        return;
      }
    size_t len = sizeof (*r);
    if (awg_wrap (&d->awg, AWG_RESP, buf, &len, cap) == 0)
      send_pkt (d, p, buf, len, true);
    sodium_memzero (buf, cap);
    free (buf);
    return;
  }
}

static void
resp_get (Dev *d, const Ep *src, MsgResp *m)
{
  Idx *e;
  Peer *p;
  uint32_t li = le32toh (m->recv);
  if (!mac_ok (d, src, m, offsetof (MsgResp, mac1), offsetof (MsgResp, mac2),
               m->sender, data_now ())
      || !(e = idx_fnd (d->idx, li)) || e->type != IDX_HS)
    return;
  awg_type_normalize (m, AWG_RESP);
  p = e->ptr;
  if (!noise_resp_get (&p->hs, m) || !kp_set (d, p, true))
    return;
  roam (p, src);
  atomic_fetch_add_explicit (&p->rx, sizeof (*m), memory_order_relaxed);
  atomic_store_explicit (&p->last_rx, data_now (), memory_order_relaxed);
  atomic_store_explicit (&p->hs_due, 0, memory_order_relaxed);
  pka_arm (p, data_now ());
  hs_time (p);
  p->hs_pending = false;
  p->hs_start = 0;
  p->hs_next = 0;
  p->hs_attempts = 0;
  p->hs_max_attempts = 0;
  p->rekey_sent = false;
  if (!p->qn)
    data_send (d, p, NULL, 0);
  flush (d, p);
}

static Peer *
idx_peer (Dev *d, Idx *e)
{
  (void)d;
  if (e->type == IDX_HS)
    return e->ptr;
  return e->type == IDX_KP ? ((Kp *)e->ptr)->peer : NULL;
}

static void
cookie_get (Dev *d, const MsgCookie *m)
{
  uint8_t cookie[COOKIE_LEN];
  Idx *e = idx_fnd (d->idx, le32toh (m->recv));
  Peer *p;
  if (!e || !(p = idx_peer (d, e)) || !p->mac1_ok
      || !cookie_reply_decrypt (cookie, m->cookie, p->last_mac1, m->nonce,
                                p->cookie_key))
    return;
  memcpy (p->cookie, cookie, sizeof (p->cookie));
  p->cookie_birth = mono ();
  p->cookie_ok = true;
  p->mac1_ok = false;
  sodium_memzero (cookie, sizeof (cookie));
}

static void
data_get (Dev *d, const Ep *src, const uint8_t *buf, size_t len)
{
  const MsgData *m = (const void *)buf;
  uint8_t plain[PKT_MAX];
  uint64_t cnt = le64toh (m->cnt);
  size_t n, iplen;
  const uint8_t *sip;
  int af;
  uint32_t li = le32toh (m->recv);
  Idx *e;
  Kp *k;
  Peer *p;
  uint8_t key[KEY_LEN];
  uint64_t now = data_now ();
  if (len < sizeof (*m) + TAG_LEN)
    return;
  pthread_mutex_lock (&d->data_lock);
  e = idx_fnd (d->idx, li);
  if (!e || e->type != IDX_KP)
    {
      pthread_mutex_unlock (&d->data_lock);
      return;
    }
  k = e->ptr;
  if (!k->ok || now - k->born
                    >= awg_hi_ms (&d->awg.reject_after, REJECT_MS)
      || cnt >= REPLAY_LIMIT)
    {
      pthread_mutex_unlock (&d->data_lock);
      return;
    }
  memcpy (key, k->rx, sizeof (key));
  pthread_mutex_unlock (&d->data_lock);
  if (!aead_dec (plain, &n, buf + sizeof (*m), len - sizeof (*m), NULL, 0, cnt,
                 key))
    {
      sodium_memzero (key, sizeof (key));
      return;
    }
  sodium_memzero (key, sizeof (key));
  pthread_mutex_lock (&d->data_lock);
  e = idx_fnd (d->idx, li);
  if (!e || e->type != IDX_KP || !(k = e->ptr) || !k->ok
      || !replay_update (&k->replay, cnt))
    {
      pthread_mutex_unlock (&d->data_lock);
      return;
    }
  p = k->peer;
  if (!p)
    {
      pthread_mutex_unlock (&d->data_lock);
      return;
    }
  bool promoted = kp_promote (d, p, k);
  roam (p, src);
  atomic_fetch_add_explicit (&p->rx, len, memory_order_relaxed);
  atomic_store_explicit (&p->last_rx, now, memory_order_relaxed);
  atomic_store_explicit (&p->hs_due, 0, memory_order_relaxed);
  pka_arm (p, now);
  p->hs_pending = false;
  p->hs_start = 0;
  p->hs_next = 0;
  p->hs_attempts = 0;
  p->hs_max_attempts = 0;
  if (promoted)
    {
      hs_time (p);
      p->rekey_sent = false;
    }
  if (p->kp.initiator && !p->rekey_sent
       && now - p->kp.born >= refresh_receiving_ms (d))
    {
      p->rekey_sent = true;
      init_send (d, p, false);
    }
  pthread_mutex_unlock (&d->data_lock);
  if (!n)
    return;
  if (plain[0])
    ka_received (d, p, now);
  if (n >= 20 && (plain[0] >> 4) == 4)
    {
      size_t ihl = (size_t)(plain[0] & 15U) * 4U;
      af = AF_INET;
      iplen = ((size_t)plain[2] << 8) | plain[3];
      sip = plain + 12;
      if (ihl < 20 || ihl > iplen)
        return;
    }
  else if (n >= 40 && (plain[0] >> 4) == 6)
    {
      af = AF_INET6;
      iplen = 40U + (((size_t)plain[4] << 8) | plain[5]);
      sip = plain + 8;
    }
  else
    return;
  if (iplen > n || aip_fnd (d, af, sip) != p)
    return;
  if (tun_write (d->tun, plain, iplen) != (ssize_t)iplen)
    err ("(%s) tun write: %s", d->name, strerror (errno));
}

void
data_keepalive (Dev *d, Peer *p)
{
  if (data_send (d, p, NULL, 0))
    return;
  if (!p->qn)
    stage (p, NULL, 0);
  init_send (d, p, false);
}

void
data_tick (Dev *d, uint64_t now)
{
  Peer *p, *tmp;
  hs_rate_prune (d, now);
  HASH_ITER (hh, d->peer, p, tmp)
  {
    uint64_t reject = awg_hi_ms (&d->awg.reject_after, REJECT_MS);
    if (p->prev.ok && now - p->prev.born >= reject)
      kp_drop (d, &p->prev);
    if (p->pending.ok && now - p->pending.born >= reject)
      kp_drop (d, &p->pending);
    if (p->kp.ok && now - p->kp.born >= reject)
      kp_drop (d, &p->kp);
    if (p->hs_pending && p->hs_attempts > p->hs_max_attempts)
      {
        if (p->hs.li)
          idx_del (&d->idx, p->hs.li);
        p->hs.li = 0;
        p->hs_pending = false;
        p->hs_start = 0;
        p->hs_next = 0;
        p->hs_attempts = 0;
        p->hs_max_attempts = 0;
        uint8_t last[sizeof (p->hs.last)];
        memcpy (last, p->hs.last, sizeof (last));
        noise_init (&p->hs, d->sk, p->pk, p->psk);
        memcpy (p->hs.last, last, sizeof (last));
        sodium_memzero (last, sizeof (last));
        purge (p);
        if (!atomic_load_explicit (&p->zero_due, memory_order_relaxed))
          atomic_store_explicit (
              &p->zero_due,
              now + awg_ms (&d->awg.reject_after, REJECT_MS) * 3U,
              memory_order_relaxed);
      }
    else if (p->hs_pending && now >= p->hs_next)
      {
        p->hs_attempts++;
        clear_src (p);
        init_send (d, p, true);
      }
    uint64_t due = atomic_load_explicit (&p->ka_due, memory_order_relaxed);
    if (due && now >= due)
      {
        atomic_store_explicit (&p->ka_due, 0, memory_order_relaxed);
        data_keepalive (d, p);
        if (p->ka_again)
          {
            p->ka_again = false;
            atomic_store_explicit (&p->ka_due,
                                   now + awg_ms (&d->awg.keepalive_timeout,
                                                 KEEPALIVE_MS),
                                   memory_order_relaxed);
          }
      }
    uint64_t handshake_due
        = atomic_load_explicit (&p->hs_due, memory_order_relaxed);
    if (handshake_due && now >= handshake_due && !p->hs_pending)
      {
        atomic_store_explicit (&p->hs_due, 0, memory_order_relaxed);
        clear_src (p);
        init_send (d, p, false);
      }
    uint64_t pka = atomic_load_explicit (&p->pka_due, memory_order_relaxed);
    if (pka && now >= pka)
      {
        atomic_store_explicit (&p->pka_due, 0, memory_order_relaxed);
        data_keepalive (d, p);
      }
    uint64_t zero = atomic_load_explicit (&p->zero_due, memory_order_relaxed);
    if (zero && now >= zero)
      {
        atomic_store_explicit (&p->zero_due, 0, memory_order_relaxed);
        key_clear (d, p);
      }
  }
}

static uint64_t
due_min (uint64_t due, uint64_t next)
{
  return due && (!next || due < next) ? due : next;
}

uint64_t
data_next_due (Dev *d, uint64_t unused)
{
  Peer *p, *tmp;
  uint64_t next = 0;
  (void)unused;
  HASH_ITER (hh, d->peer, p, tmp)
    {
      next = due_min (p->hs_pending ? p->hs_next : 0, next);
      next = due_min (atomic_load_explicit (&p->ka_due, memory_order_relaxed),
                      next);
      next = due_min (atomic_load_explicit (&p->pka_due, memory_order_relaxed),
                      next);
      next = due_min (atomic_load_explicit (&p->hs_due, memory_order_relaxed),
                      next);
      next = due_min (atomic_load_explicit (&p->zero_due, memory_order_relaxed),
                      next);
      if (p->prev.ok)
        next = due_min (p->prev.born
                            + awg_hi_ms (&d->awg.reject_after, REJECT_MS),
                        next);
      if (p->pending.ok)
        next = due_min (p->pending.born
                            + awg_hi_ms (&d->awg.reject_after, REJECT_MS),
                        next);
      if (p->kp.ok)
        next = due_min (p->kp.born
                            + awg_hi_ms (&d->awg.reject_after, REJECT_MS),
                        next);
    }
  return next;
}

void
data_udp (Dev *d, const Ep *src, uint8_t *buf, size_t len)
{
  Awg awg;
  unsigned type;
  pthread_rwlock_rdlock (&d->lock);
  awg = d->awg;
  memset (awg.i, 0, sizeof (awg.i));
  pthread_rwlock_unlock (&d->lock);
  if (awg_unwrap (&awg, buf, &len, &type) < 0)
    return;
  if (type == AWG_DATA)
    {
      WorkJob j;
      WorkJob *job;
      const MsgData *m = (const void *)buf;
      Idx *e;
      Kp *k;
      if (len < sizeof (*m) + TAG_LEN)
        return;
      if (len > sizeof (j.buf))
        {
          pthread_rwlock_rdlock (&d->lock);
          data_get (d, src, buf, len);
          pthread_rwlock_unlock (&d->lock);
          return;
        }
      job = work_reserve (WORK_IN);
      if (!job && work_count ())
        return;
      if (!job)
        job = &j;
      memset (job, 0, offsetof (WorkJob, buf));
      job->dev = d;
      job->type = WORK_IN;
      job->ep = *src;
      job->cnt = le64toh (m->cnt);
      job->index = le32toh (m->recv);
      job->wire_len = len;
      pthread_rwlock_rdlock (&d->lock);
      pthread_mutex_lock (&d->data_lock);
      e = idx_fnd (d->idx, job->index);
      if (!e || e->type != IDX_KP || !(k = e->ptr) || !k->ok
           || data_now () - k->born
                  >= awg_hi_ms (&d->awg.reject_after, REJECT_MS)
          || job->cnt >= REPLAY_LIMIT)
        {
          pthread_mutex_unlock (&d->data_lock);
          pthread_rwlock_unlock (&d->lock);
          work_release (job == &j ? NULL : job, WORK_IN);
          return;
        }
      job->receiver = k->li;
      job->owner = k->peer;
      if (job != &j)
        atomic_fetch_add_explicit (&job->owner->work_ref, 1,
                                   memory_order_relaxed);
      memcpy (job->key, k->rx, sizeof (job->key));
      memcpy (job->peer, k->peer->pk, sizeof (job->peer));
      memcpy (job->buf, buf, len);
      job->len = len;
      pthread_mutex_unlock (&d->data_lock);
      if (job == &j)
        {
          pthread_rwlock_unlock (&d->lock);
          data_work (&j);
          data_commit (&j);
        }
      else
        {
          work_submit (job);
          pthread_rwlock_unlock (&d->lock);
        }
      return;
    }
  if ((type == AWG_INIT && len != sizeof (MsgInit))
      || (type == AWG_RESP && len != sizeof (MsgResp))
      || (type == AWG_COOKIE && len != sizeof (MsgCookie)))
    return;
  pthread_mutex_lock (&d->hs_lock);
  if (d->hs_n < HS_QUEUE_CAP)
    {
      HsJob *job = &d->hs[(d->hs_head + d->hs_n) % HS_QUEUE_CAP];
      job->ep = *src;
      job->len = len;
      job->type = type;
      memcpy (job->buf, buf, len);
      d->hs_n++;
      if (d->hs_n >= HS_QUEUE_CAP / 8U)
        d->hs_busy_until = data_now () + 1000U;
      pthread_cond_signal (&d->hs_ready);
    }
  pthread_mutex_unlock (&d->hs_lock);
}

static void
hs_handle (Dev *d, HsJob *job)
{
  pthread_rwlock_wrlock (&d->lock);
  switch (job->type)
    {
    case AWG_INIT:
      init_get (d, &job->ep, (void *)job->buf);
      break;
    case AWG_RESP:
      resp_get (d, &job->ep, (void *)job->buf);
      break;
    case AWG_COOKIE:
      awg_type_normalize (job->buf, AWG_COOKIE);
      cookie_get (d, (const void *)job->buf);
      break;
    }
  pthread_rwlock_unlock (&d->lock);
}

static void *
hs_worker (void *arg)
{
  Dev *d = arg;
  for (;;)
    {
      HsJob job;
      pthread_mutex_lock (&d->hs_lock);
      while (!d->hs_n && !d->hs_stop)
        pthread_cond_wait (&d->hs_ready, &d->hs_lock);
      if (!d->hs_n && d->hs_stop)
        {
          pthread_mutex_unlock (&d->hs_lock);
          return NULL;
        }
      job = d->hs[d->hs_head];
      d->hs_head = (d->hs_head + 1U) % HS_QUEUE_CAP;
      d->hs_n--;
      d->hs_active++;
      pthread_mutex_unlock (&d->hs_lock);
      hs_handle (d, &job);
      pthread_mutex_lock (&d->hs_lock);
      d->hs_active--;
      if (!d->hs_n && !d->hs_active)
        pthread_cond_broadcast (&d->hs_idle);
      pthread_mutex_unlock (&d->hs_lock);
    }
}

int
data_hs_start (Dev *d)
{
  return pthread_create (&d->hs_thread, NULL, hs_worker, d) ? -1 : 0;
}

void
data_hs_drain (Dev *d)
{
  pthread_mutex_lock (&d->hs_lock);
  while (d->hs_n || d->hs_active)
    pthread_cond_wait (&d->hs_idle, &d->hs_lock);
  pthread_mutex_unlock (&d->hs_lock);
}

void
data_hs_free (Dev *d)
{
  pthread_mutex_lock (&d->hs_lock);
  d->hs_stop = true;
  pthread_cond_signal (&d->hs_ready);
  pthread_mutex_unlock (&d->hs_lock);
  pthread_join (d->hs_thread, NULL);
  hs_rate_prune (d, UINT64_MAX);
}

void
data_work (WorkJob *j)
{
  if (j->type == WORK_IN)
    {
      size_t n;
      memmove (j->buf, j->buf + sizeof (MsgData), j->len - sizeof (MsgData));
      j->ok = aead_dec (j->buf, &n, j->buf, j->len - sizeof (MsgData), NULL, 0,
                        j->cnt, j->key);
      j->len = j->ok ? n : 0;
    }
  else
    {
      MsgData m = {
        .type = 0,
        .recv = htole32 (j->receiver),
        .cnt = htole64 (j->cnt),
      };
      size_t plain = j->len;
      size_t pad = plain + awg_content_pad (&j->awg, plain, j->mtu);
      size_t n;
      memmove (j->buf + sizeof (m), j->buf, plain);
      awg_type_set (&j->awg, AWG_DATA, &m);
      memcpy (j->buf, &m, sizeof (m));
      memset (j->buf + sizeof (m) + plain, 0, pad - plain);
      j->ok = aead_enc (j->buf + sizeof (m), &n, j->buf + sizeof (m), pad,
                        NULL, 0, j->cnt, j->key);
      j->len = j->ok ? sizeof (m) + n : 0;
      if (j->ok
          && awg_wrap (&j->awg, AWG_DATA, j->buf, &j->len,
                       sizeof (j->buf)) < 0)
        j->ok = false;
    }
  sodium_memzero (j->key, sizeof (j->key));
}

void
data_commit (WorkJob *j)
{
  Dev *d = j->dev;
  Peer *p;
  pthread_rwlock_rdlock (&d->lock);
  p = dev_peer_fnd (d, j->peer);
  if (!j->ok || !p)
    goto out;
  if (j->type == WORK_OUT)
    {
      Ep ep;
      pthread_mutex_lock (&d->data_lock);
      ep = p->addr;
      pthread_mutex_unlock (&d->data_lock);
      int fd = sock (d, &ep);
      if (fd >= 0 && udp_send (fd, &ep, j->buf, j->len) == (ssize_t)j->len)
        {
          atomic_fetch_add_explicit (&p->tx, j->len, memory_order_relaxed);
          uint64_t now = data_now ();
          atomic_store_explicit (&p->last_tx, now,
                                 memory_order_relaxed);
          atomic_store_explicit (&p->ka_due, 0, memory_order_relaxed);
          if (j->data_sent)
            if (!atomic_load_explicit (&p->hs_due, memory_order_relaxed))
              atomic_store_explicit (
                  &p->hs_due,
                  now + new_handshake_ms (d)
                       + randombytes_uniform (RETRY_JITTER_MS),
                  memory_order_relaxed);
          if (p->kp.initiator && p->rekey_due && now >= p->rekey_due)
            atomic_store_explicit (&p->hs_due, now, memory_order_relaxed);
          pka_arm (p, now);
          if (j->cnt >= rekey_msg_limit)
            atomic_store_explicit (&p->hs_due, now, memory_order_relaxed);
        }
      goto out;
    }

  pthread_mutex_lock (&d->data_lock);
  Idx *e = idx_fnd (d->idx, j->receiver);
  Kp *k;
  if (!e || e->type != IDX_KP || !(k = e->ptr) || !k->ok || k->peer != p
      || !replay_update (&k->replay, j->cnt))
    {
      pthread_mutex_unlock (&d->data_lock);
      goto out;
    }
  uint64_t now = data_now ();
  bool promoted = kp_promote (d, p, k);
  roam (p, &j->ep);
  atomic_fetch_add_explicit (&p->rx, j->wire_len, memory_order_relaxed);
  atomic_store_explicit (&p->last_rx, now, memory_order_relaxed);
  atomic_store_explicit (&p->hs_due, 0, memory_order_relaxed);
  pka_arm (p, now);
  p->hs_pending = false;
  p->hs_start = 0;
  p->hs_next = 0;
  p->hs_attempts = 0;
  p->hs_max_attempts = 0;
  if (promoted)
    {
      hs_time (p);
      p->rekey_sent = false;
    }
  if (p->kp.initiator && !p->rekey_sent
       && now - p->kp.born >= refresh_receiving_ms (d))
    {
      p->rekey_sent = true;
      init_send (d, p, false);
    }
  pthread_mutex_unlock (&d->data_lock);
  if (j->len)
    {
      const uint8_t *sip;
      size_t iplen;
      int af;
      if (j->buf[0])
        ka_received (d, p, now);
      if (j->len >= 20 && (j->buf[0] >> 4) == 4)
        {
          size_t ihl = (size_t)(j->buf[0] & 15U) * 4U;
          af = AF_INET;
          iplen = ((size_t)j->buf[2] << 8) | j->buf[3];
          sip = j->buf + 12;
          if (ihl < 20 || ihl > iplen)
            goto out;
        }
      else if (j->len >= 40 && (j->buf[0] >> 4) == 6)
        {
          af = AF_INET6;
          iplen = 40U + (((size_t)j->buf[4] << 8) | j->buf[5]);
          sip = j->buf + 8;
        }
      else
        goto out;
      if (iplen <= j->len && aip_fnd (d, af, sip) == p)
        {
          pka_arm (p, now);
          if (tun_write (d->tun, j->buf, iplen) != (ssize_t)iplen)
            err ("(%s) tun write: %s", d->name, strerror (errno));
        }
    }
out:
  pthread_rwlock_unlock (&d->lock);
}
