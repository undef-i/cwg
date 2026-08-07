#include "uapi.h"
#include "data.h"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct
{
  Peer *p;
  bool dummy;
  bool fresh;
} SetPeer;

static int
aip_set (Dev *d, Peer *p, const char *val)
{
  uint8_t ip[16] = { 0 };
  char buf[INET6_ADDRSTRLEN + 5];
  char *slash, *end;
  bool del = *val == '-';
  unsigned long cidr;
  int af;

  if (del)
    val++;
  if (strlen (val) >= sizeof (buf))
    return -EINVAL;
  strcpy (buf, val);
  slash = strrchr (buf, '/');
  if (!slash)
    return -EINVAL;
  *slash++ = '\0';
  cidr = strtoul (slash, &end, 10);
  if (*end)
    return -EINVAL;
  af = strchr (buf, ':') ? AF_INET6 : AF_INET;
  if (cidr > (af == AF_INET ? 32UL : 128UL) || inet_pton (af, buf, ip) != 1)
    return -EINVAL;

  if (del)
    {
      aip_del (d, p, af, ip, (uint8_t)cidr);
      return 0;
    }
  return aip_add (d, p, af, ip, (uint8_t)cidr);
}

static int
dev_set (Dev *d, const char *key, const char *val)
{
  uint8_t sk[KEY_LEN];
  uint64_t n;
  if (!strcmp (key, "private_key"))
    {
      if (!key_get (sk, val))
        return -EINVAL;
      dev_key_set (d, sk);
      sodium_memzero (sk, sizeof (sk));
    }
  else if (!strcmp (key, "listen_port"))
    {
      if (!u64_get (val, UINT16_MAX, &n))
        return -EINVAL;
      if (dev_bind (d, (uint16_t)n, d->mark) < 0)
        return errno == EADDRINUSE ? -EADDRINUSE : -EIO;
    }
  else if (!strcmp (key, "fwmark"))
    {
      if (!u64_get (val, UINT32_MAX, &n))
        return -EINVAL;
      if (udp_mark (d->udp4, d->udp6, (uint32_t)n) < 0)
        return -EIO;
      d->mark = (uint32_t)n;
    }
  else if (!strcmp (key, "replace_peers") && !strcmp (val, "true"))
    dev_peer_clr (d);
  else
    return -EINVAL;
  return 0;
}

static int
peer_set (Dev *d, SetPeer *sp, const char *key, const char *val)
{
  uint64_t n;
  if (!strcmp (key, "update_only"))
    {
      if (strcmp (val, "true"))
        return -EINVAL;
      if (sp->fresh && !sp->dummy)
        {
          dev_peer_del (d, sp->p);
          sp->p = NULL;
          sp->dummy = true;
        }
    }
  else if (!strcmp (key, "remove"))
    {
      if (strcmp (val, "true"))
        return -EINVAL;
      if (!sp->dummy)
        dev_peer_del (d, sp->p);
      sp->p = NULL;
      sp->dummy = true;
    }
  else if (sp->dummy)
    return 0;
  else if (!strcmp (key, "preshared_key"))
    {
      uint8_t psk[KEY_LEN];
      if (!key_get (psk, val))
        return -EINVAL;
      memcpy (sp->p->psk, psk, sizeof (psk));
      sodium_memzero (psk, sizeof (psk));
      dev_peer_reset (d, sp->p);
    }
  else if (!strcmp (key, "endpoint"))
    {
      if (!*val || strlen (val) >= sizeof (sp->p->ep))
        return -EINVAL;
      if (ep_get (&sp->p->addr, val) < 0)
        return -EINVAL;
      strcpy (sp->p->ep, val);
      if (sp->p->qn)
        data_keepalive (d, sp->p);
    }
  else if (!strcmp (key, "persistent_keepalive_interval"))
    {
      uint16_t old = sp->p->ka;
      if (!u64_get (val, UINT16_MAX, &n))
        return -EINVAL;
      sp->p->ka = (uint16_t)n;
      if (!old && sp->p->ka)
        data_keepalive (d, sp->p);
    }
  else if (!strcmp (key, "replace_allowed_ips"))
    {
      if (strcmp (val, "true"))
        return -EINVAL;
      aip_del_peer (d, sp->p);
    }
  else if (!strcmp (key, "allowed_ip"))
    return aip_set (d, sp->p, val);
  else if (!strcmp (key, "protocol_version"))
    {
      if (strcmp (val, "1"))
        return -EINVAL;
    }
  else
    return -EINVAL;
  return 0;
}

static int
set_run (Dev *d, FILE *f)
{
  SetPeer sp = { 0 };
  char *line = NULL;
  size_t cap = 0;
  int rc = 0;

  while (getline (&line, &cap, f) > 0)
    {
      char *eq, *val;
      size_t n = strlen (line);
      if (n && line[n - 1] == '\n')
        line[--n] = '\0';
      if (!n)
        break;
      eq = strchr (line, '=');
      if (!eq)
        {
          rc = -EPROTO;
          break;
        }
      *eq = '\0';
      val = eq + 1;
      if (!strcmp (line, "public_key"))
        {
          uint8_t pk[KEY_LEN];
          if (!key_get (pk, val))
            {
              rc = -EINVAL;
              break;
            }
          sp.dummy = d->has_sk && !memcmp (pk, d->pk, KEY_LEN);
          sp.p = sp.dummy ? NULL : dev_peer_get (d, pk, &sp.fresh);
          if (!sp.dummy && !sp.p)
            {
              rc = -ENOMEM;
              break;
            }
        }
      else if (!sp.p && !sp.dummy)
        rc = dev_set (d, line, val);
      else
        rc = peer_set (d, &sp, line, val);
      if (rc)
        break;
    }
  free (line);
  return rc;
}

static void
get_run (Dev *d, FILE *f)
{
  char hex[HEX_LEN + 1];
  Peer *p, *tmp;
  if (d->has_sk)
    {
      key_hex (hex, d->sk);
      fprintf (f, "private_key=%s\n", hex);
    }
  if (d->port)
    fprintf (f, "listen_port=%u\n", d->port);
  if (d->mark)
    fprintf (f, "fwmark=%u\n", d->mark);
  HASH_ITER (hh, d->peer, p, tmp)
  {
    key_hex (hex, p->pk);
    fprintf (f, "public_key=%s\n", hex);
    key_hex (hex, p->psk);
    fprintf (f, "preshared_key=%s\nprotocol_version=1\n", hex);
    if (p->ep[0])
      fprintf (f, "endpoint=%s\n", p->ep);
    fprintf (f,
             "last_handshake_time_sec=%llu\n"
             "last_handshake_time_nsec=%llu\n"
             "tx_bytes=%llu\nrx_bytes=%llu\n"
             "persistent_keepalive_interval=%u\n",
             (unsigned long long)p->hs_s, (unsigned long long)p->hs_ns,
             (unsigned long long)atomic_load_explicit (&p->tx,
                                                       memory_order_relaxed),
             (unsigned long long)atomic_load_explicit (&p->rx,
                                                       memory_order_relaxed),
             p->ka);
    for (Aip *a = d->aip; a; a = a->next)
      {
        char ip[INET6_ADDRSTRLEN];
        if (a->peer == p && inet_ntop (a->af, a->ip, ip, sizeof (ip)))
          fprintf (f, "allowed_ip=%s/%u\n", ip, a->cidr);
      }
  }
}

static void
conn_hnd (Dev *d, int fd)
{
  FILE *f = fdopen (fd, "r+");
  char *op = NULL;
  size_t cap = 0;
  if (!f)
    {
      close (fd);
      return;
    }
  while (getline (&op, &cap, f) > 0)
    {
      int rc;
      if (!strcmp (op, "set=1\n"))
        rc = set_run (d, f);
      else if (!strcmp (op, "get=1\n"))
        {
          int c = fgetc (f);
          rc = c == '\n' ? 0 : -EINVAL;
          if (!rc)
            get_run (d, f);
        }
      else
        break;
      fprintf (f, "errno=%d\n\n", rc < 0 ? -rc : rc);
      fflush (f);
      break;
    }
  free (op);
  fclose (f);
}

int
uapi_open (Dev *d)
{
  struct sockaddr_un sa = { .sun_family = AF_UNIX };
  mode_t old;
  int fd;

  if (mkdir (SOCKET_DIR, 0755) < 0 && errno != EEXIST)
    return -1;
  snprintf (d->sock, sizeof (d->sock), "%s/%s.sock", SOCKET_DIR, d->name);
  if (strlen (d->sock) >= sizeof (sa.sun_path))
    {
      errno = ENAMETOOLONG;
      return -1;
    }
  strcpy (sa.sun_path, d->sock);
  fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0)
    return -1;
  old = umask (0077);
  if (bind (fd, (struct sockaddr *)&sa, sizeof (sa)) < 0)
    {
      int e = errno;
      umask (old);
      close (fd);
      if (e == EADDRINUSE)
        {
          int t = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
          if (t >= 0 && connect (t, (struct sockaddr *)&sa, sizeof (sa)) < 0)
            {
              close (t);
              unlink (d->sock);
              return uapi_open (d);
            }
          if (t >= 0)
            close (t);
        }
      errno = e;
      return -1;
    }
  umask (old);
  if (listen (fd, 16) < 0)
    {
      close (fd);
      unlink (d->sock);
      return -1;
    }
  d->uapi = fd;
  return 0;
}

int
uapi_hnd (Dev *d)
{
  for (;;)
    {
      int fd = accept4 (d->uapi, NULL, NULL, SOCK_CLOEXEC);
      if (fd < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
      struct timeval tv = { .tv_sec = 1 };
      setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
      setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof (tv));
      pthread_rwlock_wrlock (&d->lock);
      conn_hnd (d, fd);
      pthread_rwlock_unlock (&d->lock);
    }
}

void
uapi_close (Dev *d)
{
  if (d->uapi >= 0)
    close (d->uapi);
  d->uapi = -1;
  if (d->sock[0])
    unlink (d->sock);
}
