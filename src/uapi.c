#include "uapi.h"
#include "awg.h"
#include "data.h"
#include "utils.h"
#include "work.h"

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
#include <sys/un.h>
#include <unistd.h>

typedef struct
{
  Peer *p;
  bool dummy;
  bool fresh;
  bool pka_on;
} SetPeer;

struct UapiConn
{
  Dev *dev;
  int fd;
  UapiConn *next;
};

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
  if (slash[0] == '0' && slash[1])
    return -EINVAL;
  for (const char *p = slash; *p; p++)
    if (*p < '0' || *p > '9')
      return -EINVAL;
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
dev_set (Dev *d, Awg *awg, const char *key, const char *val)
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
      if (d->up && (uint16_t)n != d->bind_port
          && dev_bind (d, (uint16_t)n, d->mark) < 0)
        return errno == EADDRINUSE ? -EADDRINUSE : -EIO;
      if (d->up)
        dev_loop_wake (d);
      if (!d->up)
        d->bind_port = (uint16_t)n;
    }
  else if (!strcmp (key, "fwmark"))
    {
      if (!u64_get (val, UINT32_MAX, &n))
        return -EINVAL;
      if (d->up && udp_mark (d->udp4, d->udp6, (uint32_t)n) < 0)
        return -EIO;
      d->mark = (uint32_t)n;
    }
  else if (!strcmp (key, "replace_peers") && !strcmp (val, "true"))
    dev_peer_clr (d);
  else
    {
      int rc = awg_set (awg, key, val);
      if (rc == -ENOENT || rc < 0)
        return -EINVAL;
    }
  return 0;
}

static int
peer_set (Dev *d, SetPeer *sp, const char *key, const char *val)
{
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
      memcpy (sp->p->hs.psk, psk, sizeof (psk));
      sodium_memzero (psk, sizeof (psk));
    }
  else if (!strcmp (key, "endpoint"))
    {
      if (!*val || strlen (val) >= sizeof (sp->p->ep))
        return -EINVAL;
      if (ep_get (&sp->p->addr, val) < 0)
        return -EINVAL;
      if (ep_fmt (&sp->p->addr, sp->p->ep, sizeof (sp->p->ep)) < 0)
        return -EINVAL;
    }
  else if (!strcmp (key, "persistent_keepalive_interval"))
    {
      AwgRange old = sp->p->ka;
      if (awg_range_set (&sp->p->ka, val) < 0)
        return -EINVAL;
      if (!(sp->p->ka.lo || sp->p->ka.hi))
        atomic_store_explicit (&sp->p->pka_due, 0, memory_order_relaxed);
      sp->pka_on = !(old.lo || old.hi) && (sp->p->ka.lo || sp->p->ka.hi);
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

static void
peer_done (Dev *d, SetPeer *sp)
{
  if (!sp->p || sp->dummy || !d->up)
    return;
  if (sp->pka_on || sp->p->qn)
    data_keepalive (d, sp->p);
}

static int
set_run (Dev *d, FILE *f)
{
  Awg staged;
  SetPeer sp = { 0 };
  char *line = NULL;
  size_t cap = 0;
  int rc = 0;

  if (awg_clone (&staged, &d->awg) < 0)
    return -ENOMEM;
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
            peer_done (d, &sp);
            sp = (SetPeer){ 0 };
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
        rc = dev_set (d, &staged, line, val);
      else
        rc = peer_set (d, &sp, line, val);
      if (rc)
        break;
    }
  if (!rc)
    {
      if (awg_validate (&staged) < 0)
        rc = -EINVAL;
      else
        {
          Awg old = d->awg;
          d->awg = staged;
          staged = old;
          peer_done (d, &sp);
        }
    }
  awg_free (&staged);
  free (line);
  return rc;
}

static void
get_allowed_ip (int af, const uint8_t ip[16], uint8_t cidr, void *arg)
{
  FILE *f = arg;
  char text[INET6_ADDRSTRLEN];
  if (inet_ntop (af, ip, text, sizeof (text)))
    fprintf (f, "allowed_ip=%s/%u\n", text, cidr);
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
  if (d->bind_port)
    fprintf (f, "listen_port=%u\n", d->bind_port);
  if (d->mark)
    fprintf (f, "fwmark=%u\n", d->mark);
  if (d->awg.jc)
    fprintf (f, "jc=%u\n", d->awg.jc);
  if (d->awg.jmin)
    fprintf (f, "jmin=%u\n", d->awg.jmin);
  if (d->awg.jmax)
    fprintf (f, "jmax=%u\n", d->awg.jmax);
  for (unsigned i = 0; i < AWG_TYPE_N; i++)
    if (d->awg.s[i])
      fprintf (f, "s%u=%u\n", i + 1U, d->awg.s[i]);
  for (unsigned i = 0; i < AWG_TYPE_N; i++)
    {
      char range[32];
      if (d->awg.h[i].lo || d->awg.h[i].hi)
        fprintf (f, "h%u=%s\n", i + 1U,
                 awg_range_get (&d->awg.h[i], range));
    }
  for (unsigned i = 0; i < 5; i++)
    if (d->awg.i[i])
      fprintf (f, "i%u=%s\n", i + 1U, d->awg.i[i]);
  if (d->awg.hp)
    {
      key_hex (hex, d->awg.hp_key);
      fprintf (f, "header_protection_key=%s\n", hex);
    }
  if (d->awg.content_pad.lo || d->awg.content_pad.hi)
    {
      char range[32];
      fprintf (f, "content_padding_addition=%s\n",
               awg_range_get (&d->awg.content_pad, range));
    }
  const struct { const char *name; const AwgRange *range; } timings[] = {
    { "rekey_after_time", &d->awg.rekey_after },
    { "rekey_timeout", &d->awg.rekey_timeout },
    { "reject_after_time", &d->awg.reject_after },
    { "keepalive_timeout", &d->awg.keepalive_timeout },
    { "max_handshake_attempts", &d->awg.max_handshake_attempts },
  };
  for (size_t i = 0; i < sizeof (timings) / sizeof (timings[0]); i++)
    if (timings[i].range->lo || timings[i].range->hi)
      {
        char range[32];
        fprintf (f, "%s=%s\n", timings[i].name,
                 awg_range_get (timings[i].range, range));
      }
  HASH_ITER (hh, d->peer, p, tmp)
  {
    pthread_mutex_lock (&d->data_lock);
    key_hex (hex, p->pk);
    fprintf (f, "public_key=%s\n", hex);
    key_hex (hex, p->psk);
    fprintf (f, "preshared_key=%s\nprotocol_version=1\n", hex);
    if (p->ep[0])
      fprintf (f, "endpoint=%s\n", p->ep);
    fprintf (f,
             "last_handshake_time_sec=%llu\n"
             "last_handshake_time_nsec=%llu\n"
             "tx_bytes=%llu\nrx_bytes=%llu\n",
             (unsigned long long)p->hs_s, (unsigned long long)p->hs_ns,
             (unsigned long long)atomic_load_explicit (&p->tx,
                                                        memory_order_relaxed),
             (unsigned long long)atomic_load_explicit (&p->rx,
                                                        memory_order_relaxed));
    if (p->ka.lo || p->ka.hi)
      {
        char range[32];
        fprintf (f, "persistent_keepalive_interval=%s\n",
                 awg_range_get (&p->ka, range));
      }
    aip_each (d, p, get_allowed_ip, f);
    pthread_mutex_unlock (&d->data_lock);
  }
}

static void
conn_hnd (Dev *d, int fd)
{
  FILE *f = fdopen (fd, "r");
  FILE *out;
  char *op = NULL;
  size_t op_cap = 0;
  if (!f)
    {
      close (fd);
      return;
    }
  out = fdopen (dup (fd), "w");
  if (!out)
    {
      fclose (f);
      return;
    }
  for (;;)
    {
      ssize_t n = getline (&op, &op_cap, f);
      if (n <= 0)
        break;
      int rc = -EINVAL;
      if (!strcmp (op, "set=1\n"))
        {
          pthread_rwlock_wrlock (&d->lock);
          rc = set_run (d, f);
          pthread_rwlock_unlock (&d->lock);
          if (!rc)
            dev_loop_wake (d);
        }
      else if (!strcmp (op, "get=1\n"))
        {
          int c = fgetc (f);
          if (c != '\n')
            goto bad;
          char *reply = NULL;
          size_t reply_len = 0;
          FILE *snapshot = open_memstream (&reply, &reply_len);
          if (snapshot)
            {
              pthread_rwlock_rdlock (&d->lock);
              get_run (d, snapshot);
              pthread_rwlock_unlock (&d->lock);
              if (fclose (snapshot) == 0
                  && fwrite (reply, 1, reply_len, out) == reply_len)
                rc = 0;
              free (reply);
            }
          else
            rc = -ENOMEM;
        }
      else
        break;
      fprintf (out, "errno=%d\n\n", rc);
      if (fflush (out))
        break;
    }
  free (op);
  fclose (out);
  fclose (f);
  return;

bad:
  free (op);
  fclose (out);
  fclose (f);
}

static void *
conn_run (void *arg)
{
  UapiConn *conn = arg;
  Dev *d = conn->dev;
  conn_hnd (d, conn->fd);
  pthread_mutex_lock (&d->uapi_lock);
  UapiConn **pp = &d->uapi_conn;
  while (*pp != conn)
    pp = &(*pp)->next;
  *pp = conn->next;
  d->uapi_n--;
  if (!d->uapi_n)
    pthread_cond_broadcast (&d->uapi_idle);
  pthread_mutex_unlock (&d->uapi_lock);
  free (conn);
  return NULL;
}

int
uapi_open (Dev *d)
{
  struct sockaddr_un sa = { .sun_family = AF_UNIX };
  mode_t old;
  int fd;

  if (mkdir (d->socket_dir, 0755) < 0 && errno != EEXIST)
    return -1;
  snprintf (d->sock, sizeof (d->sock), "%s/%s.sock", d->socket_dir, d->name);
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
uapi_adopt (Dev *d, int fd)
{
  struct sockaddr_un sa = { 0 };
  socklen_t sa_len = sizeof (sa);
  socklen_t opt_len = sizeof (int);
  int flags, type, listening;
  if (fd < 0 || getsockname (fd, (struct sockaddr *)&sa, &sa_len) < 0
      || sa.sun_family != AF_UNIX
      || getsockopt (fd, SOL_SOCKET, SO_TYPE, &type, &opt_len) < 0
      || type != SOCK_STREAM
      || getsockopt (fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &opt_len) < 0
      || !listening || !sa.sun_path[0]
      || (flags = fcntl (fd, F_GETFL)) < 0
      || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0
      || (flags = fcntl (fd, F_GETFD)) < 0
      || fcntl (fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    return -1;
  snprintf (d->sock, sizeof (d->sock), "%s", sa.sun_path);
  char expected[sizeof (d->sock)];
  snprintf (expected, sizeof (expected), "%s/%s.sock", d->socket_dir,
            d->name);
  if (strcmp (d->sock, expected))
    return -1;
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
      UapiConn *conn = malloc (sizeof (*conn));
      if (!conn)
        {
          close (fd);
          continue;
        }
      conn->dev = d;
      conn->fd = fd;
      pthread_mutex_lock (&d->uapi_lock);
      conn->next = d->uapi_conn;
      d->uapi_conn = conn;
      d->uapi_n++;
      pthread_mutex_unlock (&d->uapi_lock);
      pthread_t thread;
      if (pthread_create (&thread, NULL, conn_run, conn))
        {
          pthread_mutex_lock (&d->uapi_lock);
          d->uapi_conn = conn->next;
          d->uapi_n--;
          pthread_mutex_unlock (&d->uapi_lock);
          close (fd);
          free (conn);
          continue;
        }
      pthread_detach (thread);
    }
}

void
uapi_drain (Dev *d)
{
  pthread_mutex_lock (&d->uapi_lock);
  for (UapiConn *conn = d->uapi_conn; conn; conn = conn->next)
    shutdown (conn->fd, SHUT_RDWR);
  while (d->uapi_n)
    pthread_cond_wait (&d->uapi_idle, &d->uapi_lock);
  pthread_mutex_unlock (&d->uapi_lock);
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
