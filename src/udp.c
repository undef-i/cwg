#include "udp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
port_get (const char *s, uint16_t *port)
{
  char *end;
  unsigned long n;

  if (!*s)
    return -1;
  errno = 0;
  n = strtoul (s, &end, 10);
  if (errno || *end || n > UINT16_MAX)
    return -1;
  *port = (uint16_t)n;
  return 0;
}

int
ep_get (Ep *ep, const char *s)
{
  struct sockaddr_in sa4 = { .sin_family = AF_INET };
  struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6 };
  char host[INET6_ADDRSTRLEN];
  const char *p;
  size_t n;
  uint16_t port;

  if (!ep || !s)
    {
      errno = EINVAL;
      return -1;
    }
  if (*s == '[')
    {
      p = strchr (s + 1, ']');
      if (!p || p[1] != ':' || port_get (p + 2, &port) < 0)
        goto bad;
      n = (size_t)(p - s - 1);
      if (!n || n >= sizeof (host))
        goto bad;
      memcpy (host, s + 1, n);
      host[n] = '\0';
      if (inet_pton (AF_INET6, host, &sa6.sin6_addr) != 1)
        goto bad;
      sa6.sin6_port = htons (port);
      memset (ep, 0, sizeof (*ep));
      memcpy (&ep->sa, &sa6, sizeof (sa6));
      ep->len = sizeof (sa6);
      return 0;
    }
  p = strrchr (s, ':');
  if (!p || port_get (p + 1, &port) < 0)
    goto bad;
  n = (size_t)(p - s);
  if (!n || n >= sizeof (host))
    goto bad;
  memcpy (host, s, n);
  host[n] = '\0';
  if (inet_pton (AF_INET, host, &sa4.sin_addr) != 1)
    goto bad;
  sa4.sin_port = htons (port);
  memset (ep, 0, sizeof (*ep));
  memcpy (&ep->sa, &sa4, sizeof (sa4));
  ep->len = sizeof (sa4);
  return 0;

bad:
  errno = EINVAL;
  return -1;
}

static int
udp_bind (int af, uint16_t port)
{
  int fd = socket (af, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  if (af == AF_INET6)
    {
      int one = 1;
      if (setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof (one)) < 0)
        goto fail;
      struct sockaddr_in6 sa = {
        .sin6_family = AF_INET6,
        .sin6_port = htons (port),
        .sin6_addr = IN6ADDR_ANY_INIT,
      };
      if (bind (fd, (struct sockaddr *)&sa, sizeof (sa)) < 0)
        goto fail;
    }
  else
    {
      struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons (port),
        .sin_addr.s_addr = htonl (INADDR_ANY),
      };
      if (bind (fd, (struct sockaddr *)&sa, sizeof (sa)) < 0)
        goto fail;
    }
  return fd;

fail:
  {
    int e = errno;
    close (fd);
    errno = e;
    return -1;
  }
}

int
udp_open (int *udp4, int *udp6, uint16_t *port)
{
  uint16_t want;
  int e4, e6;

  if (!udp4 || !udp6 || !port)
    {
      errno = EINVAL;
      return -1;
    }
  want = *port;
  *udp4 = -1;
  *udp6 = -1;
  for (;;)
    {
      struct sockaddr_in sa;
      socklen_t len = sizeof (sa);

      *udp4 = udp_bind (AF_INET, want);
      e4 = errno;
      if (*udp4 >= 0)
        {
          if (getsockname (*udp4, (struct sockaddr *)&sa, &len) < 0)
            goto fail;
          *udp6 = udp_bind (AF_INET6, ntohs (sa.sin_port));
          e6 = errno;
          if (*udp6 >= 0 || e6 == EAFNOSUPPORT)
            {
              *port = ntohs (sa.sin_port);
              return 0;
            }
          if (!want && e6 == EADDRINUSE)
            {
              close (*udp4);
              *udp4 = -1;
              continue;
            }
          goto fail;
        }
      *udp6 = udp_bind (AF_INET6, want);
      e6 = errno;
      if (*udp6 >= 0 && e4 == EAFNOSUPPORT)
        {
          struct sockaddr_in6 sa6;
          socklen_t len6 = sizeof (sa6);
          if (getsockname (*udp6, (struct sockaddr *)&sa6, &len6) < 0)
            goto fail;
          *port = ntohs (sa6.sin6_port);
          return 0;
        }
      errno = e4 != EAFNOSUPPORT ? e4 : e6;
      goto fail;
    }

fail:
  {
    int e = errno;
    udp_close (*udp4, *udp6);
    *udp4 = -1;
    *udp6 = -1;
    errno = e;
    return -1;
  }
}

void
udp_close (int udp4, int udp6)
{
  if (udp4 >= 0)
    close (udp4);
  if (udp6 >= 0)
    close (udp6);
}

int
udp_mark (int udp4, int udp6, uint32_t mark)
{
  if (udp4 >= 0
      && setsockopt (udp4, SOL_SOCKET, SO_MARK, &mark, sizeof (mark)) < 0)
    return -1;
  return udp6 < 0
         || setsockopt (udp6, SOL_SOCKET, SO_MARK, &mark, sizeof (mark)) == 0
             ? 0
             : -1;
}

ssize_t
udp_send (int fd, const Ep *ep, const void *buf, size_t len)
{
  ssize_t n;

  if (!ep || (ep->sa.ss_family != AF_INET && ep->sa.ss_family != AF_INET6))
    {
      errno = EINVAL;
      return -1;
    }
  do
    n = sendto (fd, buf, len, 0, (const struct sockaddr *)&ep->sa, ep->len);
  while (n < 0 && errno == EINTR);
  return n;
}

ssize_t
udp_recv (int fd, Ep *ep, void *buf, size_t cap)
{
  struct sockaddr_storage sa;
  socklen_t len;
  ssize_t n;

  if (!ep)
    {
      errno = EINVAL;
      return -1;
    }
  do
    {
      len = sizeof (sa);
      n = recvfrom (fd, buf, cap, 0, (struct sockaddr *)&sa, &len);
    }
  while (n < 0 && errno == EINTR);
  if (n >= 0)
    {
      memset (ep, 0, sizeof (*ep));
      memcpy (&ep->sa, &sa, len);
      ep->len = len;
    }
  return n;
}

int
udp_recv_batch (int fd, UdpPacket *pkt, unsigned cap)
{
  struct mmsghdr msg[UDP_BATCH_MAX];
  struct iovec iov[UDP_BATCH_MAX];
  struct sockaddr_storage sa[UDP_BATCH_MAX];
  int n;
  if (!pkt || !cap || cap > UDP_BATCH_MAX)
    {
      errno = EINVAL;
      return -1;
    }
  memset (msg, 0, cap * sizeof (*msg));
  for (unsigned i = 0; i < cap; i++)
    {
      iov[i].iov_base = pkt[i].buf;
      iov[i].iov_len = sizeof (pkt[i].buf);
      msg[i].msg_hdr.msg_name = &sa[i];
      msg[i].msg_hdr.msg_namelen = sizeof (sa[i]);
      msg[i].msg_hdr.msg_iov = &iov[i];
      msg[i].msg_hdr.msg_iovlen = 1;
    }
  do
    n = recvmmsg (fd, msg, cap, MSG_DONTWAIT, NULL);
  while (n < 0 && errno == EINTR);
  for (int i = 0; i < n; i++)
    {
      memset (&pkt[i].ep, 0, sizeof (pkt[i].ep));
      memcpy (&pkt[i].ep.sa, &sa[i], msg[i].msg_hdr.msg_namelen);
      pkt[i].ep.len = msg[i].msg_hdr.msg_namelen;
      pkt[i].len = (msg[i].msg_hdr.msg_flags & MSG_TRUNC) ? 0 : msg[i].msg_len;
    }
  return n;
}
