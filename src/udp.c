#include "udp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

static int
port_get (const char *s, uint16_t *port)
{
  uint64_t n = 0;

  if (!*s)
    return -1;
  for (const char *p = s; *p; p++)
    {
      if (*p < '0' || *p > '9' || n > (UINT16_MAX - (unsigned)(*p - '0')) / 10U)
        return -1;
      n = n * 10U + (unsigned)(*p - '0');
    }
  if (n > UINT16_MAX)
    return -1;
  *port = (uint16_t)n;
  return 0;
}

int
ep_get (Ep *ep, const char *s)
{
  struct sockaddr_in sa4 = { .sin_family = AF_INET };
  struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6 };
  char host[INET6_ADDRSTRLEN + IFNAMSIZ + 2U];
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
      char *zone = strchr (host, '%');
      if (zone)
        {
          *zone++ = '\0';
          if (!*zone || !(sa6.sin6_scope_id = if_nametoindex (zone)))
            goto bad;
        }
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

int
ep_fmt (const Ep *ep, char *buf, size_t cap)
{
  char ip[INET6_ADDRSTRLEN];
  uint16_t port;
  if (ep->sa.ss_family == AF_INET)
    {
      const struct sockaddr_in *sa = (const void *)&ep->sa;
      if (!inet_ntop (AF_INET, &sa->sin_addr, ip, sizeof (ip)))
        return -1;
      port = ntohs (sa->sin_port);
      return snprintf (buf, cap, "%s:%u", ip, port) < (int)cap ? 0 : -1;
    }
  if (ep->sa.ss_family == AF_INET6)
    {
      const struct sockaddr_in6 *sa = (const void *)&ep->sa;
      if (!inet_ntop (AF_INET6, &sa->sin6_addr, ip, sizeof (ip)))
        return -1;
      port = ntohs (sa->sin6_port);
      if (sa->sin6_scope_id)
        {
          char zone[IFNAMSIZ];
          if (if_indextoname (sa->sin6_scope_id, zone))
            return snprintf (buf, cap, "[%s%%%s]:%u", ip, zone, port)
                           < (int)cap
                       ? 0
                       : -1;
        }
      return snprintf (buf, cap, "[%s]:%u", ip, port) < (int)cap ? 0 : -1;
    }
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
      if (setsockopt (fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof (one))
          < 0)
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
      int one = 1;
      if (setsockopt (fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof (one)) < 0)
        goto fail;
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
  int old4 = 0, old6 = 0;
  socklen_t len4 = sizeof (old4), len6 = sizeof (old6);
  bool set4 = false, set6 = false;
  if (udp4 >= 0 && (getsockopt (udp4, SOL_SOCKET, SO_MARK, &old4, &len4) < 0
                    || setsockopt (udp4, SOL_SOCKET, SO_MARK, &mark,
                                   sizeof (mark)) < 0))
    return -1;
  set4 = udp4 >= 0;
  if (udp6 >= 0
      && (getsockopt (udp6, SOL_SOCKET, SO_MARK, &old6, &len6) < 0
          || setsockopt (udp6, SOL_SOCKET, SO_MARK, &mark, sizeof (mark)) < 0))
    {
      if (set4)
        setsockopt (udp4, SOL_SOCKET, SO_MARK, &old4, sizeof (old4));
      return -1;
    }
  set6 = udp6 >= 0;
  (void)set6;
  return 0;
}

ssize_t
udp_send (int fd, const Ep *ep, const void *buf, size_t len)
{
  struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
  struct msghdr msg = {
    .msg_name = (void *)&ep->sa,
    .msg_namelen = ep->len,
    .msg_iov = &iov,
    .msg_iovlen = 1,
  };
  uint8_t control[CMSG_SPACE (sizeof (struct in6_pktinfo))] = { 0 };
  ssize_t n;

  if (!ep || (ep->sa.ss_family != AF_INET && ep->sa.ss_family != AF_INET6))
    {
      errno = EINVAL;
      return -1;
    }
  if (ep->src_len)
    {
      struct cmsghdr *cmsg;
      msg.msg_control = control;
      if (ep->src.ss_family == AF_INET)
        {
          struct in_pktinfo *info;
          msg.msg_controllen = CMSG_SPACE (sizeof (*info));
          cmsg = CMSG_FIRSTHDR (&msg);
          cmsg->cmsg_level = IPPROTO_IP;
          cmsg->cmsg_type = IP_PKTINFO;
          cmsg->cmsg_len = CMSG_LEN (sizeof (*info));
          info = (void *)CMSG_DATA (cmsg);
          info->ipi_ifindex = (int)ep->ifindex;
          info->ipi_spec_dst = ((const struct sockaddr_in *)&ep->src)->sin_addr;
        }
      else if (ep->src.ss_family == AF_INET6)
        {
          struct in6_pktinfo *info;
          msg.msg_controllen = CMSG_SPACE (sizeof (*info));
          cmsg = CMSG_FIRSTHDR (&msg);
          cmsg->cmsg_level = IPPROTO_IPV6;
          cmsg->cmsg_type = IPV6_PKTINFO;
          cmsg->cmsg_len = CMSG_LEN (sizeof (*info));
          info = (void *)CMSG_DATA (cmsg);
          info->ipi6_ifindex = ep->ifindex;
          info->ipi6_addr = ((const struct sockaddr_in6 *)&ep->src)->sin6_addr;
        }
    }
  do
    n = sendmsg (fd, &msg, 0);
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
  uint8_t control[UDP_BATCH_MAX][CMSG_SPACE (sizeof (struct in6_pktinfo))];
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
      msg[i].msg_hdr.msg_control = control[i];
      msg[i].msg_hdr.msg_controllen = sizeof (control[i]);
    }
  do
    n = recvmmsg (fd, msg, cap, MSG_DONTWAIT, NULL);
  while (n < 0 && errno == EINTR);
  for (int i = 0; i < n; i++)
    {
      memset (&pkt[i].ep, 0, sizeof (pkt[i].ep));
      memcpy (&pkt[i].ep.sa, &sa[i], msg[i].msg_hdr.msg_namelen);
      pkt[i].ep.len = msg[i].msg_hdr.msg_namelen;
      for (struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg[i].msg_hdr); cmsg;
           cmsg = CMSG_NXTHDR (&msg[i].msg_hdr, cmsg))
        {
          if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
            {
              const struct in_pktinfo *info = (const void *)CMSG_DATA (cmsg);
              struct sockaddr_in *src = (void *)&pkt[i].ep.src;
              src->sin_family = AF_INET;
              src->sin_addr = info->ipi_addr;
              pkt[i].ep.src_len = sizeof (*src);
              pkt[i].ep.ifindex = (uint32_t)info->ipi_ifindex;
            }
          else if (cmsg->cmsg_level == IPPROTO_IPV6
                   && cmsg->cmsg_type == IPV6_PKTINFO)
            {
              const struct in6_pktinfo *info = (const void *)CMSG_DATA (cmsg);
              struct sockaddr_in6 *src = (void *)&pkt[i].ep.src;
              src->sin6_family = AF_INET6;
              src->sin6_addr = info->ipi6_addr;
              src->sin6_scope_id = info->ipi6_ifindex;
              pkt[i].ep.src_len = sizeof (*src);
              pkt[i].ep.ifindex = info->ipi6_ifindex;
            }
        }
      pkt[i].len = (msg[i].msg_hdr.msg_flags & MSG_TRUNC) ? 0 : msg[i].msg_len;
    }
  return n;
}
