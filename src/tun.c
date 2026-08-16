#include "tun.h"
#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/virtio_net.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifndef IFF_TUN
#define IFF_TUN 0x0001
#endif
#ifndef IFF_NO_PI
#define IFF_NO_PI 0x1000
#endif
#ifndef TUNSETIFF
#define TUNSETIFF _IOW ('T', 202, int)
#endif
#ifndef TUNGETIFF
#define TUNGETIFF _IOR ('T', 210, unsigned int)
#endif
#ifndef TUNSETOFFLOAD
#define TUNSETOFFLOAD _IOW ('T', 208, unsigned int)
#endif
#ifndef IFF_VNET_HDR
#define IFF_VNET_HDR 0x4000
#endif
#ifndef TUN_F_CSUM
#define TUN_F_CSUM 0x01
#endif
#ifndef TUN_F_TSO4
#define TUN_F_TSO4 0x02
#endif
#ifndef TUN_F_TSO6
#define TUN_F_TSO6 0x04
#endif
#ifndef TUN_F_USO4
#define TUN_F_USO4 0x20
#endif
#ifndef TUN_F_USO6
#define TUN_F_USO6 0x40
#endif
#ifndef VIRTIO_NET_HDR_GSO_UDP_L4
#define VIRTIO_NET_HDR_GSO_UDP_L4 5
#endif

enum
{
  DEFAULT_MTU = 1420,
  MAX_CONTENT_MTU = PKT_MAX - 32U,
  TUN_GSO_MAX_SEGMENTS = 128U,
};

static uint16_t
csum (const uint8_t *buf, size_t len, uint32_t sum)
{
  while (len > 1)
    {
      sum += ((uint32_t)buf[0] << 8) | buf[1];
      buf += 2;
      len -= 2;
    }
  if (len)
    sum += (uint32_t)buf[0] << 8;
  while (sum >> 16)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (uint16_t)sum;
}

static uint32_t
pseudo_csum (uint8_t proto, const uint8_t *src, const uint8_t *dst,
             size_t addr_len, uint16_t len)
{
  uint8_t tail[8] = { 0 };
  uint32_t sum = csum (src, addr_len, 0);
  sum = csum (dst, addr_len, sum);
  if (addr_len == 4)
    {
      tail[1] = proto;
      tail[2] = (uint8_t)(len >> 8);
      tail[3] = (uint8_t)len;
      return csum (tail, sizeof (tail) / 2U, sum);
    }
  tail[2] = (uint8_t)(len >> 8);
  tail[3] = (uint8_t)len;
  tail[7] = proto;
  return csum (tail, sizeof (tail), sum);
}

static uint32_t
get32 (const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | p[3];
}

static bool
gro_ip_headers_match (const uint8_t *a, const uint8_t *b, bool v6)
{
  if (v6)
    return a[0] == b[0] && (a[1] >> 4) == (b[1] >> 4) && a[7] == b[7];
  return a[1] == b[1] && (a[6] >> 5) == (b[6] >> 5) && a[8] == b[8];
}

static bool
gro_ipv4_unfragmented (const uint8_t *p)
{
  return !(p[6] & 0x3fU) && !p[7];
}

static bool
gro_checksum_valid (const uint8_t *pkt, size_t len, size_t ip_len,
                    bool v6, uint8_t proto)
{
  size_t addr_at = v6 ? 8U : 12U;
  size_t addr_len = v6 ? 16U : 4U;
  uint16_t transport_len;
  uint32_t sum;
  if (len < ip_len || len - ip_len > UINT16_MAX)
    return false;
  transport_len = (uint16_t)(len - ip_len);
  sum = pseudo_csum (proto, pkt + addr_at, pkt + addr_at + addr_len, addr_len,
                     transport_len);
  return csum (pkt + ip_len, transport_len, sum) == UINT16_MAX;
}

static bool
gro_packet_valid (const uint8_t *pkt, size_t len, bool v6, uint8_t proto,
                  size_t *ip_len, size_t *transport_len, bool check_checksum)
{
  size_t ihl = v6 ? 40U : (size_t)(pkt[0] & 15U) * 4U;
  size_t thl;
  if (len > UINT16_MAX || len < ihl + (proto == IPPROTO_TCP ? 20U : 8U)
      || (!v6 && ihl != 20U)
      || (v6 && (((size_t)pkt[4] << 8 | pkt[5]) != len - ihl))
      || (!v6 && (((size_t)pkt[2] << 8 | pkt[3]) != len
                  || !gro_ipv4_unfragmented (pkt)))
      || pkt[v6 ? 6 : 9] != proto)
    return false;
  thl = proto == IPPROTO_TCP ? (size_t)(pkt[ihl + 12] >> 4) * 4U : 8U;
  if (thl < (proto == IPPROTO_TCP ? 20U : 8U) || thl > 60U
      || ihl + thl >= len
      || (check_checksum && !gro_checksum_valid (pkt, len, ihl, v6, proto)))
    return false;
  *ip_len = ihl;
  *transport_len = thl;
  return true;
}

static void
gro_update_checksum (uint8_t *pkt, size_t len, size_t ip_len, bool v6,
                     uint8_t proto)
{
  size_t addr_at = v6 ? 8U : 12U;
  size_t addr_len = v6 ? 16U : 4U;
  size_t csum_at = ip_len + (proto == IPPROTO_TCP ? 16U : 6U);
  uint16_t transport_len = (uint16_t)(len - ip_len);
  uint32_t sum = pseudo_csum (proto, pkt + addr_at, pkt + addr_at + addr_len,
                              addr_len, transport_len);
  pkt[csum_at] = pkt[csum_at + 1] = 0;
  sum = csum (pkt + ip_len, transport_len, sum);
  pkt[csum_at] = (uint8_t)(~sum >> 8);
  pkt[csum_at + 1] = (uint8_t)~sum;
}

static bool
tun_vnet_setup (int fd, bool *vnet, bool *udp_gso)
{
  unsigned offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
  *vnet = false;
  *udp_gso = false;
  if (ioctl (fd, TUNSETOFFLOAD, offload) < 0)
    return false;
  *udp_gso = ioctl (fd, TUNSETOFFLOAD, offload | TUN_F_USO4 | TUN_F_USO6) == 0;
  *vnet = true;
  return true;
}

int
tun_open (const char *name, bool *vnet, bool *udp_gso)
{
  struct ifreq ifr = { 0 };
  int fd = open ("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    return -1;
  if (!vnet || !udp_gso)
    {
      close (fd);
      errno = EINVAL;
      return -1;
    }
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", name);
  if (ioctl (fd, TUNSETIFF, &ifr) < 0)
    {
      ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
      if (ioctl (fd, TUNSETIFF, &ifr) < 0)
        {
          close (fd);
          return -1;
        }
      *vnet = false;
      *udp_gso = false;
      return fd;
    }
  if (tun_vnet_setup (fd, vnet, udp_gso))
    return fd;
  close (fd);
  return -1;
}

int
tun_adopt (int fd, const char *name, bool *vnet, bool *udp_gso)
{
  struct ifreq ifr = { 0 };
  int flags;
  if (!vnet || !udp_gso)
    return -1;
  if (fd < 0 || ioctl (fd, (int)TUNGETIFF, &ifr) < 0
      || strncmp (ifr.ifr_name, name, IFNAMSIZ)
      || (flags = fcntl (fd, F_GETFL)) < 0
      || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0
      || (flags = fcntl (fd, F_GETFD)) < 0
      || fcntl (fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    return -1;
  *vnet = (ifr.ifr_flags & IFF_VNET_HDR) != 0;
  if (*vnet && !tun_vnet_setup (fd, vnet, udp_gso))
    return -1;
  if (!*vnet)
    *udp_gso = false;
  return fd;
}

int
tun_mtu (const char *name)
{
  struct ifreq ifr = { 0 };
  int fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  int mtu = DEFAULT_MTU;
  if (fd < 0)
    return mtu;
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", name);
  if (ioctl (fd, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu > 0)
    mtu = ifr.ifr_mtu;
  close (fd);
  return mtu > MAX_CONTENT_MTU ? MAX_CONTENT_MTU : mtu;
}

bool
tun_up (const char *name)
{
  struct ifreq ifr = { 0 };
  int fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  bool up = false;
  if (fd < 0)
    return false;
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", name);
  if (ioctl (fd, SIOCGIFFLAGS, &ifr) == 0)
    up = (ifr.ifr_flags & IFF_UP) != 0;
  close (fd);
  return up;
}

int
tun_watch_open (void)
{
  struct sockaddr_nl sa = {
    .nl_family = AF_NETLINK,
    .nl_groups = RTMGRP_LINK,
  };
  int fd = socket (AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                   NETLINK_ROUTE);
  if (fd < 0)
    return -1;
  if (bind (fd, (struct sockaddr *)&sa, sizeof (sa)) < 0)
    {
      close (fd);
      return -1;
    }
  return fd;
}

int
tun_watch_drain (int fd)
{
  uint8_t buf[8192];
  ssize_t n;
  bool changed = false;
  do
    n = recv (fd, buf, sizeof (buf), 0);
  while (n < 0 && errno == EINTR);
  if (n < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
  for (struct nlmsghdr *nlh = (void *)buf; NLMSG_OK (nlh, (unsigned)n);
       nlh = NLMSG_NEXT (nlh, n))
    if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK)
      changed = true;
  return changed;
}

ssize_t
tun_read (int fd, uint8_t *buf, size_t cap)
{
  ssize_t n;
  do
    n = read (fd, buf, cap);
  while (n < 0 && errno == EINTR);
  return n;
}

int
tun_gso_split (uint8_t *in, size_t len, uint8_t *out, size_t out_cap,
               TunPacketFn emit, void *arg)
{
  struct virtio_net_hdr hdr;
  uint8_t *pkt;
  size_t pkt_len, ip_len, transport_len, hdr_len, data_at, addr_len;
  uint16_t gso_size;
  uint8_t proto;
  bool v6, tcp;

  if (!in || !out || !emit || len < sizeof (hdr))
    return -1;
  memcpy (&hdr, in, sizeof (hdr));
  pkt = in + sizeof (hdr);
  pkt_len = len - sizeof (hdr);
  if (hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE)
    {
      if (hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
        {
          size_t csum_start = hdr.csum_start;
          size_t csum_offset = hdr.csum_offset;
          size_t at;
          if (csum_start > pkt_len || csum_offset > pkt_len - csum_start)
            return -1;
          at = csum_start + csum_offset;
          if (at + 1U >= pkt_len)
            return -1;
          uint16_t initial = (uint16_t)((uint16_t)pkt[at] << 8 | pkt[at + 1]);
          pkt[at] = pkt[at + 1] = 0;
          uint32_t sum = csum (pkt + hdr.csum_start,
                               pkt_len - hdr.csum_start, initial);
          uint16_t value = (uint16_t)~sum;
          pkt[at] = (uint8_t)(value >> 8);
          pkt[at + 1] = (uint8_t)value;
        }
      return emit (arg, pkt, pkt_len) ? 1 : -1;
    }
  if (pkt_len < 20 || !hdr.gso_size)
    return -1;
  v6 = (pkt[0] >> 4) == 6;
  if (!v6 && (pkt[0] >> 4) != 4)
    return -1;
  if (v6)
    {
      ip_len = 40;
      addr_len = 16;
      if (pkt_len < ip_len)
        return -1;
      proto = pkt[6];
      if (((size_t)pkt[4] << 8 | pkt[5]) != pkt_len - ip_len)
        return -1;
    }
  else
    {
      ip_len = (size_t)(pkt[0] & 15U) * 4U;
      addr_len = 4;
      proto = pkt[9];
      if (ip_len < 20 || ip_len > pkt_len)
        return -1;
      if (((size_t)pkt[2] << 8 | pkt[3]) != pkt_len)
        return -1;
    }
  tcp = hdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV4
        || hdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV6;
  if ((tcp && proto != IPPROTO_TCP) || (!tcp && proto != IPPROTO_UDP)
      || (!tcp && hdr.gso_type != VIRTIO_NET_HDR_GSO_UDP_L4)
      || (v6 && hdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV4)
      || (!v6 && hdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV6))
    return -1;
  if (hdr.csum_start != ip_len)
    return -1;
  if (ip_len + (tcp ? 20U : 8U) > pkt_len)
    return -1;
  transport_len = tcp ? (size_t)(pkt[ip_len + 12] >> 4) * 4U : 8U;
  hdr_len = ip_len + transport_len;
  if (transport_len < (tcp ? 20U : 8U) || hdr_len > pkt_len || hdr.gso_size > pkt_len - hdr_len)
    return -1;
  size_t payload_len = pkt_len - hdr_len;
  if (1U + (payload_len - 1U) / hdr.gso_size > TUN_GSO_MAX_SEGMENTS)
    return -1;
  data_at = hdr_len;
  gso_size = hdr.gso_size;
  size_t emitted = 0;
  for (; data_at < pkt_len; emitted++)
    {
      size_t data_len = pkt_len - data_at;
      if (data_len > gso_size)
        data_len = gso_size;
      size_t total = hdr_len + data_len;
      if (total > out_cap || total > UINT16_MAX)
        return -1;
      memcpy (out, pkt, hdr_len);
      memcpy (out + hdr_len, pkt + data_at, data_len);
      if (v6)
        {
          uint16_t payload = (uint16_t)(total - ip_len);
          out[4] = (uint8_t)(payload >> 8);
          out[5] = (uint8_t)payload;
        }
      else
        {
          uint16_t id = (uint16_t)(((uint16_t)out[4] << 8) | out[5]);
          out[2] = (uint8_t)(total >> 8);
          out[3] = (uint8_t)total;
          id = (uint16_t)(id + emitted);
          out[4] = (uint8_t)(id >> 8);
          out[5] = (uint8_t)id;
          out[10] = out[11] = 0;
          uint16_t ipcsum = (uint16_t)~csum (out, ip_len, 0);
          out[10] = (uint8_t)(ipcsum >> 8);
          out[11] = (uint8_t)ipcsum;
        }
      if (tcp)
        {
          uint32_t seq = ((uint32_t)pkt[ip_len + 4] << 24)
                         | ((uint32_t)pkt[ip_len + 5] << 16)
                         | ((uint32_t)pkt[ip_len + 6] << 8) | pkt[ip_len + 7];
          seq += (uint32_t)(emitted * gso_size);
          out[ip_len + 4] = (uint8_t)(seq >> 24);
          out[ip_len + 5] = (uint8_t)(seq >> 16);
          out[ip_len + 6] = (uint8_t)(seq >> 8);
          out[ip_len + 7] = (uint8_t)seq;
          if (data_at + data_len != pkt_len)
            out[ip_len + 13] &= (uint8_t)~(0x01U | 0x08U);
        }
      else
        {
          uint16_t udp_len = (uint16_t)(transport_len + data_len);
          out[ip_len + 4] = (uint8_t)(udp_len >> 8);
          out[ip_len + 5] = (uint8_t)udp_len;
        }
      size_t csum_at = ip_len + hdr.csum_offset;
      if (csum_at + 1 >= total)
        return -1;
      out[csum_at] = out[csum_at + 1] = 0;
      uint16_t plen = (uint16_t)(transport_len + data_len);
      uint32_t sum = pseudo_csum (proto, out + (v6 ? 8 : 12),
                                  out + (v6 ? 24 : 16), addr_len, plen);
      uint16_t transport_csum = (uint16_t)~csum (out + ip_len, plen, sum);
      out[csum_at] = (uint8_t)(transport_csum >> 8);
      out[csum_at + 1] = (uint8_t)transport_csum;
      if (!emit (arg, out, total))
        return -1;
      data_at += data_len;
    }
  return (int)emitted;
}

int
tun_gro_tcp (uint8_t *first, size_t cap, size_t *first_len, uint16_t *gso_size,
             uint16_t *merged_count, const uint8_t *next, size_t next_len)
{
  size_t ip_len, tcp_len, next_ip_len, next_tcp_len, first_payload,
      next_payload, merged;
  bool v6;
  uint8_t proto;

  uint8_t first_flags, next_flags, final_flags;
  if (!first || !first_len || !gso_size || !merged_count || !next
      || *first_len < 40 || next_len < 40
      || *first_len > cap || *first_len > UINT16_MAX || next_len > UINT16_MAX)
    return 0;
  v6 = (first[0] >> 4) == 6;
  if ((next[0] >> 4) != (first[0] >> 4))
    return 0;
  ip_len = v6 ? 40U : (size_t)(first[0] & 15U) * 4U;
  proto = IPPROTO_TCP;
  if (!gro_packet_valid (first, *first_len, v6, proto, &ip_len, &tcp_len,
                         false)
      || !gro_packet_valid (next, next_len, v6, proto, &next_ip_len,
                            &next_tcp_len, false)
      || ip_len != next_ip_len)
    return 0;
  if (!gro_checksum_valid (first, *first_len, ip_len, v6, IPPROTO_TCP))
    return -1;
  if (!gro_checksum_valid (next, next_len, next_ip_len, v6, IPPROTO_TCP))
    return -2;
  if (tcp_len != next_tcp_len)
    return 0;
  if (memcmp (first + (v6 ? 8 : 12), next + (v6 ? 8 : 12), v6 ? 32 : 8)
       || memcmp (first + ip_len, next + ip_len, 4)
       || memcmp (first + ip_len + 8, next + ip_len + 8, 4)
       || !gro_ip_headers_match (first, next, v6)
       || (tcp_len > 20 && memcmp (first + ip_len + 20, next + ip_len + 20,
                                    tcp_len - 20)))
    return 0;
  first_flags = first[ip_len + 13];
  next_flags = next[ip_len + 13];
  final_flags = next_flags;
  if ((first_flags != 0x10U && first_flags != 0x18U)
      || (next_flags != 0x10U && next_flags != 0x18U))
    return 0;
  first_payload = *first_len - ip_len - tcp_len;
  next_payload = next_len - ip_len - tcp_len;
  if (!*gso_size)
    *gso_size = (uint16_t)first_payload;
  if (!first_payload || !next_payload || *first_len + next_payload > PKT_MAX)
    return 0;
  if (*first_len + next_payload > cap)
    return -3;
  if (get32 (first + ip_len + 4) + (uint32_t)first_payload
      == get32 (next + ip_len + 4))
    {
      if (next_payload > *gso_size || first_payload % *gso_size
          || (first_flags & 0x08U))
        return 0;
    }
  else if (get32 (next + ip_len + 4) + (uint32_t)next_payload
           == get32 (first + ip_len + 4))
    {
      uint8_t header[100];
      if ((next_flags & 0x08U) || next_payload < *gso_size
          || (next_payload > *gso_size && *merged_count))
        return 0;
      memcpy (header, next, ip_len + tcp_len);
      memmove (first + ip_len + tcp_len + next_payload,
               first + ip_len + tcp_len, first_payload);
      memcpy (first + ip_len + tcp_len, next + ip_len + tcp_len, next_payload);
      memcpy (first, header, ip_len + tcp_len);
      merged = *first_len + next_payload;
      final_flags = first_flags;
      if (next_payload > *gso_size)
        *gso_size = (uint16_t)next_payload;
      goto account;
    }
  else
    return 0;
  merged = *first_len + next_payload;
  memcpy (first + *first_len, next + ip_len + tcp_len, next_payload);
account:
  if (v6)
    {
      uint16_t payload = (uint16_t)(merged - ip_len);
      first[4] = (uint8_t)(payload >> 8);
      first[5] = (uint8_t)payload;
    }
  else
    {
      first[2] = (uint8_t)(merged >> 8);
      first[3] = (uint8_t)merged;
      first[10] = first[11] = 0;
      uint16_t ipcsum = (uint16_t)~csum (first, ip_len, 0);
      first[10] = (uint8_t)(ipcsum >> 8);
      first[11] = (uint8_t)ipcsum;
    }
  first[ip_len + 13] = final_flags;
  gro_update_checksum (first, merged, ip_len, v6, IPPROTO_TCP);
  *first_len = merged;
  (*merged_count)++;
  return *gso_size;
}

int
tun_gro_udp (uint8_t *first, size_t cap, size_t *first_len, uint16_t *gso_size,
             uint16_t *merged_count, const uint8_t *next, size_t next_len)
{
  size_t ip_len, udp_len, next_ip_len, next_udp_len, first_payload,
      next_payload, merged;
  bool v6;

  if (!first || !first_len || !gso_size || !merged_count || !next
      || *first_len < 28 || next_len < 28
      || *first_len > cap || *first_len > UINT16_MAX || next_len > UINT16_MAX)
    return 0;
  v6 = (first[0] >> 4) == 6;
  if ((next[0] >> 4) != (first[0] >> 4))
    return 0;
  ip_len = v6 ? 40U : (size_t)(first[0] & 15U) * 4U;
  if (!gro_packet_valid (first, *first_len, v6, IPPROTO_UDP, &ip_len,
                         &udp_len, false)
      || !gro_packet_valid (next, next_len, v6, IPPROTO_UDP, &next_ip_len,
                            &next_udp_len, false)
      || udp_len != 8U || next_udp_len != 8U || ip_len != next_ip_len
       || memcmp (first + (v6 ? 8 : 12), next + (v6 ? 8 : 12), v6 ? 32 : 8)
       || memcmp (first + ip_len, next + ip_len, 4)
      || !gro_ip_headers_match (first, next, v6))
    return 0;
  if (!gro_checksum_valid (first, *first_len, ip_len, v6, IPPROTO_UDP))
    return -1;
  if (!gro_checksum_valid (next, next_len, next_ip_len, v6, IPPROTO_UDP))
    return -2;
  first_payload = *first_len - ip_len - 8U;
  next_payload = next_len - ip_len - 8U;
  if (!*gso_size)
    *gso_size = (uint16_t)first_payload;
  if (!first_payload || !next_payload || next_payload > *gso_size
      || first_payload % *gso_size || *first_len + next_payload > PKT_MAX)
    return 0;
  if (*first_len + next_payload > cap)
    return -3;
  merged = *first_len + next_payload;
  memcpy (first + *first_len, next + ip_len + 8U, next_payload);
  if (v6)
    {
      uint16_t payload = (uint16_t)(merged - ip_len);
      first[4] = (uint8_t)(payload >> 8);
      first[5] = (uint8_t)payload;
    }
  else
    {
      first[2] = (uint8_t)(merged >> 8);
      first[3] = (uint8_t)merged;
      first[10] = first[11] = 0;
      uint16_t ipcsum = (uint16_t)~csum (first, ip_len, 0);
      first[10] = (uint8_t)(ipcsum >> 8);
      first[11] = (uint8_t)ipcsum;
    }
  uint16_t udp_total_len = (uint16_t)(merged - ip_len);
  first[ip_len + 4] = (uint8_t)(udp_total_len >> 8);
  first[ip_len + 5] = (uint8_t)udp_total_len;
  gro_update_checksum (first, merged, ip_len, v6, IPPROTO_UDP);
  *first_len = merged;
  (*merged_count)++;
  return *gso_size;
}

bool
tun_gro_udp_flow (const uint8_t *first, size_t first_len,
                  const uint8_t *next, size_t next_len)
{
  bool v6;
  size_t ip_len, next_ip_len;
  size_t udp_len, next_udp_len;
  if (!first || !next || first_len < 28U || next_len < 28U)
    return false;
  v6 = (first[0] >> 4) == 6;
  if ((next[0] >> 4) != (first[0] >> 4)
      || !gro_packet_valid (first, first_len, v6, IPPROTO_UDP, &ip_len,
                            &udp_len, false)
      || !gro_packet_valid (next, next_len, v6, IPPROTO_UDP, &next_ip_len,
                            &next_udp_len, false)
      || udp_len != 8U || next_udp_len != 8U || ip_len != next_ip_len)
    return false;
  return !memcmp (first + (v6 ? 8 : 12), next + (v6 ? 8 : 12),
                  v6 ? 32 : 8)
         && !memcmp (first + ip_len, next + ip_len, 4);
}

ssize_t
tun_write (int fd, bool vnet, uint8_t *buf, size_t len)
{
  return tun_write_gso (fd, vnet, buf, len, 0);
}

ssize_t
tun_write_gso (int fd, bool vnet, uint8_t *buf, size_t len,
               uint16_t gso_size)
{
  ssize_t n;
  uint8_t hdr[TUN_VNET_HDR_LEN] = { 0 };
  struct virtio_net_hdr *v = (void *)hdr;
  if (vnet && gso_size)
    {
      bool v6;
      size_t ip_len;
      uint8_t proto;
      size_t transport_len;
      if (!buf || !len || len > UINT16_MAX)
        {
          errno = EINVAL;
          return -1;
        }
      v6 = (buf[0] >> 4) == 6;
      ip_len = v6 ? 40U : (size_t)(buf[0] & 15U) * 4U;
      if ((v6 && len < 40U) || (!v6 && ((buf[0] >> 4) != 4 || ip_len < 20U))
          || ip_len > len)
        {
          errno = EINVAL;
          return -1;
        }
      proto = buf[v6 ? 6 : 9];
      if (proto == IPPROTO_TCP)
        {
          if (ip_len + 20U > len)
            {
              errno = EINVAL;
              return -1;
            }
          transport_len = (size_t)(buf[ip_len + 12] >> 4) * 4U;
          if (transport_len < 20U || transport_len > 60U)
            {
              errno = EINVAL;
              return -1;
            }
          v->gso_type = v6 ? VIRTIO_NET_HDR_GSO_TCPV6
                            : VIRTIO_NET_HDR_GSO_TCPV4;
          v->csum_offset = 16;
        }
      else if (proto == IPPROTO_UDP)
        {
          transport_len = 8;
          v->gso_type = VIRTIO_NET_HDR_GSO_UDP_L4;
          v->csum_offset = 6;
        }
      else
        {
          errno = EINVAL;
          return -1;
        }
      if (ip_len + transport_len > len)
        {
          errno = EINVAL;
          return -1;
        }
      if (gso_size > len - ip_len - transport_len)
        {
          errno = EINVAL;
          return -1;
        }
      v->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      v->hdr_len = (uint16_t)(ip_len + transport_len);
      v->gso_size = gso_size;
      v->csum_start = (uint16_t)ip_len;
      if (v->hdr_len > len)
        {
          errno = EINVAL;
          return -1;
        }
      size_t addr_len = v6 ? 16U : 4U;
      size_t addr_at = v6 ? 8U : 12U;
      uint16_t plen = (uint16_t)(len - ip_len);
      uint16_t pseudo = csum (NULL, 0,
                              pseudo_csum (proto, buf + addr_at,
                                           buf + addr_at + addr_len, addr_len,
                                           plen));
      buf[ip_len + v->csum_offset] = (uint8_t)(pseudo >> 8);
      buf[ip_len + v->csum_offset + 1U] = (uint8_t)pseudo;
    }
  struct iovec iov[2] = {
    { .iov_base = hdr, .iov_len = vnet ? sizeof (hdr) : 0 },
    { .iov_base = (void *)buf, .iov_len = len },
  };
  do
    n = writev (fd, iov + (vnet ? 0 : 1), vnet ? 2 : 1);
  while (n < 0 && errno == EINTR);
  return n < 0 ? n : n - (vnet ? (ssize_t)sizeof (hdr) : 0);
}
