#include "tun.h"
#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
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

enum { DEFAULT_MTU = 1420, MAX_CONTENT_MTU = PKT_MAX - 32U };

int
tun_open (const char *name)
{
  struct ifreq ifr = { 0 };
  int fd = open ("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    return -1;
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", name);
  if (ioctl (fd, TUNSETIFF, &ifr) < 0)
    {
      close (fd);
      return -1;
    }
  return fd;
}

int
tun_adopt (int fd, const char *name)
{
  struct ifreq ifr = { 0 };
  int flags;
  if (fd < 0 || ioctl (fd, (int)TUNGETIFF, &ifr) < 0
      || strncmp (ifr.ifr_name, name, IFNAMSIZ)
      || (flags = fcntl (fd, F_GETFL)) < 0
      || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0
      || (flags = fcntl (fd, F_GETFD)) < 0
      || fcntl (fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    return -1;
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

ssize_t
tun_write (int fd, const uint8_t *buf, size_t len)
{
  ssize_t n;
  do
    n = write (fd, buf, len);
  while (n < 0 && errno == EINTR);
  return n;
}
