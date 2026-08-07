#include "tun.h"
#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
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
