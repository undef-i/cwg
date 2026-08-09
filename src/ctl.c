#include "ctl.h"
#include "tun.h"
#include "uapi.h"
#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static void
reply (int fd, int rc)
{
  char buf[32];
  int n = snprintf (buf, sizeof (buf), "errno=%d\n", rc);
  if (n > 0)
    {
      ssize_t wr = write (fd, buf, (size_t)n);
      (void)wr;
    }
}

static Dev *
dev_fnd (Dev *head, const char *name)
{
  for (Dev *d = head; d; d = d->next)
    if (!strcmp (d->name, name))
      return d;
  return NULL;
}

static int
dev_add (Dev **head, int ep, const char *name, const char *socket_dir)
{
  struct epoll_event ev = { .events = EPOLLIN | EPOLLERR | EPOLLHUP };
  Dev *d;

  if (!if_ok (name))
    return -EINVAL;
  if (dev_fnd (*head, name))
    return -EEXIST;
  d = dev_new (name);
  if (!d)
    return -ENOMEM;
  snprintf (d->socket_dir, sizeof (d->socket_dir), "%s", socket_dir);
  d->tun = tun_open (name);
  if (d->tun < 0)
    goto fail;
  if (uapi_open (d) < 0)
    goto fail;
  if (dev_bind (d, 0, 0) < 0)
    goto fail;
  ev.data.fd = d->tun;
  if (epoll_ctl (ep, EPOLL_CTL_ADD, d->tun, &ev) < 0)
    goto fail;
  ev.data.fd = d->uapi;
  if (epoll_ctl (ep, EPOLL_CTL_ADD, d->uapi, &ev) < 0)
    {
      epoll_ctl (ep, EPOLL_CTL_DEL, d->tun, NULL);
      goto fail;
    }
  ev.data.fd = d->udp4;
  if (epoll_ctl (ep, EPOLL_CTL_ADD, d->udp4, &ev) < 0)
    goto fail;
  ev.data.fd = d->udp6;
  if (epoll_ctl (ep, EPOLL_CTL_ADD, d->udp6, &ev) < 0)
    goto fail;
  d->udp_seen = d->udp_gen;
  d->next = *head;
  *head = d;
  dbg ("(%s) add", name);
  return 0;

fail:
  {
    int e = errno;
    uapi_close (d);
    if (d->tun >= 0)
      close (d->tun);
    dev_free (d);
    return -e;
  }
}

int
ctl_open (void)
{
  struct sockaddr_un sa = { .sun_family = AF_UNIX };
  mode_t old;
  int fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0)
    return -1;
  strcpy (sa.sun_path, CTL_PATH);
  old = umask (0077);
  if (bind (fd, (struct sockaddr *)&sa, sizeof (sa)) < 0)
    {
      int e = errno;
      umask (old);
      close (fd);
      errno = e;
      return -1;
    }
  umask (old);
  if (listen (fd, 16) < 0)
    {
      int e = errno;
      close (fd);
      unlink (CTL_PATH);
      errno = e;
      return -1;
    }
  return fd;
}

int
ctl_add (const char *name, const char *socket_dir)
{
  struct sockaddr_un sa = { .sun_family = AF_UNIX };
  char req[IFNAMSIZ + 48], res[32];
  int fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  strcpy (sa.sun_path, CTL_PATH);
  if (connect (fd, (struct sockaddr *)&sa, sizeof (sa)) < 0)
    {
      int e = errno;
      close (fd);
      errno = e;
      return -1;
    }
  int n = snprintf (req, sizeof (req), "add=%s:%s\n", socket_dir, name);
  if (n <= 0 || write (fd, req, (size_t)n) != n)
    {
      close (fd);
      errno = EIO;
      return -1;
    }
  n = (int)read (fd, res, sizeof (res) - 1U);
  close (fd);
  if (n <= 0)
    {
      errno = EIO;
      return -1;
    }
  res[n] = '\0';
  int rc;
  if (sscanf (res, "errno=%d", &rc) != 1)
    {
      errno = EPROTO;
      return -1;
    }
  if (rc)
    {
      errno = -rc;
      return -1;
    }
  return 0;
}

int
ctl_hnd (int fd, Dev **head, int ep)
{
  for (;;)
    {
      char buf[IFNAMSIZ + 48];
      int c = accept4 (fd, NULL, NULL, SOCK_CLOEXEC);
      if (c < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
      ssize_t n = read (c, buf, sizeof (buf) - 1U);
      int rc = -EPROTO;
      if (n > 0)
        {
          buf[n] = '\0';
          char *nl = strchr (buf, '\n');
          if (nl)
            *nl = '\0';
          if (!strncmp (buf, "add=", 4))
            {
              char *name = strrchr (buf + 4, ':');
              if (name)
                {
                  *name++ = '\0';
                  if (!strcmp (buf + 4, WG_SOCKET_DIR)
                      || !strcmp (buf + 4, AWG_SOCKET_DIR))
                    rc = dev_add (head, ep, name, buf + 4);
                }
            }
        }
      reply (c, rc);
      close (c);
    }
}

void
ctl_close (int fd)
{
  if (fd >= 0)
    {
      close (fd);
      unlink (CTL_PATH);
    }
}
