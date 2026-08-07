#include "loop.h"
#include "ctl.h"
#include "data.h"
#include "tun.h"
#include "uapi.h"
#include "work.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

void
loop_stop (void)
{
  g_stop = 1;
}

enum
{
  FD_NONE,
  FD_TUN,
  FD_UAPI,
  FD_UDP,
};

static Dev *
dev_fd (Dev *head, int fd, int *kind)
{
  for (Dev *d = head; d; d = d->next)
    {
      if (d->tun == fd)
        {
          *kind = FD_TUN;
          return d;
        }
      if (d->uapi == fd)
        {
          *kind = FD_UAPI;
          return d;
        }
      if (d->udp4 == fd || d->udp6 == fd)
        {
          *kind = FD_UDP;
          return d;
        }
    }
  return NULL;
}

static void
dev_del (Dev **head, Dev *d, int ep)
{
  Dev **pp = head;
  while (*pp && *pp != d)
    pp = &(*pp)->next;
  if (!*pp)
    return;
  *pp = d->next;
  work_drain ();
  epoll_ctl (ep, EPOLL_CTL_DEL, d->tun, NULL);
  epoll_ctl (ep, EPOLL_CTL_DEL, d->uapi, NULL);
  epoll_ctl (ep, EPOLL_CTL_DEL, d->udp4, NULL);
  epoll_ctl (ep, EPOLL_CTL_DEL, d->udp6, NULL);
  uapi_close (d);
  close (d->tun);
  dbg ("(%s) del", d->name);
  dev_free (d);
}

static void
dev_all_del (Dev **head, int ep)
{
  while (*head)
    dev_del (head, *head, ep);
}

int
loop_run (Dev *head, int ctl)
{
  struct epoll_event ev, arr[64];
  uint8_t *buf = malloc (PKT_MAX);
  UdpPacket *pkt = calloc (UDP_BATCH_MAX, sizeof (*pkt));
  int ep = epoll_create1 (EPOLL_CLOEXEC);
  if (ep < 0 || !buf || !pkt)
    {
      free (pkt);
      free (buf);
      if (ep >= 0)
        close (ep);
      return -1;
    }
  if (work_start (data_work, data_commit) < 0)
    {
      close (ep);
      free (pkt);
      free (buf);
      return -1;
    }

  ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
  ev.data.fd = ctl;
  if (epoll_ctl (ep, EPOLL_CTL_ADD, ctl, &ev) < 0)
    goto fail;
  for (Dev *d = head; d; d = d->next)
    {
      ev.data.fd = d->tun;
      if (epoll_ctl (ep, EPOLL_CTL_ADD, d->tun, &ev) < 0)
        goto fail;
      ev.data.fd = d->uapi;
      if (epoll_ctl (ep, EPOLL_CTL_ADD, d->uapi, &ev) < 0)
        goto fail;
      ev.data.fd = d->udp4;
      if (epoll_ctl (ep, EPOLL_CTL_ADD, d->udp4, &ev) < 0)
        goto fail;
      ev.data.fd = d->udp6;
      if (epoll_ctl (ep, EPOLL_CTL_ADD, d->udp6, &ev) < 0)
        goto fail;
      d->udp_seen = d->udp_gen;
    }

  while (!g_stop && head)
    {
      int n = epoll_wait (ep, arr, 64, 1000);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          goto fail;
        }
      for (int i = 0; i < n; i++)
        {
          int kind = FD_NONE;
          if (arr[i].data.fd == ctl)
            {
              if (ctl_hnd (ctl, &head, ep) < 0)
                goto fail;
              continue;
            }
          Dev *d = dev_fd (head, arr[i].data.fd, &kind);
          if (!d)
            continue;
          if (kind == FD_UAPI)
            {
              if (uapi_hnd (d) < 0)
                dev_del (&head, d, ep);
              else if (d->udp_seen != d->udp_gen)
                {
                  ev.data.fd = d->udp4;
                  if (epoll_ctl (ep, EPOLL_CTL_ADD, d->udp4, &ev) < 0)
                    goto fail;
                  ev.data.fd = d->udp6;
                  if (epoll_ctl (ep, EPOLL_CTL_ADD, d->udp6, &ev) < 0)
                    goto fail;
                  d->udp_seen = d->udp_gen;
                }
              continue;
            }
          if (kind == FD_UDP)
            {
              for (;;)
                {
                  int nr = udp_recv_batch (arr[i].data.fd, pkt, UDP_BATCH_MAX);
                  if (nr > 0)
                    {
                      for (int k = 0; k < nr; k++)
                        if (pkt[k].len)
                          data_udp (d, &pkt[k].ep, pkt[k].buf, pkt[k].len);
                      continue;
                    }
                  if (!nr)
                    break;
                  if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                  if (errno == EINTR)
                    continue;
                  break;
                }
              continue;
            }
          if (arr[i].events & (EPOLLERR | EPOLLHUP))
            {
              dev_del (&head, d, ep);
              continue;
            }
          for (;;)
            {
              ssize_t nr = tun_read (d->tun, buf, PKT_MAX);
              if (nr > 0)
                {
                  data_tun (d, buf, (size_t)nr);
                  continue;
                }
              if (nr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
              if (nr < 0 && errno == EINTR)
                continue;
              dev_del (&head, d, ep);
              break;
            }
        }
      uint64_t now = data_now ();
      for (Dev *d = head; d; d = d->next)
        {
          pthread_rwlock_wrlock (&d->lock);
          data_tick (d, now);
          pthread_rwlock_unlock (&d->lock);
        }
    }
  dev_all_del (&head, ep);
  work_stop ();
  close (ep);
  free (pkt);
  free (buf);
  return 0;

fail:
  dev_all_del (&head, ep);
  work_stop ();
  close (ep);
  free (pkt);
  free (buf);
  return -1;
}
