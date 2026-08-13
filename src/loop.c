#include "loop.h"
#include "ctl.h"
#include "data.h"
#include "tun.h"
#include "uapi.h"
#include "work.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

static bool
socket_alive (const Dev *d)
{
  struct stat st;
  return d->sock[0] && !lstat (d->sock, &st) && S_ISSOCK (st.st_mode);
}

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
  FD_UDP_EVENT,
  FD_INOTIFY,
  FD_WORK,
  FD_LINK,
  FD_TIMER,
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
      if (d->udp_event == fd)
        {
          *kind = FD_UDP_EVENT;
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
  epoll_ctl (ep, EPOLL_CTL_DEL, d->udp_old4, NULL);
  epoll_ctl (ep, EPOLL_CTL_DEL, d->udp_old6, NULL);
  epoll_ctl (ep, EPOLL_CTL_DEL, d->udp_event, NULL);
  uapi_close (d);
  close (d->tun);
  dbg ("(%s) del", d->name);
  dev_free (d);
}

static int
udp_sync (Dev *d, int ep, struct epoll_event *ev)
{
  int rc = 0;
  pthread_rwlock_wrlock (&d->lock);
  if (d->udp_seen == d->udp_gen)
    goto out;
  epoll_ctl (ep, EPOLL_CTL_DEL, d->udp_old4, NULL);
  epoll_ctl (ep, EPOLL_CTL_DEL, d->udp_old6, NULL);
  udp_close (d->udp_old4, d->udp_old6);
  d->udp_old4 = d->udp_old6 = -1;
  if (d->udp4 >= 0)
    {
      ev->data.fd = d->udp4;
      if (epoll_ctl (ep, EPOLL_CTL_ADD, d->udp4, ev) < 0)
        {
          rc = -1;
          goto out;
        }
    }
  if (d->udp6 >= 0)
    {
      ev->data.fd = d->udp6;
      if (epoll_ctl (ep, EPOLL_CTL_ADD, d->udp6, ev) < 0)
        {
          rc = -1;
          goto out;
        }
    }
  d->udp_seen = d->udp_gen;
out:
  pthread_rwlock_unlock (&d->lock);
  return rc;
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
  int ino = inotify_init1 (IN_CLOEXEC | IN_NONBLOCK);
  int link = tun_watch_open ();
  int timer = timerfd_create (CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
  int wg_watch = -1, awg_watch = -1;
  if (ep < 0 || ino < 0 || link < 0 || timer < 0 || !buf || !pkt)
    {
      free (pkt);
      free (buf);
      if (ep >= 0)
        close (ep);
      if (ino >= 0)
        close (ino);
      if (link >= 0)
        close (link);
      if (timer >= 0)
        close (timer);
      return -1;
    }
  if (work_start (data_work, data_commit) < 0)
    {
      close (ep);
      close (ino);
      close (link);
      close (timer);
      free (pkt);
      free (buf);
      return -1;
    }

  ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
  ev.data.fd = ctl;
  if (ctl >= 0 && epoll_ctl (ep, EPOLL_CTL_ADD, ctl, &ev) < 0)
    goto fail;
  if ((mkdir (WG_SOCKET_DIR, 0755) < 0 && errno != EEXIST)
      || (mkdir (AWG_SOCKET_DIR, 0755) < 0 && errno != EEXIST)
      || (wg_watch = inotify_add_watch (ino, WG_SOCKET_DIR, IN_DELETE)) < 0
      || (awg_watch = inotify_add_watch (ino, AWG_SOCKET_DIR, IN_DELETE)) < 0)
    goto fail;
  ev.data.fd = ino;
  if (epoll_ctl (ep, EPOLL_CTL_ADD, ino, &ev) < 0)
    goto fail;
  ev.data.fd = link;
  if (epoll_ctl (ep, EPOLL_CTL_ADD, link, &ev) < 0)
    goto fail;
  ev.data.fd = timer;
  if (epoll_ctl (ep, EPOLL_CTL_ADD, timer, &ev) < 0)
    goto fail;
  for (Dev *d = head; d; d = d->next)
    if (!socket_alive (d))
      goto fail;
  ev.data.fd = work_fd ();
  if (epoll_ctl (ep, EPOLL_CTL_ADD, work_fd (), &ev) < 0)
    goto fail;
  for (Dev *d = head; d; d = d->next)
    {
      ev.data.fd = d->tun;
      if (epoll_ctl (ep, EPOLL_CTL_ADD, d->tun, &ev) < 0)
        goto fail;
      ev.data.fd = d->uapi;
      if (epoll_ctl (ep, EPOLL_CTL_ADD, d->uapi, &ev) < 0)
        goto fail;
      if (d->udp4 >= 0)
        {
          ev.data.fd = d->udp4;
          if (epoll_ctl (ep, EPOLL_CTL_ADD, d->udp4, &ev) < 0)
            goto fail;
        }
      if (d->udp6 >= 0)
        {
          ev.data.fd = d->udp6;
          if (epoll_ctl (ep, EPOLL_CTL_ADD, d->udp6, &ev) < 0)
            goto fail;
        }
      ev.data.fd = d->udp_event;
      if (epoll_ctl (ep, EPOLL_CTL_ADD, d->udp_event, &ev) < 0)
        goto fail;
      d->udp_seen = d->udp_gen;
    }

  while (!g_stop && head)
    {
      uint64_t now = data_now (), next = 0;
      for (Dev *d = head; d; d = d->next)
        {
          pthread_rwlock_rdlock (&d->lock);
          uint64_t due = data_next_due (d, now);
          pthread_rwlock_unlock (&d->lock);
          if (due && (!next || due < next))
            next = due;
        }
      struct itimerspec its = { 0 };
      if (next)
        {
          its.it_value.tv_sec = (time_t)(next / 1000U);
          its.it_value.tv_nsec = (long)(next % 1000U) * 1000000L;
        }
      if (timerfd_settime (timer, TFD_TIMER_ABSTIME, &its, NULL) < 0)
        goto fail;
      int n = epoll_wait (ep, arr, 64, -1);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          goto fail;
        }
      for (int i = 0; i < n; i++)
        {
          int kind = FD_NONE;
          if (ctl >= 0 && arr[i].data.fd == ctl)
            {
              if (ctl_hnd (ctl, &head, ep) < 0)
                goto fail;
              continue;
            }
          if (arr[i].data.fd == ino)
            {
              char ibuf[sizeof (struct inotify_event) + 256];
              ssize_t nr;
              while ((nr = read (ino, ibuf, sizeof (ibuf))) > 0)
                for (size_t off = 0; off < (size_t)nr;)
                  {
                    struct inotify_event *ie
                        = (struct inotify_event *)(ibuf + off);
                    Dev *d;
                    if (ie->mask & IN_Q_OVERFLOW)
                      {
                        for (d = head; d;)
                          {
                            Dev *next = d->next;
                            if (!socket_alive (d))
                              dev_del (&head, d, ep);
                            d = next;
                          }
                        off += sizeof (*ie) + ie->len;
                        continue;
                      }
                    for (d = head; d; d = d->next)
                        {
                          const char *base = strrchr (d->sock, '/');
                          bool same_dir
                              = (ie->wd == wg_watch
                                 && !strcmp (d->socket_dir, WG_SOCKET_DIR))
                                || (ie->wd == awg_watch
                                    && !strcmp (d->socket_dir,
                                                AWG_SOCKET_DIR));
                          if ((ie->mask & IN_DELETE) && ie->len && base
                              && same_dir && !strcmp (ie->name, base + 1))
                            {
                              dev_del (&head, d, ep);
                              break;
                            }
                        }
                    off += sizeof (*ie) + ie->len;
                  }
              if (nr < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                goto fail;
              continue;
            }
          if (arr[i].data.fd == link)
            {
              if (tun_watch_drain (link) < 0)
                goto fail;
              for (Dev *d = head; d;)
                {
                  Dev *next = d->next;
                  d->mtu = tun_mtu (d->name);
                  if (dev_up (d, tun_up (d->name)) < 0)
                    dev_del (&head, d, ep);
                  d = next;
                }
              continue;
            }
          if (arr[i].data.fd == timer)
            {
              uint64_t expirations;
              while (read (timer, &expirations, sizeof (expirations)) > 0)
                ;
              continue;
            }
          if (arr[i].data.fd == work_fd ())
            {
              work_hnd ();
              continue;
            }
          Dev *d = dev_fd (head, arr[i].data.fd, &kind);
          if (!d)
            continue;
          if (kind == FD_UAPI)
            {
              if (uapi_hnd (d) < 0)
                dev_del (&head, d, ep);
              else if (udp_sync (d, ep, &ev) < 0)
                goto fail;
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
          if (kind == FD_UDP_EVENT)
            {
              uint64_t value;
              while (read (d->udp_event, &value, sizeof (value)) > 0)
                ;
              if (udp_sync (d, ep, &ev) < 0)
                goto fail;
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
      now = data_now ();
      for (Dev *d = head; d;)
        {
          Dev *next = d->next;
          if (!socket_alive (d))
            dev_del (&head, d, ep);
          else
            {
                if (udp_sync (d, ep, &ev) < 0)
                  goto fail;
              pthread_rwlock_wrlock (&d->lock);
              data_tick (d, now);
              dev_reap (d);
              pthread_rwlock_unlock (&d->lock);
            }
          d = next;
        }
    }
  dev_all_del (&head, ep);
  work_stop ();
  close (ino);
  close (link);
  close (timer);
  close (ep);
  free (pkt);
  free (buf);
  return 0;

fail:
  dev_all_del (&head, ep);
  work_stop ();
  close (ino);
  close (link);
  close (timer);
  close (ep);
  free (pkt);
  free (buf);
  return -1;
}
