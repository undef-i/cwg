#include "work.h"
#include "device.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <unistd.h>

enum
{
  SLOT_N = 2048,
  SLOT_PER_TYPE = SLOT_N / 2,
  BATCH_N = 16,
  SLOT_RESERVED,
  SLOT_READY,
  SLOT_DONE,
  SLOT_FREE,
};

typedef struct
{
  pthread_mutex_t lock;
  pthread_cond_t ready;
  pthread_cond_t drained;
  pthread_cond_t space;
  pthread_t *thread;
  int event;
  WorkJob slot[SLOT_N];
  unsigned freeq[2][SLOT_PER_TYPE];
  unsigned readyq[SLOT_N];
  unsigned doneq[SLOT_N];
  unsigned free_head[2], free_n[2];
  unsigned ready_head, ready_n;
  unsigned done_head, done_n;
  unsigned active;
  unsigned nthread;
  bool stopping;
  void (*run) (WorkJob *);
  void (*commit) (WorkJob *);
} Pool;

static Pool g;

static unsigned
workers_get (void)
{
  const char *s = getenv ("WG_WORKERS");
  long n = sysconf (_SC_NPROCESSORS_ONLN);
  char *end;
  unsigned long v;

  if (s && *s)
    {
      errno = 0;
      v = strtoul (s, &end, 10);
      if (!errno && !*end && v <= 256U)
        return (unsigned)v;
    }
  if (n < 1)
    n = 1;
  return (unsigned)n;
}

static void *
worker (void *arg)
{
  unsigned idx[BATCH_N];
  (void)arg;
  for (;;)
    {
      unsigned n = 0;
      pthread_mutex_lock (&g.lock);
      while (!g.ready_n && !g.stopping)
        pthread_cond_wait (&g.ready, &g.lock);
      if (!g.ready_n && g.stopping)
        {
          pthread_mutex_unlock (&g.lock);
          return NULL;
        }
      while (n < BATCH_N && g.ready_n)
        {
          idx[n++] = g.readyq[g.ready_head];
          g.ready_head = (g.ready_head + 1U) % SLOT_N;
          g.ready_n--;
        }
      pthread_mutex_unlock (&g.lock);

      for (unsigned i = 0; i < n; i++)
        g.run (&g.slot[idx[i]]);

      pthread_mutex_lock (&g.lock);
      for (unsigned i = 0; i < n; i++)
        {
          unsigned tail = (g.done_head + g.done_n) % SLOT_N;
          atomic_store_explicit (&g.slot[idx[i]].state, SLOT_DONE,
                                 memory_order_release);
          g.doneq[tail] = idx[i];
          g.done_n++;
        }
      pthread_cond_broadcast (&g.drained);
      pthread_mutex_unlock (&g.lock);
      uint64_t one = 1;
      write (g.event, &one, sizeof (one));
    }
}

int
work_start (void (*run) (WorkJob *), void (*commit) (WorkJob *))
{
  unsigned made = 0;
  memset (&g, 0, sizeof (g));
  g.event = -1;
  if (pthread_mutex_init (&g.lock, NULL) || pthread_cond_init (&g.ready, NULL)
      || pthread_cond_init (&g.drained, NULL)
      || pthread_cond_init (&g.space, NULL))
    return -1;
  g.run = run;
  g.commit = commit;
  g.event = eventfd (0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (g.event < 0)
    return -1;
  g.nthread = workers_get ();
  g.free_n[WORK_OUT] = SLOT_PER_TYPE;
  g.free_n[WORK_IN] = SLOT_PER_TYPE;
  for (unsigned i = 0; i < SLOT_PER_TYPE; i++)
    {
      g.freeq[WORK_OUT][i] = i;
      g.freeq[WORK_IN][i] = SLOT_PER_TYPE + i;
    }
  if (!g.nthread)
    return 0;
  g.thread = calloc (g.nthread, sizeof (*g.thread));
  if (!g.thread)
    goto fail;
  for (; made < g.nthread; made++)
    if (pthread_create (&g.thread[made], NULL, worker, NULL))
      goto fail;
  return 0;

fail:
  pthread_mutex_lock (&g.lock);
  g.stopping = true;
  pthread_cond_broadcast (&g.ready);
  pthread_mutex_unlock (&g.lock);
  while (made)
    pthread_join (g.thread[--made], NULL);
  free (g.thread);
  g.thread = NULL;
  g.nthread = 0;
  return -1;
}

WorkJob *
work_reserve (unsigned type)
{
  unsigned idx;
  WorkJob *j;
  if (!g.nthread || type > WORK_IN)
    return NULL;
  pthread_mutex_lock (&g.lock);
  if (g.stopping || !g.free_n[type])
    {
      pthread_mutex_unlock (&g.lock);
      return NULL;
    }
  idx = g.freeq[type][g.free_head[type]];
  g.free_head[type] = (g.free_head[type] + 1U) % SLOT_PER_TYPE;
  g.free_n[type]--;
  j = &g.slot[idx];
  atomic_store_explicit (&j->state, SLOT_RESERVED, memory_order_relaxed);
  pthread_mutex_unlock (&g.lock);
  return j;
}

void
work_release (WorkJob *j, unsigned type)
{
  unsigned idx, tail;
  if (!j || type > WORK_IN)
    return;
  idx = (unsigned)(j - g.slot);
  pthread_mutex_lock (&g.lock);
  atomic_store_explicit (&j->state, SLOT_FREE, memory_order_release);
  tail = (g.free_head[type] + g.free_n[type]) % SLOT_PER_TYPE;
  g.freeq[type][tail] = idx;
  g.free_n[type]++;
  pthread_cond_signal (&g.space);
  pthread_mutex_unlock (&g.lock);
}

void
work_submit (WorkJob *j)
{
  unsigned idx, tail;
  if (!j || j->type > WORK_IN || j->len > sizeof (j->buf))
    return;
  idx = (unsigned)(j - g.slot);
  pthread_mutex_lock (&g.lock);
  j->next = NULL;
  if (j->owner->work_tail[j->type])
    j->owner->work_tail[j->type]->next = j;
  else
    j->owner->work_head[j->type] = j;
  j->owner->work_tail[j->type] = j;
  atomic_store_explicit (&j->state, SLOT_READY, memory_order_release);
  tail = (g.ready_head + g.ready_n) % SLOT_N;
  g.readyq[tail] = idx;
  g.ready_n++;
  g.active++;
  pthread_cond_signal (&g.ready);
  pthread_mutex_unlock (&g.lock);
}

int
work_fd (void)
{
  return g.event;
}

int
work_hnd (void)
{
  uint64_t value;
  while (read (g.event, &value, sizeof (value)) > 0)
    ;
  for (;;)
    {
      unsigned idx;
      WorkJob *j;
      pthread_mutex_lock (&g.lock);
      if (!g.done_n)
        {
          pthread_mutex_unlock (&g.lock);
          break;
        }
      idx = g.doneq[g.done_head];
      g.done_head = (g.done_head + 1U) % SLOT_N;
      g.done_n--;
      pthread_mutex_unlock (&g.lock);

      j = &g.slot[idx];
      if (atomic_load_explicit (&j->state, memory_order_acquire) != SLOT_DONE)
        continue;
      Peer *p = j->owner;
      unsigned type = j->type;
      while ((j = p->work_head[type])
             && atomic_load_explicit (&j->state, memory_order_acquire)
                    == SLOT_DONE)
        {
          p->work_head[type] = j->next;
          if (!p->work_head[type])
            p->work_tail[type] = NULL;
          g.commit (j);
          atomic_fetch_sub_explicit (&p->work_ref, 1, memory_order_release);
          work_release (j, type);
          pthread_mutex_lock (&g.lock);
          g.active--;
          if (!g.active)
            pthread_cond_broadcast (&g.drained);
          pthread_mutex_unlock (&g.lock);
        }
    }
  return 0;
}

void
work_drain (void)
{
  struct pollfd pfd = { 0 };
  if (!g.nthread)
    return;
  pfd.fd = g.event;
  pfd.events = POLLIN;
  pthread_mutex_lock (&g.lock);
  while (g.active)
    {
      pthread_mutex_unlock (&g.lock);
      work_hnd ();
      pthread_mutex_lock (&g.lock);
      bool done = !g.active;
      pthread_mutex_unlock (&g.lock);
      if (done)
        break;
      poll (&pfd, 1, -1);
      pthread_mutex_lock (&g.lock);
    }
  pthread_mutex_unlock (&g.lock);
}

void
work_stop (void)
{
  if (g.nthread)
    {
      work_drain ();
      pthread_mutex_lock (&g.lock);
      g.stopping = true;
      pthread_cond_broadcast (&g.ready);
      pthread_mutex_unlock (&g.lock);
      for (unsigned i = 0; i < g.nthread; i++)
        pthread_join (g.thread[i], NULL);
    }
  free (g.thread);
  if (g.event >= 0)
    close (g.event);
  pthread_cond_destroy (&g.drained);
  pthread_cond_destroy (&g.ready);
  pthread_cond_destroy (&g.space);
  pthread_mutex_destroy (&g.lock);
  memset (&g, 0, sizeof (g));
}

unsigned
work_count (void)
{
  return g.nthread;
}
