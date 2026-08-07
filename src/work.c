#include "work.h"
#include "device.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum
{
  SLOT_N = 256,
  BATCH_N = 16,
};

typedef struct
{
  pthread_mutex_t lock;
  pthread_cond_t ready;
  pthread_cond_t drained;
  pthread_cond_t space;
  pthread_t *thread;
  WorkJob slot[SLOT_N];
  unsigned freeq[SLOT_N];
  unsigned readyq[SLOT_N];
  unsigned free_head, free_n;
  unsigned ready_head, ready_n;
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
  return (unsigned)(n < 4 ? n : 4);
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
        {
          WorkJob *j = &g.slot[idx[i]];
          Dev *d = j->dev;
          unsigned type = j->type;
          g.run (j);
          pthread_mutex_lock (&d->work_lock[type]);
          while (j->seq != d->work_commit[type])
            pthread_cond_wait (&d->work_ready[type], &d->work_lock[type]);
          g.commit (j);
          d->work_commit[type]++;
          pthread_cond_broadcast (&d->work_ready[type]);
          pthread_mutex_unlock (&d->work_lock[type]);
        }

      pthread_mutex_lock (&g.lock);
      for (unsigned i = 0; i < n; i++)
        {
          unsigned tail = (g.free_head + g.free_n) % SLOT_N;
          g.freeq[tail] = idx[i];
          g.free_n++;
        }
      g.active -= n;
      if (!g.active)
        pthread_cond_broadcast (&g.drained);
      pthread_cond_broadcast (&g.space);
      pthread_mutex_unlock (&g.lock);
    }
}

int
work_start (void (*run) (WorkJob *), void (*commit) (WorkJob *))
{
  unsigned made = 0;
  memset (&g, 0, sizeof (g));
  if (pthread_mutex_init (&g.lock, NULL) || pthread_cond_init (&g.ready, NULL)
      || pthread_cond_init (&g.drained, NULL)
      || pthread_cond_init (&g.space, NULL))
    return -1;
  g.run = run;
  g.commit = commit;
  g.nthread = workers_get ();
  g.free_n = SLOT_N;
  for (unsigned i = 0; i < SLOT_N; i++)
    g.freeq[i] = i;
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

bool
work_submit (const WorkJob *job)
{
  unsigned idx, tail;
  WorkJob *j;
  if (!g.nthread || !job || job->type > WORK_IN
      || job->len > sizeof (g.slot[0].buf))
    return false;
  pthread_mutex_lock (&g.lock);
  while (!g.free_n && !g.stopping)
    pthread_cond_wait (&g.space, &g.lock);
  if (g.stopping)
    {
      pthread_mutex_unlock (&g.lock);
      return false;
    }
  idx = g.freeq[g.free_head];
  g.free_head = (g.free_head + 1U) % SLOT_N;
  g.free_n--;
  j = &g.slot[idx];
  *j = *job;
  j->seq = j->dev->work_submit[j->type]++;
  tail = (g.ready_head + g.ready_n) % SLOT_N;
  g.readyq[tail] = idx;
  g.ready_n++;
  g.active++;
  pthread_cond_signal (&g.ready);
  pthread_mutex_unlock (&g.lock);
  return true;
}

void
work_drain (void)
{
  if (!g.nthread)
    return;
  pthread_mutex_lock (&g.lock);
  while (g.active)
    pthread_cond_wait (&g.drained, &g.lock);
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
