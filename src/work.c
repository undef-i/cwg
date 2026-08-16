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
  BATCH_N = UDP_BATCH_MAX,
  SLOT_RESERVED,
  SLOT_READY,
  SLOT_DONE,
  SLOT_FREE,
};

typedef struct
{
  pthread_mutex_t lock;
  pthread_cond_t ready;
  pthread_t *thread;
  int event;
  WorkJob slot[SLOT_N];
  unsigned freeq[2][SLOT_PER_TYPE];
  unsigned readyq[SLOT_N];
  unsigned done_prev[SLOT_N], done_next[SLOT_N];
  bool done_queued[SLOT_N];
  unsigned free_head[2], free_n[2];
  unsigned ready_head, ready_n;
  unsigned done_head, done_tail, done_n;
  unsigned active;
  unsigned nthread;
  bool stopping;
  void (*run) (WorkJob *);
  void (*commit) (WorkJob *, unsigned);
} Pool;

static Pool g;

static void
done_remove (unsigned idx)
{
  unsigned prev = g.done_prev[idx], next = g.done_next[idx];
  if (!g.done_queued[idx])
    return;
  if (prev < SLOT_N)
    g.done_next[prev] = next;
  else
    g.done_head = next;
  if (next < SLOT_N)
    g.done_prev[next] = prev;
  else
    g.done_tail = prev;
  g.done_queued[idx] = false;
  g.done_prev[idx] = g.done_next[idx] = SLOT_N;
  g.done_n--;
}

static void
done_push (unsigned idx)
{
  if (g.done_queued[idx])
    return;
  g.done_prev[idx] = g.done_tail;
  g.done_next[idx] = SLOT_N;
  if (g.done_tail < SLOT_N)
    g.done_next[g.done_tail] = idx;
  else
    g.done_head = idx;
  g.done_tail = idx;
  g.done_queued[idx] = true;
  g.done_n++;
}

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
      if (!errno && !*end && v > 0 && v <= SLOT_N)
        return (unsigned)v;
    }
  if (n < 1)
    n = 1;
  if ((unsigned long)n > SLOT_N)
    n = SLOT_N;
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
          unsigned slot = idx[i];
          atomic_store_explicit (&g.slot[slot].state, SLOT_DONE,
                                 memory_order_release);
          done_push (slot);
        }
      pthread_mutex_unlock (&g.lock);
      uint64_t one = 1;
      write (g.event, &one, sizeof (one));
    }
}

int
work_start (void (*run) (WorkJob *), void (*commit) (WorkJob *, unsigned))
{
  unsigned made = 0;
  bool lock_ok = false, ready_ok = false;
  memset (&g, 0, sizeof (g));
  g.event = -1;
  g.done_head = g.done_tail = SLOT_N;
  for (unsigned i = 0; i < SLOT_N; i++)
    g.done_prev[i] = g.done_next[i] = SLOT_N;
  if (pthread_mutex_init (&g.lock, NULL))
    goto fail;
  lock_ok = true;
  if (pthread_cond_init (&g.ready, NULL))
    goto fail;
  ready_ok = true;
  g.run = run;
  g.commit = commit;
  g.event = eventfd (0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (g.event < 0)
    goto fail;
  g.nthread = workers_get ();
  g.free_n[WORK_OUT] = SLOT_PER_TYPE;
  g.free_n[WORK_IN] = SLOT_PER_TYPE;
  for (unsigned i = 0; i < SLOT_PER_TYPE; i++)
    {
      g.freeq[WORK_OUT][i] = i;
      g.freeq[WORK_IN][i] = SLOT_PER_TYPE + i;
    }
  g.thread = calloc (g.nthread, sizeof (*g.thread));
  if (!g.thread)
    goto fail;
  for (; made < g.nthread; made++)
    if (pthread_create (&g.thread[made], NULL, worker, NULL))
      goto fail;
  return 0;

fail:
  if (lock_ok)
    {
      pthread_mutex_lock (&g.lock);
      g.stopping = true;
      if (ready_ok)
        pthread_cond_broadcast (&g.ready);
      pthread_mutex_unlock (&g.lock);
    }
  while (made)
    pthread_join (g.thread[--made], NULL);
  free (g.thread);
  g.thread = NULL;
  g.nthread = 0;
  if (ready_ok)
    pthread_cond_destroy (&g.ready);
  if (lock_ok)
    pthread_mutex_destroy (&g.lock);
  if (g.event >= 0)
    close (g.event);
  g.event = -1;
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
      WorkJob *j, *first = NULL, *last = NULL;
      Peer *p;
      unsigned type, n = 0;
      pthread_mutex_lock (&g.lock);
      if (!g.done_n)
        {
          pthread_mutex_unlock (&g.lock);
          break;
        }
      idx = g.done_head;
      done_remove (idx);
      j = &g.slot[idx];
      p = j->owner;
      type = j->type;
      if (j != p->work_head[type])
        {
          pthread_mutex_unlock (&g.lock);
          continue;
        }
      while (n < BATCH_N && (j = p->work_head[type])
             && atomic_load_explicit (&j->state, memory_order_acquire)
                    == SLOT_DONE)
        {
          idx = (unsigned)(j - g.slot);
          done_remove (idx);
          p->work_head[type] = j->next;
          if (!first)
            first = j;
          last = j;
          n++;
        }
      if (!p->work_head[type])
        p->work_tail[type] = NULL;
      if (last)
        last->next = NULL;
      if ((j = p->work_head[type])
          && atomic_load_explicit (&j->state, memory_order_acquire)
                 == SLOT_DONE)
        done_push ((unsigned)(j - g.slot));
      pthread_mutex_unlock (&g.lock);
      if (!first)
        continue;

      g.commit (first, n);
      for (j = first; j;)
        {
          WorkJob *next = j->next;
          atomic_fetch_sub_explicit (&p->work_ref, 1, memory_order_release);
          pthread_mutex_lock (&g.lock);
          g.active--;
          pthread_mutex_unlock (&g.lock);
          work_release (j, type);
          j = next;
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
  pthread_cond_destroy (&g.ready);
  pthread_mutex_destroy (&g.lock);
  memset (&g, 0, sizeof (g));
}

unsigned
work_count (void)
{
  return g.nthread;
}
