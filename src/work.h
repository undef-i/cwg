#pragma once

#include "awg.h"
#include "common.h"
#include "udp.h"

#include <stdatomic.h>

typedef struct Dev Dev;
typedef struct Peer Peer;
typedef struct WorkJob WorkJob;

enum
{
  WORK_OUT,
  WORK_IN,
};

struct WorkJob
{
  Dev *dev;
  Peer *owner;
  Ep ep;
  uint8_t peer[KEY_LEN];
  uint8_t key[KEY_LEN];
  uint64_t cnt;
  uint32_t index;
  uint32_t receiver;
  Awg awg;
  int mtu;
  size_t len;
  size_t wire_len;
  unsigned type;
  bool data_sent;
  bool ok;
  atomic_uint state;
  struct WorkJob *next;
  uint8_t buf[2048];
};

int work_start (void (*run) (WorkJob *), void (*commit) (WorkJob *, unsigned));
int work_fd (void);
int work_hnd (void);
WorkJob *work_reserve (unsigned type);
void work_release (WorkJob *job, unsigned type);
void work_submit (WorkJob *job);
void work_drain (void);
void work_stop (void);
unsigned work_count (void);
