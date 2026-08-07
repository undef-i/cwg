#pragma once

#include "common.h"
#include "udp.h"

typedef struct Dev Dev;

enum
{
  WORK_OUT,
  WORK_IN,
};

typedef struct
{
  Dev *dev;
  Ep ep;
  uint8_t peer[KEY_LEN];
  uint8_t key[KEY_LEN];
  uint64_t cnt;
  uint64_t seq;
  uint32_t index;
  uint32_t receiver;
  size_t len;
  size_t wire_len;
  unsigned type;
  bool ok;
  uint8_t buf[2048];
} WorkJob;

int work_start (void (*run) (WorkJob *), void (*commit) (WorkJob *));
WorkJob *work_reserve (void);
void work_release (WorkJob *job);
void work_submit (WorkJob *job);
void work_drain (void);
void work_stop (void);
unsigned work_count (void);
