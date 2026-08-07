#pragma once

#include <stdbool.h>
#include <stdint.h>

#define REPLAY_BITS 8192U
#define REPLAY_WIN (REPLAY_BITS - 64U)
#define REPLAY_LIMIT (UINT64_MAX - REPLAY_BITS)

typedef struct
{
  uint64_t last;
  uint64_t bits[REPLAY_BITS / 64U];
} Replay;

void replay_clr (Replay *r);
bool replay_check (const Replay *r, uint64_t counter);
bool replay_update (Replay *r, uint64_t counter);
