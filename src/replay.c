#include "replay.h"

#include <string.h>

#define BLOCKS (REPLAY_BITS / 64U)
#define BLOCK_MASK (BLOCKS - 1U)

void
replay_clr (Replay *r)
{
  memset (r, 0, sizeof (*r));
}

bool
replay_check (const Replay *r, uint64_t counter)
{
  uint64_t bit;

  if (counter >= REPLAY_LIMIT
      || (counter <= r->last && r->last - counter > REPLAY_WIN))
    return false;
  if (counter > r->last)
    return true;
  bit = UINT64_C (1) << (counter & 63U);
  return !(r->bits[(counter >> 6) & BLOCK_MASK] & bit);
}

bool
replay_update (Replay *r, uint64_t counter)
{
  uint64_t block, cur, n, i;

  if (!replay_check (r, counter))
    return false;
  block = counter >> 6;
  if (counter > r->last)
    {
      cur = r->last >> 6;
      n = block - cur;
      if (n > BLOCKS)
        n = BLOCKS;
      for (i = 1; i <= n; i++)
        r->bits[(cur + i) & BLOCK_MASK] = 0;
      r->last = counter;
    }
  r->bits[block & BLOCK_MASK] |= UINT64_C (1) << (counter & 63U);
  return true;
}
