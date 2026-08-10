#include "idx.h"

#include <sodium.h>
#include <stdlib.h>

uint32_t
idx_add (Idx **idx, void *ptr, uint8_t type)
{
  Idx *e, *old;

  if (!(e = malloc (sizeof (*e))))
    return 0;
  do
    {
      e->index = randombytes_random ();
      HASH_FIND (hh, *idx, &e->index, sizeof (e->index), old);
    }
  while (!e->index || old);
  e->ptr = ptr;
  e->type = type;
  HASH_ADD (hh, *idx, index, sizeof (e->index), e);
  return e->index;
}

Idx *
idx_fnd (Idx *idx, uint32_t index)
{
  Idx *e;

  HASH_FIND (hh, idx, &index, sizeof (index), e);
  return e;
}

void
idx_del (Idx **idx, uint32_t index)
{
  Idx *e;

  if (!(e = idx_fnd (*idx, index)))
    return;
  HASH_DEL (*idx, e);
  free (e);
}

void
idx_clr (Idx **idx)
{
  Idx *e, *tmp;

  HASH_ITER (hh, *idx, e, tmp)
  {
    HASH_DEL (*idx, e);
    free (e);
  }
}
