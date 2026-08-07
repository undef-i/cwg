#pragma once

#include <stdint.h>

#include "uthash.h"

typedef struct Idx Idx;

struct Idx
{
  uint32_t index;
  void *ptr;
  uint8_t type;
  UT_hash_handle hh;
};

uint32_t idx_add (Idx **idx, void *ptr, uint8_t type);
Idx *idx_fnd (Idx *idx, uint32_t index);
void idx_del (Idx **idx, uint32_t index);
void idx_clr (Idx **idx);
