#pragma once

#include "common.h"

void key_hex (char out[HEX_LEN + 1], const uint8_t key[KEY_LEN]);
bool key_get (uint8_t out[KEY_LEN], const char *hex);
bool if_ok (const char *name);
bool u64_get (const char *s, uint64_t max, uint64_t *out);
