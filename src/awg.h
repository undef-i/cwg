#pragma once

#include "common.h"

enum
{
  AWG_PACKET_MAX = 65535,
  AWG_INIT = 0,
  AWG_RESP,
  AWG_COOKIE,
  AWG_DATA,
  AWG_TYPE_N,
};

typedef struct
{
  uint32_t lo;
  uint32_t hi;
} AwgRange;

typedef struct
{
  AwgRange h[AWG_TYPE_N];
  uint32_t s[AWG_TYPE_N];
  uint32_t jc;
  uint32_t jmin;
  uint32_t jmax;
  AwgRange content_pad;
  AwgRange rekey_after;
  AwgRange rekey_timeout;
  AwgRange reject_after;
  AwgRange keepalive_timeout;
  AwgRange max_handshake_attempts;
  uint8_t hp_key[KEY_LEN];
  bool hp;
  char i[5][AWG_PACKET_MAX + 1U];
} Awg;

void awg_init (Awg *a);
int awg_range_set (AwgRange *r, const char *value);
int awg_hex_set (uint8_t *out, size_t *out_len, const char *value);
int awg_set (Awg *a, const char *key, const char *value);
int awg_validate (const Awg *a);
const char *awg_range_get (const AwgRange *r, char buf[32]);
void awg_type_set (const Awg *a, unsigned type, void *msg);
void awg_type_normalize (void *msg, unsigned type);
int awg_wrap (const Awg *a, unsigned type, uint8_t *buf, size_t *len,
              size_t cap);
int awg_unwrap (const Awg *a, uint8_t *buf, size_t *len, unsigned *type);
int awg_i_make (const Awg *a, unsigned index, uint8_t *out, size_t *len,
                size_t cap);
size_t awg_content_pad (const Awg *a, size_t len, size_t mtu);
uint32_t awg_range_pick (const AwgRange *r, uint32_t fallback);
