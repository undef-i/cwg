#pragma once

#include <stdint.h>

enum
{
  MSG_INIT = 1,
  MSG_RESP = 2,
  MSG_COOKIE = 3,
  MSG_DATA = 4,
};

typedef struct __attribute__ ((packed))
{
  uint32_t type;
  uint32_t sender;
  uint8_t eph[32];
  uint8_t stat[48];
  uint8_t time[28];
  uint8_t mac1[16];
  uint8_t mac2[16];
} MsgInit;

typedef struct __attribute__ ((packed))
{
  uint32_t type;
  uint32_t sender;
  uint32_t recv;
  uint8_t eph[32];
  uint8_t empty[16];
  uint8_t mac1[16];
  uint8_t mac2[16];
} MsgResp;

typedef struct __attribute__ ((packed))
{
  uint32_t type;
  uint32_t recv;
  uint8_t nonce[24];
  uint8_t cookie[32];
} MsgCookie;

typedef struct __attribute__ ((packed))
{
  uint32_t type;
  uint32_t recv;
  uint64_t cnt;
} MsgData;

_Static_assert (sizeof (MsgInit) == 148, "init size");
_Static_assert (sizeof (MsgResp) == 92, "response size");
_Static_assert (sizeof (MsgCookie) == 64, "cookie size");
_Static_assert (sizeof (MsgData) == 16, "transport header size");
