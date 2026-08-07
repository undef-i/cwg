#pragma once

#include "crypto.h"
#include "wire.h"

enum
{
  NS_ZERO,
  NS_INIT_MADE,
  NS_INIT_GOT,
  NS_RESP_MADE,
  NS_RESP_GOT,
};

typedef struct
{
  uint8_t sk[32];
  uint8_t pk[32];
  uint8_t rpk[32];
  uint8_t psk[32];
  uint8_t e[32];
  uint8_t re[32];
  uint8_t ck[32];
  uint8_t h[32];
  uint8_t last[12];
  uint32_t li;
  uint32_t ri;
  int state;
} Noise;

bool noise_init (Noise *n, const uint8_t sk[32], const uint8_t rpk[32],
                 const uint8_t psk[32]);
bool noise_init_make (Noise *n, MsgInit *m, uint32_t idx);
bool noise_init_get (Noise *n, const MsgInit *m);
bool noise_resp_make (Noise *n, MsgResp *m, uint32_t idx);
bool noise_resp_get (Noise *n, const MsgResp *m);
bool noise_keys (Noise *n, uint8_t tx[32], uint8_t rx[32]);
