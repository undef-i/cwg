#pragma once

#include "common.h"

typedef struct Aip Aip;
typedef struct Dev Dev;
typedef struct Peer Peer;

struct Aip
{
  int af;
  uint8_t ip[16];
  uint8_t cidr;
  Peer *peer;
  Aip *next;
};

int aip_add (Dev *d, Peer *p, int af, const uint8_t ip[16], uint8_t cidr);
void aip_del (Dev *d, const Peer *p, int af, const uint8_t ip[16],
              uint8_t cidr);
void aip_del_peer (Dev *d, const Peer *p);
Peer *aip_fnd (const Dev *d, int af, const uint8_t ip[16]);
