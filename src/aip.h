#pragma once

#include "common.h"

typedef struct AipNode AipNode;
typedef struct Dev Dev;
typedef struct Peer Peer;

struct AipNode
{
  AipNode *child[2];
  Peer *peer;
};

typedef void (*AipVisit) (int af, const uint8_t ip[16], uint8_t cidr,
                          void *arg);

int aip_add (Dev *d, Peer *p, int af, const uint8_t ip[16], uint8_t cidr);
void aip_del (Dev *d, const Peer *p, int af, const uint8_t ip[16],
              uint8_t cidr);
void aip_del_peer (Dev *d, const Peer *p);
void aip_free (Dev *d);
void aip_each (const Dev *d, const Peer *p, AipVisit visit, void *arg);
Peer *aip_fnd (const Dev *d, int af, const uint8_t ip[16]);
