#pragma once

#include "device.h"
#include "work.h"

void data_tun (Dev *d, const uint8_t *buf, size_t len);
void data_udp (Dev *d, const Ep *src, uint8_t *buf, size_t len);
void data_keepalive (Dev *d, Peer *p);
void data_tick (Dev *d, uint64_t now);
uint64_t data_now (void);
void data_work (WorkJob *j);
void data_commit (WorkJob *j);
