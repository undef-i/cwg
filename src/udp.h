#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef struct Ep Ep;

#define UDP_BATCH_MAX 32U
#define UDP_PACKET_MAX 65535U

struct Ep
{
  struct sockaddr_storage sa;
  socklen_t len;
};

typedef struct
{
  Ep ep;
  size_t len;
  uint8_t buf[UDP_PACKET_MAX];
} UdpPacket;

int ep_get (Ep *ep, const char *s);
int udp_open (int *udp4, int *udp6, uint16_t *port);
void udp_close (int udp4, int udp6);
int udp_mark (int udp4, int udp6, uint32_t mark);
ssize_t udp_send (int fd, const Ep *ep, const void *buf, size_t len);
ssize_t udp_recv (int fd, Ep *ep, void *buf, size_t cap);
int udp_recv_batch (int fd, UdpPacket *pkt, unsigned cap);
