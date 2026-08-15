#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

enum { TUN_VNET_HDR_LEN = 10U };

typedef bool (*TunPacketFn) (void *arg, const uint8_t *buf, size_t len);

int tun_open (const char *name, bool *vnet);
int tun_adopt (int fd, const char *name, bool *vnet);
int tun_mtu (const char *name);
bool tun_up (const char *name);
int tun_watch_open (void);
int tun_watch_drain (int fd);
ssize_t tun_read (int fd, uint8_t *buf, size_t cap);
int tun_gso_split (uint8_t *in, size_t len, uint8_t *out, size_t out_cap,
                   TunPacketFn emit, void *arg);
int tun_gro_tcp (uint8_t *first, size_t *first_len, uint16_t *gso_size,
                 uint16_t *merged, const uint8_t *next, size_t next_len);
int tun_gro_udp (uint8_t *first, size_t *first_len, uint16_t *gso_size,
                 uint16_t *merged, const uint8_t *next, size_t next_len);
ssize_t tun_write (int fd, bool vnet, uint8_t *buf, size_t len);
ssize_t tun_write_gso (int fd, bool vnet, uint8_t *buf, size_t len,
                       uint16_t gso_size);
