#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

int tun_open (const char *name);
int tun_adopt (int fd, const char *name);
int tun_mtu (const char *name);
bool tun_up (const char *name);
ssize_t tun_read (int fd, uint8_t *buf, size_t cap);
ssize_t tun_write (int fd, const uint8_t *buf, size_t len);
