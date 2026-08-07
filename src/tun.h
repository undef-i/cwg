#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int tun_open (const char *name);
ssize_t tun_read (int fd, uint8_t *buf, size_t cap);
ssize_t tun_write (int fd, const uint8_t *buf, size_t len);
