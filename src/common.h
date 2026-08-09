#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WG_SOCKET_DIR "/var/run/wireguard"
#define AWG_SOCKET_DIR "/var/run/amneziawg"

#define KEY_LEN 32U
#define HEX_LEN 64U
#define PKT_MAX 65535U

enum
{
  LOG_OFF,
  LOG_ERR,
  LOG_DBG,
};

extern int g_log;

void log_init (void);
void log_msg (int lvl, const char *fmt, ...)
    __attribute__ ((format (printf, 2, 3)));

#define err(...) log_msg (LOG_ERR, __VA_ARGS__)
#define dbg(...) log_msg (LOG_DBG, __VA_ARGS__)
