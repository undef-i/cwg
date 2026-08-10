#pragma once

#include "aip.h"
#include "awg.h"
#include "common.h"
#include "cookie.h"
#include "idx.h"
#include "noise.h"
#include "replay.h"
#include "udp.h"
#include "uthash.h"
#include "wire.h"

#include <net/if.h>
#include <pthread.h>
#include <stdatomic.h>

typedef struct Peer Peer;
typedef struct Dev Dev;
typedef struct Kp Kp;
typedef struct Pkt Pkt;
typedef struct WorkJob WorkJob;
typedef struct HsRate HsRate;
typedef struct UapiConn UapiConn;

#define STAGE_MAX 128U

struct Kp
{
  uint8_t tx[KEY_LEN];
  uint8_t rx[KEY_LEN];
  uint32_t ri;
  uint32_t li;
  atomic_uint_fast64_t cnt;
  uint64_t born;
  Replay replay;
  Peer *peer;
  bool initiator;
  bool ok;
};

struct Pkt
{
  size_t len;
  uint8_t buf[];
};

enum { HS_QUEUE_CAP = 1024U };

typedef struct
{
  Ep ep;
  size_t len;
  unsigned type;
  uint8_t buf[sizeof (MsgInit)];
} HsJob;

struct HsRate
{
  uint8_t key[17];
  uint64_t last;
  uint64_t tokens;
  UT_hash_handle hh;
};

struct Peer
{
  uint8_t pk[KEY_LEN];
  uint8_t psk[KEY_LEN];
  char ep[256];
  Ep addr;
  AwgRange ka;
  uint64_t hs_s;
  uint64_t hs_ns;
  atomic_uint_fast64_t tx;
  atomic_uint_fast64_t rx;
  atomic_uint_fast64_t last_tx;
  atomic_uint_fast64_t last_rx;
  atomic_uint_fast64_t ka_due;
  atomic_uint_fast64_t pka_due;
  atomic_uint_fast64_t hs_due;
  atomic_uint_fast64_t zero_due;
  uint64_t hs_start;
  uint64_t hs_next;
  uint64_t hs_last_sent;
  uint64_t last_init_ms;
  uint32_t hs_attempts;
  uint32_t hs_max_attempts;
  bool ka_again;
  bool rekey_sent;
  bool hs_pending;
  Noise hs;
  Kp kp;
  Kp prev;
  Kp pending;
  uint8_t cookie[COOKIE_LEN];
  uint8_t last_mac1[COOKIE_LEN];
  uint8_t mac1_key[COOKIE_KEY_LEN];
  uint8_t cookie_key[COOKIE_KEY_LEN];
  uint64_t cookie_birth;
  bool cookie_ok;
  bool mac1_ok;
  Pkt *q[STAGE_MAX];
  size_t qn;
  atomic_uint work_ref;
  bool retired;
  Peer *retired_next;
  WorkJob *work_head[2];
  WorkJob *work_tail[2];
  UT_hash_handle hh;
};

struct Dev
{
  char name[IFNAMSIZ];
  char socket_dir[32];
  char sock[108];
  int tun;
  int uapi;
  int udp4;
  int udp6;
  int mtu;
  uint64_t udp_gen;
  uint64_t udp_seen;
  uint8_t sk[KEY_LEN];
  uint8_t pk[KEY_LEN];
  uint8_t cookie_secret[COOKIE_KEY_LEN];
  uint8_t mac1_key[COOKIE_KEY_LEN];
  uint8_t cookie_key[COOKIE_KEY_LEN];
  uint64_t cookie_birth;
  HsJob *hs;
  unsigned hs_head;
  unsigned hs_n;
  unsigned hs_active;
  uint64_t hs_busy_until;
  HsRate *hs_rate;
  bool has_sk;
  uint16_t port;
  uint16_t bind_port;
  uint32_t mark;
  bool up;
  Awg awg;
  Peer *peer;
  Peer *retired;
  AipNode *aip4;
  AipNode *aip6;
  Idx *idx;
  pthread_rwlock_t lock;
  pthread_mutex_t data_lock;
  pthread_mutex_t hs_lock;
  pthread_cond_t hs_ready;
  pthread_cond_t hs_idle;
  pthread_t hs_thread;
  bool hs_stop;
  pthread_mutex_t uapi_lock;
  pthread_cond_t uapi_idle;
  unsigned uapi_n;
  UapiConn *uapi_conn;
  Dev *next;
};

Dev *dev_new (const char *name);
void dev_free (Dev *d);
void dev_peer_clr (Dev *d);
Peer *dev_peer_fnd (Dev *d, const uint8_t pk[KEY_LEN]);
Peer *dev_peer_get (Dev *d, const uint8_t pk[KEY_LEN], bool *is_new);
void dev_peer_del (Dev *d, Peer *p);
void dev_reap (Dev *d);
void dev_key_set (Dev *d, const uint8_t sk[KEY_LEN]);
void dev_peer_reset (Dev *d, Peer *p);
int dev_bind (Dev *d, uint16_t port, uint32_t mark);
int dev_up (Dev *d, bool up);
