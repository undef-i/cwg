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

#include <net/if.h>
#include <pthread.h>
#include <stdatomic.h>

typedef struct Peer Peer;
typedef struct Dev Dev;
typedef struct Kp Kp;
typedef struct Pkt Pkt;
typedef struct WorkJob WorkJob;

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

struct Peer
{
  uint8_t pk[KEY_LEN];
  uint8_t psk[KEY_LEN];
  char ep[256];
  Ep addr;
  uint16_t ka;
  uint64_t hs_s;
  uint64_t hs_ns;
  atomic_uint_fast64_t tx;
  atomic_uint_fast64_t rx;
  atomic_uint_fast64_t last_tx;
  atomic_uint_fast64_t last_rx;
  atomic_uint_fast64_t ka_due;
  uint64_t hs_start;
  uint64_t hs_next;
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
  uint64_t work_submit[2];
  uint64_t work_commit[2];
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
  uint64_t udp_gen;
  uint64_t udp_seen;
  uint8_t sk[KEY_LEN];
  uint8_t pk[KEY_LEN];
  uint8_t cookie_secret[COOKIE_KEY_LEN];
  uint8_t mac1_key[COOKIE_KEY_LEN];
  uint8_t cookie_key[COOKIE_KEY_LEN];
  uint64_t cookie_birth;
  uint64_t hs_window;
  unsigned hs_count;
  bool has_sk;
  uint16_t port;
  uint32_t mark;
  Awg awg;
  Peer *peer;
  Peer *retired;
  Aip *aip;
  Idx *idx;
  pthread_rwlock_t lock;
  pthread_mutex_t data_lock;
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
