#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define COOKIE_LEN 16U
#define COOKIE_KEY_LEN 32U
#define COOKIE_NONCE_LEN 24U
#define COOKIE_REPLY_LEN 32U
#define COOKIE_SECRET_AGE 120U
#define COOKIE_VALID_AGE 115U

void cookie_mac1_key (uint8_t key[COOKIE_KEY_LEN],
                      const uint8_t pub[COOKIE_KEY_LEN]);
void cookie_key (uint8_t key[COOKIE_KEY_LEN],
                 const uint8_t pub[COOKIE_KEY_LEN]);
void cookie_mac1 (uint8_t mac[COOKIE_LEN], const uint8_t key[COOKIE_KEY_LEN],
                  const void *msg, size_t prefix_len);
void cookie_mac2 (uint8_t mac[COOKIE_LEN], const uint8_t cookie[COOKIE_LEN],
                  const void *msg, size_t prefix_len);
bool cookie_mac1_check (const uint8_t mac[COOKIE_LEN],
                        const uint8_t key[COOKIE_KEY_LEN], const void *msg,
                        size_t prefix_len);
bool cookie_mac2_check (const uint8_t mac[COOKIE_LEN],
                        const uint8_t cookie[COOKIE_LEN], const void *msg,
                        size_t prefix_len);
bool cookie_reply_encrypt (uint8_t out[COOKIE_REPLY_LEN],
                           const uint8_t cookie[COOKIE_LEN],
                           const uint8_t mac1[COOKIE_LEN],
                           const uint8_t nonce[COOKIE_NONCE_LEN],
                           const uint8_t key[COOKIE_KEY_LEN]);
bool cookie_reply_decrypt (uint8_t cookie[COOKIE_LEN],
                           const uint8_t in[COOKIE_REPLY_LEN],
                           const uint8_t mac1[COOKIE_LEN],
                           const uint8_t nonce[COOKIE_NONCE_LEN],
                           const uint8_t key[COOKIE_KEY_LEN]);
bool cookie_src (uint8_t cookie[COOKIE_LEN],
                 const uint8_t secret[COOKIE_KEY_LEN],
                 const struct sockaddr *src);
