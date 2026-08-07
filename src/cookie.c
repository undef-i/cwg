#include "cookie.h"

#include "blake2.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>
#include <string.h>

static void
derive (uint8_t key[COOKIE_KEY_LEN], const char label[8],
        const uint8_t pub[COOKIE_KEY_LEN])
{
  blake2s_state s;
  blake2s_init (&s, COOKIE_KEY_LEN);
  blake2s_update (&s, label, 8);
  blake2s_update (&s, pub, COOKIE_KEY_LEN);
  blake2s_final (&s, key, COOKIE_KEY_LEN);
}

void
cookie_mac1_key (uint8_t key[COOKIE_KEY_LEN],
                 const uint8_t pub[COOKIE_KEY_LEN])
{
  derive (key, "mac1----", pub);
}

void
cookie_key (uint8_t key[COOKIE_KEY_LEN], const uint8_t pub[COOKIE_KEY_LEN])
{
  derive (key, "cookie--", pub);
}

void
cookie_mac1 (uint8_t mac[COOKIE_LEN], const uint8_t key[COOKIE_KEY_LEN],
             const void *msg, size_t prefix_len)
{
  blake2s (mac, COOKIE_LEN, msg, prefix_len, key, COOKIE_KEY_LEN);
}

void
cookie_mac2 (uint8_t mac[COOKIE_LEN], const uint8_t cookie[COOKIE_LEN],
             const void *msg, size_t prefix_len)
{
  blake2s (mac, COOKIE_LEN, msg, prefix_len, cookie, COOKIE_LEN);
}

bool
cookie_mac1_check (const uint8_t mac[COOKIE_LEN],
                   const uint8_t key[COOKIE_KEY_LEN], const void *msg,
                   size_t prefix_len)
{
  uint8_t got[COOKIE_LEN];
  cookie_mac1 (got, key, msg, prefix_len);
  return sodium_memcmp (got, mac, COOKIE_LEN) == 0;
}

bool
cookie_mac2_check (const uint8_t mac[COOKIE_LEN],
                   const uint8_t cookie[COOKIE_LEN], const void *msg,
                   size_t prefix_len)
{
  uint8_t got[COOKIE_LEN];
  cookie_mac2 (got, cookie, msg, prefix_len);
  return sodium_memcmp (got, mac, COOKIE_LEN) == 0;
}

bool
cookie_reply_encrypt (uint8_t out[COOKIE_REPLY_LEN],
                      const uint8_t cookie[COOKIE_LEN],
                      const uint8_t mac1[COOKIE_LEN],
                      const uint8_t nonce[COOKIE_NONCE_LEN],
                      const uint8_t key[COOKIE_KEY_LEN])
{
  unsigned long long len;
  int rc = crypto_aead_xchacha20poly1305_ietf_encrypt (
      out, &len, cookie, COOKIE_LEN, mac1, COOKIE_LEN, NULL, nonce, key);
  return rc == 0 && len == COOKIE_REPLY_LEN;
}

bool
cookie_reply_decrypt (uint8_t cookie[COOKIE_LEN],
                      const uint8_t in[COOKIE_REPLY_LEN],
                      const uint8_t mac1[COOKIE_LEN],
                      const uint8_t nonce[COOKIE_NONCE_LEN],
                      const uint8_t key[COOKIE_KEY_LEN])
{
  unsigned long long len;
  int rc = crypto_aead_xchacha20poly1305_ietf_decrypt (
      cookie, &len, NULL, in, COOKIE_REPLY_LEN, mac1, COOKIE_LEN, nonce, key);
  if (rc || len != COOKIE_LEN)
    {
      sodium_memzero (cookie, COOKIE_LEN);
      return false;
    }
  return true;
}

bool
cookie_src (uint8_t cookie[COOKIE_LEN], const uint8_t secret[COOKIE_KEY_LEN],
            const struct sockaddr *src)
{
  blake2s_state s;
  const void *addr, *port;
  size_t len;
  if (src->sa_family == AF_INET)
    {
      const struct sockaddr_in *sa = (const void *)src;
      addr = &sa->sin_addr;
      port = &sa->sin_port;
      len = sizeof (sa->sin_addr);
    }
  else if (src->sa_family == AF_INET6)
    {
      const struct sockaddr_in6 *sa = (const void *)src;
      addr = &sa->sin6_addr;
      port = &sa->sin6_port;
      len = sizeof (sa->sin6_addr);
    }
  else
    return false;
  blake2s_init_key (&s, COOKIE_LEN, secret, COOKIE_KEY_LEN);
  blake2s_update (&s, addr, len);
  blake2s_update (&s, port, sizeof (uint16_t));
  blake2s_final (&s, cookie, COOKIE_LEN);
  return true;
}
