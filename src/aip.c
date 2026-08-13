#include "aip.h"
#include "device.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static size_t
af_len (int af)
{
  return af == AF_INET ? 4U : af == AF_INET6 ? 16U : 0U;
}

static unsigned
ip_bit (const uint8_t ip[16], unsigned bit)
{
  return (ip[bit / 8U] >> (7U - bit % 8U)) & 1U;
}

static AipNode **
aip_root (Dev *d, int af)
{
  return af == AF_INET ? &d->aip4 : af == AF_INET6 ? &d->aip6 : NULL;
}

static void
aip_node_free (AipNode *node)
{
  if (!node)
    return;
  aip_node_free (node->child[0]);
  aip_node_free (node->child[1]);
  free (node);
}

static bool
aip_prune (AipNode **node)
{
  bool left, right;
  if (!*node)
    return true;
  left = aip_prune (&(*node)->child[0]);
  right = aip_prune (&(*node)->child[1]);
  if (left && right && !(*node)->peer)
    {
      free (*node);
      *node = NULL;
    }
  return !*node;
}

int
aip_add (Dev *d, Peer *p, int af, const uint8_t ip[16], uint8_t cidr)
{
  AipNode **root = aip_root (d, af);
  AipNode *node;
  AipNode **created_link[129];
  AipNode *created[129];
  unsigned created_n = 0;
  size_t bits = af_len (af) * 8U;

  if (!root || cidr > bits)
    return -EINVAL;
  if (!*root)
    {
      *root = calloc (1, sizeof (**root));
      if (!*root)
        return -ENOMEM;
      created_link[created_n] = root;
      created[created_n++] = *root;
    }
  node = *root;
  for (unsigned bit = 0; bit < cidr; bit++)
    {
      unsigned side = ip_bit (ip, bit);
      bool made = !node->child[side];
      if (made && !(node->child[side] = calloc (1, sizeof (*node))))
        {
          while (created_n)
            {
              AipNode *child = created[--created_n];
              *created_link[created_n] = NULL;
              free (child);
            }
          return -ENOMEM;
        }
      if (made)
        {
          created_link[created_n] = &node->child[side];
          created[created_n++] = node->child[side];
        }
      node = node->child[side];
    }
  node->peer = p;
  return 0;
}

void
aip_del (Dev *d, const Peer *p, int af, const uint8_t ip[16], uint8_t cidr)
{
  AipNode **root = aip_root (d, af);
  AipNode *node;
  size_t bits = af_len (af) * 8U;

  if (!root || !*root || cidr > bits)
    return;
  node = *root;
  for (unsigned bit = 0; bit < cidr; bit++)
    {
      node = node->child[ip_bit (ip, bit)];
      if (!node)
        return;
    }
  if (node->peer == p)
    {
      node->peer = NULL;
      aip_prune (root);
    }
}

static void
aip_node_del_peer (AipNode *node, const Peer *peer)
{
  if (!node)
    return;
  if (node->peer == peer)
    node->peer = NULL;
  aip_node_del_peer (node->child[0], peer);
  aip_node_del_peer (node->child[1], peer);
}

void
aip_del_peer (Dev *d, const Peer *p)
{
  aip_node_del_peer (d->aip4, p);
  aip_node_del_peer (d->aip6, p);
  aip_prune (&d->aip4);
  aip_prune (&d->aip6);
}

void
aip_free (Dev *d)
{
  aip_node_free (d->aip4);
  aip_node_free (d->aip6);
  d->aip4 = d->aip6 = NULL;
}

static void
aip_node_each (const AipNode *node, int af, uint8_t ip[16], unsigned bit,
               const Peer *peer, AipVisit visit, void *arg)
{
  size_t bits = af_len (af) * 8U;
  if (!node)
    return;
  if (node->peer == peer)
    visit (af, ip, (uint8_t)bit, arg);
  if (bit == bits)
    return;
  for (unsigned side = 0; side < 2; side++)
    if (node->child[side])
      {
        uint8_t next[16];
        memcpy (next, ip, sizeof (next));
        if (side)
          next[bit / 8U] |= (uint8_t)(1U << (7U - bit % 8U));
        aip_node_each (node->child[side], af, next, bit + 1U, peer, visit,
                       arg);
      }
}

void
aip_each (const Dev *d, const Peer *p, AipVisit visit, void *arg)
{
  uint8_t ip[16] = { 0 };
  aip_node_each (d->aip4, AF_INET, ip, 0, p, visit, arg);
  aip_node_each (d->aip6, AF_INET6, ip, 0, p, visit, arg);
}

Peer *
aip_fnd (const Dev *d, int af, const uint8_t ip[16])
{
  const AipNode *node;
  Peer *peer = NULL;
  size_t bits = af_len (af) * 8U;

  if (!bits)
    return NULL;
  node = af == AF_INET ? d->aip4 : d->aip6;
  for (unsigned bit = 0; node && bit <= bits; bit++)
    {
      if (node->peer)
        peer = node->peer;
      if (bit == bits)
        break;
      node = node->child[ip_bit (ip, bit)];
    }
  return peer;
}
