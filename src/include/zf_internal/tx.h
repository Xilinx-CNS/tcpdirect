/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF tx - socket tx fast path */

#ifndef __ZF_TX_H__
#define __ZF_TX_H__

#include <zf/zf.h>
#include <zf_internal/tx_types.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/utils.h>


ZF_HOT static inline int
zft_alloc_pkt(zf_pool* pool, pkt_id* id)
{
  *id = zf_pool_get_free_pkt(pool);

  return *id != PKT_INVALID ? 0 : -ENOBUFS;
}


static inline bool zf_tx_do_vlan(const zf_tx* tx)
{
  return tx->path.vlan != ZF_NO_VLAN;
}


static inline ethhdr* zf_tx_ethhdr(zf_tx* tx)
{
  return &tx->pkt.tcp_novlanhdr.eth;
}


static inline const ethhdr* zf_tx_ethhdr_c(const zf_tx* tx)
{
  return &tx->pkt.tcp_novlanhdr.eth;
}


static inline tcphdr* zf_tx_tcphdr(zf_tx* tx)
{
  if( ! zf_tx_do_vlan(tx) )
    return &tx->pkt.tcp_novlanhdr.tcp;
  else
    return &tx->pkt.tcp_vlanhdr.tcp;
}


static inline iphdr* zf_tx_iphdr(zf_tx* tx)
{
  if( ! zf_tx_do_vlan(tx) )
    return &tx->pkt.tcp_novlanhdr.ip;
  else
    return &tx->pkt.tcp_vlanhdr.ip;
}


static inline udphdr* zf_tx_udphdr(zf_tx* tx)
{
  if( ! zf_tx_do_vlan(tx) )
    return &tx->pkt.udp_novlanhdr.udp;
  else
    return &tx->pkt.udp_vlanhdr.udp;
}

extern ZF_COLD void zf_init_tx_state(struct zf_stack* stack, struct zf_tx* tx);
extern ZF_COLD void zf_init_tx_ethhdr(struct zf_stack* stack, struct zf_tx* tx);
extern ZF_COLD void zf_tx_dump(struct zf_tx* tx, int proto);

static inline bool
is_multicast(uint32_t addr_be)
{
  return (addr_be & htonl(0xf0000000)) == htonl(0xe0000000);
}

static inline bool
is_multicast(const struct sockaddr_in* laddr)
{
  return is_multicast(laddr->sin_addr.s_addr);
}


#endif
