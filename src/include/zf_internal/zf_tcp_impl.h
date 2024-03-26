/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INT_TCP_IMPL_H__
#define __ZF_INT_TCP_IMPL_H__

#include <zf/zf.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/stack_params.h>
#include <zf_internal/zf_tcp_impl_types.h>


static inline unsigned zf_tcp_max_pkt_bufs_usage(zf_stack* st)
{
  /* sndq, ooo queue, rcv queue, fast send cache, EOF cache */
  return TCP_SND_QUEUE_SEG_COUNT + SW_RECVQ_MAX * 2 + 2;
}


static inline unsigned zf_tcp_listen_max_pkt_bufs_usage(zf_stack* st)
{
  return 0;
}


/* The listenq add/set/free functions are called from the SYN_RCVD fast path.
 */

static inline int
zftl_listenq_add_entry(struct zf_tcp_listenq* listenq, uint16_t listener_id)
{
  uint16_t index;
  struct zf_tcp_listenq_entry* entry;
  if( listenq->lazy_alloc_index < listenq->max_syn_backlog ) {
    index = listenq->lazy_alloc_index++;
    entry = &listenq->table[index];
  }
  else if( listenq->free_list_head != ZF_LISTENQ_INDEX_INVALID ) {
    index = listenq->free_list_head;
    entry = &listenq->table[index];
    listenq->free_list_head = entry->free_list_next;
  }
  else {
    return -ENOBUFS;
  }

  entry->listener_id = listener_id;

  return index;
}


static inline void
zftl_listenq_free_entry(struct zf_tcp_listenq* listenq, uint16_t index)
{
  struct zf_tcp_listenq_entry* entry = &listenq->table[index];
  entry->listener_id = ZF_ZOCKET_ID_INVALID;
  entry->free_list_next = listenq->free_list_head;
  listenq->free_list_head = index;
}


static inline void
zftl_listenq_set_synrecv_id(struct zf_tcp_listenq* listenq, uint16_t index,
                            uint16_t synrecv_id)
{
  struct zf_tcp_listenq_entry* entry = &listenq->table[index];
  entry->synrecv_id = synrecv_id;
}



ZF_HOT static inline void
zft_zc_read(struct zf_tcp* tcp, struct zft_msg* restrict msg)
{
  struct zf_rx* rx = &tcp->tsr;
  unsigned iovcnt = msg->iovcnt;

  zfr_pkts_peek(&rx->ring, msg->iov, &iovcnt);
  msg->pkts_left = zfr_queue_packets_unread_n(rx) - iovcnt;

  /* Short reads are guaranteed against by the API.  Assert this. */
  if( (int) iovcnt < msg->iovcnt )
    zf_assume_equal(msg->pkts_left, 0);

  msg->iovcnt = rx->release_n = iovcnt;
}


static inline bool zft_zc_recv_in_progress(struct zf_tcp* tcp)
{
  return tcp->tsr.release_n > 0;
}


#define TCP_OPT_END_KIND    0u

#define TCP_OPT_NOP_KIND    1u

#define TCP_OPT_MSS_KIND    2u
#define TCP_OPT_MSS_LENGTH  4u
#define TCP_OPT_MSS_HE(mss) ((TCP_OPT_MSS_KIND   << 24) | \
                             (TCP_OPT_MSS_LENGTH << 16) | \
                             ((mss) & 0xFFFFu))

#endif /* __ZF_INT_TCP_IMPL_H__ */
