/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_TCP_IMPL_TYPES_H__
#define __ZF_INTERNAL_TCP_IMPL_TYPES_H__

#include <zf/zf.h>
#include <zf_internal/rx_types.h>
#include <zf_internal/tx_types.h>
#include <zf_internal/tcp_types.h>
#include <zf_internal/stack_params.h>


struct zf_tcp {
  /* Public data structure */
  struct zft ts;

  /* Common zf rx structure */
  struct zf_rx tsr;

  /* Common zf tx structure */
  struct zf_tx tst;

  /* Internal TCP data */
  struct tcp_pcb pcb;

  struct zf_waitable w;

  struct sockaddr_in laddr, raddr;

#define ZF_TCP_STATE_FLAGS_INITIALISED 0x00000001u
#define ZF_TCP_STATE_FLAGS_DEFER_EOF   0x00000002u
#define ZF_TCP_STATE_FLAGS_DEFER_OOO   0x00000004u
  uint32_t tcp_state_flags;

  /* We maintain a refcount as this zocket is used both from the TCP state
   * machine and the application.  This allows us to track when both have
   * finished using it, and it can be freed.
   */
  int refcount;

  /* It's considerably more efficient for a zocket to remember
   * (1u << zocket_index) than to calculate it from the zocket's address. */
  uint64_t zocket_mask;

  /* Bitmask of alts on which this TCP zocket has queued data. */
  uint32_t zocket_alts;

  pkt_id eof_pkt;
};


struct zf_tcp_listen_state {
  /* Public data structure */
  struct zftl tl;

  /* Common zf tx structure */
  struct zf_tx tst;

  int refcount;

  /* From the point of view of the TCP core, a zf_tcp_listener is *not* a TCP
   * state.  One consequence is that this structure does not contain a tcp_pcb.
   * Rather, objects of this type exist to create tcp_pcbs, and their
   * enveloping ZF state, for connections that are established as a result of
   * incoming SYNs. */

  struct sockaddr_in laddr;
  uint16_t acceptq_head;
  struct zf_waitable w;
#define ZF_LISTEN_FLAGS_SHUTDOWN 0x00000001u
  uint32_t tls_flags;
};


/* The only time we ever need to iterate over a listening zocket's listenq is
 * when shutting down that zocket.  This is already a slow operation as it
 * requires a filter removal.  By maintaining the set of SYN_RCVD metadata in a
 * single stack-global array, we make shutdown slightly more expensive -- we
 * have to iterate over the entire array -- but avoid the costs of maintaining
 * a doubly-linked list per listening zocket, which would otherwise be
 * necessary. */

struct zf_tcp_listenq_entry {
  /* The entry is allocated if and only if this field is not
   * ZF_ZOCKET_ID_INVALID. */
  uint16_t listener_id;

  /* If this listenq entry is allocated, the ID of the SYN_RCVD zocket is in
   * [synrecv_id]; otherwise, [free_list_next] links it into the list of free
   * entries. */
  union {
    uint16_t synrecv_id;
    uint16_t free_list_next;
  };
};

struct zf_tcp_listenq {
  /* Array tracking all current SYN_RCVD TCP states. */
  struct zf_tcp_listenq_entry* table;

  /* Maximum number of SYN_RCVD states. */
  uint16_t max_syn_backlog;

  /* Used for the initial sequential allocation phase of entries in [table].
   * When this reaches max_syn_backlog, the free-list is used instead. */
  uint16_t lazy_alloc_index;

  /* Head of a linked-list of freed entries in [table]. */
#define ZF_LISTENQ_INDEX_INVALID   UINT16_MAX
  uint16_t free_list_head;
};

#define STANDARD_MSS 1460
/* Reserve last bytes of pktbuf for easy ptr computation, e.g.
 * to avoid confusing pktbuf end pointer with next buffer's start.
 * See __zft_zc_recv_done_tail and each time iov_base ptr is
 * increased on recv and ooo queue. */
#define PKT_BUF_TCP_RESERVE 4
/* Maximum TCP MSS we can handle in worst case. Effectively 1460.
 * TODO consider MSS calculations dynamic to allow larger MTUs
 *      with less headers/no prefix. */
#define TCP_MAX_MSS \
  (PKT_BUF_SIZE_USABLE - ETH_HLEN - \
   IP_HLEN - TCP_HLEN - VLAN_HLEN - \
   MAX_PREFIX_LEN - PKT_BUF_TCP_RESERVE)
/* Minimum TCP MSS supported - see RFC 791 / RFC 879 */
#define TCP_MIN_MSS 536U
_Static_assert(TCP_MAX_MSS >= STANDARD_MSS,
               "Standrad MSS segment will not fit into a single pkt buffer");

#define TCP_OPT_END_KIND    0u

#define TCP_OPT_NOP_KIND    1u

#define TCP_OPT_MSS_KIND    2u
#define TCP_OPT_MSS_LENGTH  4u
#define TCP_OPT_MSS_HE(mss) ((TCP_OPT_MSS_KIND   << 24) | \
                             (TCP_OPT_MSS_LENGTH << 16) | \
                             ((mss) & 0xFFFFu))

#endif /* __ZF_INTERNAL_TCP_IMPL_TYPES_H__ */
