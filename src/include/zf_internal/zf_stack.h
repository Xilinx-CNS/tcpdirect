/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF stack - critical path data and code only */

#ifndef __ZF_INTERNAL_STACK_H__
#define __ZF_INTERNAL_STACK_H__

#include <zf/zf.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/utils.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/tcp.h>
#include <zf_internal/udp_rx.h>
#include <zf_internal/udp_tx.h>
#include <zf_internal/rx_table.h>
#include <zf_internal/timekeeping.h>
#include <zf_internal/timers.h>
#include <zf_internal/zf_alts.h>

#include <zf_internal/allocator.h>
#include <zf_internal/utils.h>

#include <zf_internal/private/zf_stack_def.h>

#include <etherfabric/ef_vi.h>


/* Number of TXQ spaces needed for maximum allowed send,
 * this should be large enough to send full-sized fragmented UDP datagram */
static const unsigned ZF_SEND_TXQ_THRESHOLD = 64;
/* Maximum count of pkt buffers needed for maximum allowed send +
 * a reserve for receive path */
static const unsigned ZF_SEND_POOL_THRESHOLD = TCP_SND_QUEUE_SEG_COUNT * 2 +
                                               TCP_SND_QUEUE_SEG_COUNT;


static const zf_stack_flag ZF_STACK_FLAG_TCP_NO_DELACK = 0x1;
/* Should we wait for all TIME_WAITs to have gone away before considering the
 * stack to be quiescent? */
static const zf_stack_flag ZF_STACK_FLAG_TCP_WAIT_FOR_TIME_WAIT = 0x2;
static const zf_stack_flag ZF_STACK_FLAG_TCP_FIN_WAIT_TIMEOUT_DISABLED = 0x4;
static const zf_stack_flag ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED = 0x8;

#ifdef ZF_DEVEL
/* disable sending for debug purposes */
static const zf_stack_flag ZF_STACK_FLAG_DEVEL_NO_TX = 0x80;
#endif


/* Trigger the process of rebuilding the contents of all alternatives
 * which have data queued for the given zocket.
 */
ZF_HOT static inline void
zf_stack_mark_alternatives_for_rebuild(struct zf_stack* stack,
                                       struct zf_tcp* tcp)
{
  for( int i = 0; i < zf_stack::MAX_ALTERNATIVES; i++ ) {
    if( tcp->zocket_alts & (1 << i) ) {
      int ack_offset = tcp->pcb.rcv_nxt - stack->tcp_alt_first_ack[i];
      if( ack_offset >= stack->tcp_alt_ack_rewind ) {
        stack->alts_need_rebuild |= (1 << i);
      }
    }
  }
}

static const unsigned ZF_STACK_REFILL_MAX = ~0u;
ZF_HOT static inline void zf_stack_refill_rx_ring(struct zf_stack* st,
                                                  int nic, unsigned max_count)
{
  ef_vi* vi = &st->nic[nic].vi;
  if( *zf_stack_res_nic_flags(st, nic) & ZF_RES_NIC_FLAG_RX_REF )
    return;
  unsigned space = ef_vi_receive_space(vi);
  if( space < st->nic[nic].rx_ring_refill_batch_size )
    return;

  unsigned free = NUM_FREE_PKTS(&st->pool);
  if(ZF_UNLIKELY( free < st->nic[nic].rx_ring_refill_batch_size )) {
    ZF_ONCE(
      zf_log_stack_err(st, "No free packet buffers to refill rx ring.  "
                           "From now on poor performance is expected.  "
                           "Rerun application with more packet buffers, see "
                           "n_bufs attribute.\n") );
    st->stats.ring_refill_nomem++;
    return;
  }

  unsigned count = MIN(space, free);

  if( max_count == 0 )
    max_count = st->nic[nic].rx_ring_refill_batch_size;
  count = MIN(count, max_count);

  pkt_id* ids = NULL; /* set to NULL to appease compiler */
  int rc = zf_pool_get_free_pkts(&st->pool, &ids, &count);
  /* The following assumption will suppress compiler warnings below */
  zf_assume(rc >= 0);
  zf_assume_equal(count, MIN(MIN(space, free), max_count));

  for( unsigned i = 0; i < count; ++i ) {
    char* packet = PKT_BUF_RX_START_BY_ID(&st->pool, ids[i]);
    zfr_poison_packet(packet);
    ef_vi_receive_init(vi, PKT_EFADDR_BY_ID(&st->pool, nic, ids[i]) +
                       RX_PKT_START_OFS(ids[i]), ids[i]);
  }
  ef_vi_receive_push(vi);

  zf_pool_get_free_pkts_done(&st->pool);
}


static inline iphdr*
zf_ip_hdr(char* eth_hdr_base)
{
  /* currently only single vlan header is supported */
  return (iphdr*)(eth_hdr_base + sizeof(struct ethhdr) +
         4 * ZF_UNLIKELY((((ethhdr*)eth_hdr_base)->h_proto) == htons(ETH_P_8021Q)));
}

static inline const iphdr*
zf_ip_hdr(const char* eth_hdr_base)
{
  return zf_ip_hdr((char*)eth_hdr_base);
}


extern ZF_HOT int
zf_stack_handle_tx_tcp(struct zf_tcp* tcp, zf_tx_req_id req_id);

static inline int
zf_stack_handle_tx(struct zf_stack* st, int nic, zf_tx_req_id req_id)
{
  zf_log_event_trace(st, "tx complete: %x\n", req_id);
  if(ZF_LIKELY( req_id & ZF_REQ_ID_PIO_FLAG )) {
    /* mark part of the pio as free */
    st->nic[nic].pio.busy &= ~(1u << (req_id & 1));
  }
  else switch( req_id & ZF_REQ_ID_PROTO_MASK ) {
  case ZF_REQ_ID_PROTO_UDP:
    if( ZF_UNLIKELY((req_id & ZF_REQ_ID_PKT_ID_MASK) == ZF_REQ_ID_PKT_ID_MASK) ) {
      zf_assert(req_id & ZF_REQ_ID_CTPIO_FLAG);
      break;
    }
    /* fall through */
  case ZF_REQ_ID_PROTO_TCP_FREE:
    zf_pool_free_pkt(&st->pool, req_id & ZF_REQ_ID_PKT_ID_MASK);
    break;
  case ZF_REQ_ID_PROTO_TCP_ALT:
    break;
  case ZF_REQ_ID_PROTO_TCP_KEEP:
    int zock_id = req_id & ZF_REQ_ID_ZOCK_ID_MASK;
    zock_id >>= ZF_REQ_ID_ZOCK_ID_SHIFT;
    return zf_stack_handle_tx_tcp(&st->tcp[zock_id], req_id);
  }

  return 0; /* any action worth notifying anyone - currently none */
}


static inline void zf_stack_busy_ref(struct zf_stack* stack)
{
  if( stack->busy_refcount++ == 0 )
    zf_muxer_mark_waitable_not_ready(&stack->w, EPOLLSTACKHUP);
  zf_log_stack_trace(stack, "%s: busy_refcount = %d\n", __FUNCTION__,
                        stack->busy_refcount);
}


static inline void zf_stack_busy_release(struct zf_stack* stack)
{
  zf_assume_gt(stack->busy_refcount, 0);
  if( --stack->busy_refcount == 0 )
    zf_muxer_mark_waitable_ready(&stack->w, EPOLLSTACKHUP);
  zf_log_stack_trace(stack, "%s: busy_refcount = %d\n", __FUNCTION__,
                        stack->busy_refcount);
}


extern unsigned zf_stack_max_pkt_buf_usage(zf_stack_impl* sti);

#ifdef ZF_DEVEL
extern int zf_stack_check_vi_compatibility(zf_stack* st, const zf_attr* attr,
                                           ef_vi* vi_a, ef_vi* vi_b);
#endif

#endif /* __ZF_INTERNAL_STACK_H__ */
