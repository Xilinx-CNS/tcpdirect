/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mj
**  \brief  ZF reactor
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/bond.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/zf_tcp_timers.h>
#include <zf_internal/attr.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/private/zf_stack_rx.h>

#include <etherfabric/vi.h>
#include <etherfabric/ef_vi.h>
#include <etherfabric/efct_vi.h>
#include <ci/driver/efab/hardware/host_ef10_common.h>

extern "C" {
#include <etherfabric/internal/internal.h>
}

static inline void
zf_reactor_handle_tx_event_unbundled(struct zf_stack* st, int nic_no,
                                     ef_vi* vi, ef_event* ev, int cnt)
{
  struct zf_stack_nic* nic = &st->nic[nic_no];
  for( int i = 0; i < cnt; ++i ) {
    zf_assert(nic->tx_reqs_removed != nic->tx_reqs_added);

    unsigned req_idx = nic->tx_reqs_removed++;
    zf_tx_req_id* id = &nic->tx_reqs[req_idx & nic->tx_reqs_mask];
    zf_stack_handle_tx(st, nic_no, *id);

    /* Check for failed CTPIO sends. */
    if( (*id & ZF_REQ_ID_CTPIO_FLAG) &&
        !(ev->tx.flags & EF_EVENT_FLAG_CTPIO) ) {
      nic->ctpio_allowed = 0;
    }
    *id = ZF_REQ_ID_INVALID;
  }

  /* Received TX completion events tell us that the amount of space in
   * the TX ring is increasing, which may mean we can make more
   * progress on rebuilding alts. */
  if( ZF_UNLIKELY(st->alts_rebuilding != 0) )
    zf_alternatives_resend(st);

  /* Check for TX ring empty. If so, allow CTPIO sends. */
  if( ef_vi_transmit_fill_level(vi) == 0 )
    nic->ctpio_allowed = st->ctpio_max_frame_len;
}


static inline void
zf_reactor_handle_tx_event(struct zf_stack* st, int nic, ef_vi* vi, ef_event* ev)
{
  ef_request_id ids_[EF_VI_TRANSMIT_BATCH];
  /* We have our own txqueue in stack so ef_vi_transmit_unbundle
   * is only needed to clear hw tx ring (to avoid BUG_ONs). */
  int cnt = ef_vi_transmit_unbundle(vi, ev, ids_);

  /* EFCT uses this event type to report warmup completions, even if timestamps
   * are enabled. It should never report an actual send in that case, so we
   * shouldn't need to deal with any pending transmit reports. */
  zf_assert_impl(st->tx_reports.enabled(), cnt == 0);

  zf_reactor_handle_tx_event_unbundled(st, nic, vi, ev, cnt);
}


static inline void
zf_reactor_handle_tx_timestamp_event(struct zf_stack* st, int nic, ef_vi* vi, ef_event* ev)
{
  unsigned req_idx = st->nic[nic].tx_reqs_removed;
  unsigned req_len = ef_vi_transmit_capacity(vi);
  zf_tx_req_id req_id = st->nic[nic].tx_reqs[req_idx & req_len];

  int zock_id = req_id & ZF_REQ_ID_ZOCK_ID_MASK;
  zock_id >>= ZF_REQ_ID_ZOCK_ID_SHIFT;

  zf_assume(st->tx_reports.enabled());
  switch( req_id & ZF_REQ_ID_PROTO_MASK ) {
  case ZF_REQ_ID_PROTO_UDP:
    if( ~req_id & ZF_REQ_ID_UDP_FRAGMENT ) {
      zf_tx_reports::complete(&st->tx_reports, zock_id, false, ev);
      zf_muxer_mark_waitable_ready(&st->udp_tx[zock_id].w, EPOLLERR);
    }
    break;
  case ZF_REQ_ID_PROTO_TCP_KEEP:
    zf_tx_reports::complete(&st->tx_reports, zock_id, true, ev);
    zf_muxer_mark_waitable_ready(&st->tcp[zock_id].w, EPOLLERR);
    break;
  case ZF_REQ_ID_PROTO_TCP_ALT:  /* not currently supported by EF_VI */
  case ZF_REQ_ID_PROTO_TCP_FREE: /* no segment data to report */
    break;
  }

  zf_reactor_handle_tx_event_unbundled(st, nic, vi, ev, 1);
}


ZF_COLD static void
zf_reactor_handle_rx_discard(struct zf_stack* st, int nic, const ef_event* ev)
{
  int discard_type = EF_EVENT_RX_DISCARD_TYPE(*ev);
  if( ZF_LIKELY(discard_type >= 0
      && discard_type < EF_EVENT_RX_DISCARD_MAX) ) {
    ++st->stats.discards[discard_type];
  }
  else {
    /* Presumably a new discard type has been added to ef_vi.
    Update zf_stack::stats::discards array to be the right
    size and add printing to zf_stackdump. */
    zf_assert(false);
  }
}


ZF_COLD static void
zf_reactor_handle_rx_ref_discard(struct zf_stack* st, int nic, ef_vi *vi,
                                 const ef_event* ev)
{
  uint16_t flags = ev->rx_ref_discard.flags;

  zf_log_event_trace(st, "%s: Packet %x is bad\n",
                     __FUNCTION__, ev->rx_ref_discard.pkt_id );

  /* Map to the common sets of discard stats. These are flags, so more than
   * one could apply, but for stats it's probably more useful to have one
   * event logged per discarded packet, so just record the first one. */
  if( flags & EF_VI_DISCARD_RX_ETH_FCS_ERR )
    ++st->stats.discards[EF_EVENT_RX_DISCARD_CRC_BAD];
  else if( flags & EF_VI_DISCARD_RX_L3_CSUM_ERR )
    ++st->stats.discards[EF_EVENT_RX_DISCARD_CSUM_BAD];
  else if( flags & EF_VI_DISCARD_RX_L4_CSUM_ERR )
    ++st->stats.discards[EF_EVENT_RX_DISCARD_CSUM_BAD];
  else
    ++st->stats.discards[EF_EVENT_RX_DISCARD_OTHER];

  efct_vi_rxpkt_release(vi, ev->rx_ref_discard.pkt_id);
}


/* This function places a packet prefix at `dest` for a received EFCT packet.
 * The `efpkt` parameter takes the value retrieved from `efct_vi_rxpkt_get` */
ZF_HOT static void
efct_pkt_prefix(ef_vi* vi, char* dest, const void* efpkt)
{
  ef_precisetime ts;
  int rc = ef_vi_receive_get_precise_timestamp(vi, efpkt, &ts);
  *(uint32_t*)(dest + RX_PREFIX_TSYNC_MAJOR_OFST) = ts.tv_sec;
  *(uint32_t*)(dest + RX_PREFIX_TSYNC_MINOR_OFST) = ts.tv_nsec;
  *(uint16_t*)(dest + RX_PREFIX_NICNO_OFST) = RX_PREFIX_NICNO_EFCT;
  *(uint16_t*)(dest + RX_PREFIX_TS_FLAGS_OFST) = ts.tv_flags;
  *(uint16_t*)(dest + RX_PREFIX_TS_RESULT_OFST) = -rc;
}


ZF_HOT static void
efct_pkt_memcpy(void* dst, const void* src, size_t n)
{
  __m128_u* vdst = (__m128_u*)dst;
  const __m128_u* vsrc = (const __m128_u*)src;
  size_t i;

  /* Both src and dst are larger than the largest supported MTU, so we can
   * launch straight in to doing big copies without having to worry about
   * overrunning. The below zf_assume checks this for dst, but we don't have
   * visibility here of the underlying size of the X3 superbufs, so we're
   * relying on secret knowledge. */
  n = (n + 15) >> 4;
  zf_assume_le(n * 16, PKT_BUF_SIZE_USABLE);
  zf_assume_gt(n, 0);
  for( i = 0; i < n; ++i )
    vdst[i] = vsrc[i];
}


ZF_COLD static void
zf_reactor_handle_reset_event(struct zf_stack* st)
{
  const struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);
  sti->reset_callback(sti->reset_callback_arg);
}

/* returns 1 if something interesting has happened */
ZF_HOT int
zf_reactor_process_event(struct zf_stack* st, int nic, ef_vi* vi, ef_event* ev)
{
  zf_assert(st);
  zf_assert(st->pool.pkt_bufs_n);
  zf_assert(st->pool.pkt_bufs);
  int rx_prefix_len = st->nic[nic].rx_prefix_len;
  uint32_t id;
  switch( EF_EVENT_TYPE(*ev) ) {
  case EF_EVENT_TYPE_RX: {
    /* This code does not handle jumbos. */
#ifndef NDEBUG
    if( EF_EVENT_RX_SOP(*ev) == 0 || EF_EVENT_RX_CONT(*ev) != 0 ) {
      zf_log_stack_trace(st, "unsupported jumbo frame received\n");
    }
    /* Note: jumbo frame will be discarded by frame len checking code */
#endif
    id = EF_EVENT_RX_RQ_ID(*ev);
    char* base = PKT_BUF_RX_START_BY_ID(&st->pool, id);

    zf_assert_le(id, UINT16_MAX);
    return zf_stack_handle_rx(st, nic, base, id,
                              EF_EVENT_RX_BYTES(*ev) - rx_prefix_len);
  }
  case EF_EVENT_TYPE_RX_REF: {
    zf_assume_equal(rx_prefix_len, ES_DZ_RX_PREFIX_SIZE);
    /* for EFCT id is generated by ef_vi and is a token identifying the
     * buffer within ef_vi for us it is opaque, but we could potentially
     * use it to discriminate among big buffers, if we had policy based on age
     * on how long to retain data in a given big buffer. */
    uint32_t elusive_id = ev->rx_ref.pkt_id;
    const void* space_start = efct_vi_rxpkt_get(vi, elusive_id);

    /* FIXME X3: With more changes to tcpdirect we could retain the elusive
     * packet and have it stored on socket's rxq. For now just copy on the
     * spot to our internal buffer. */
    id = zf_pool_get_free_pkt(&st->pool);
    if(ZF_UNLIKELY( id == PKT_INVALID )) {
      st->stats.ring_refill_nomem++;
      efct_vi_rxpkt_release(vi, elusive_id);
      break;
    }
    size_t frame_len = ev->rx_ref.len;
    char* base = PKT_BUF_RX_START_BY_ID(&st->pool, id);
    size_t space = ROUND_UP(((uintptr_t) base) | 1, PKT_BUF_SIZE) -
                   (uintptr_t) (base + rx_prefix_len);
    zf_assume_le(frame_len, space);

    efct_pkt_prefix(vi, base, space_start);
    efct_pkt_memcpy(base + rx_prefix_len, space_start, frame_len);
    efct_vi_rxpkt_release(vi, elusive_id);

    return zf_stack_handle_rx(st, nic, base, id, frame_len);
  }
  case EF_EVENT_TYPE_TX:
    zf_reactor_handle_tx_event(st, nic, vi, ev);
    break;
  case EF_EVENT_TYPE_TX_WITH_TIMESTAMP:
    zf_reactor_handle_tx_timestamp_event(st, nic, vi, ev);
    return 1;
  case EF_EVENT_TYPE_TX_ALT:
    return zf_alternatives_handle_event(st, nic, ev);
  case EF_EVENT_TYPE_RX_DISCARD:
    zf_reactor_handle_rx_discard(st, nic, ev);
    zf_pool_free_pkt(&st->pool, EF_EVENT_RX_RQ_ID(*ev));
    break;
  case EF_EVENT_TYPE_RX_REF_DISCARD:
    zf_reactor_handle_rx_ref_discard(st, nic, vi, ev);
    break;
  case EF_EVENT_TYPE_RESET:
    zf_reactor_handle_reset_event(st);
    break;
  default:
    zf_log_stack_err(st, "ERROR: unexpected event type=%d\n",
                     (int) EF_EVENT_TYPE(*ev));
    break;
  }
  return 0;
}


/* X3 leaves 2 padding bytes at the beginning of packets (so that the IP
 * header is 4-byte aligned, meaning that the first cache line has 62 data
 * bytes in it. When we see the poisoning disappear, therefore, this is the
 * number of bytes that we're allowed to read */
static constexpr size_t BYTES_IN_FIRST_EFCT_LINE = 62;

ZF_HOT static void
efct_copy_62(void* dst, const void* src)
{
  __m128i a, b, c, d;
  zf_assert_equal((uintptr_t)src & (ZF_CACHE_LINE_SIZE - 1), 2);
  a = _mm_loadu_si128((const __m128i*)src);
  b = _mm_load_si128((const __m128i*)((const char*)src + 14));
  c = _mm_load_si128((const __m128i*)((const char*)src + 14 + 16));
  d = _mm_load_si128((const __m128i*)((const char*)src + 14 + 32));
  _mm_storeu_si128((__m128i*)dst, a);
  _mm_storeu_si128((__m128i*)((char*)dst + 14), b);
  _mm_storeu_si128((__m128i*)((char*)dst + 14 + 16), c);
  _mm_storeu_si128((__m128i*)((char*)dst + 14 + 32), d);
}


/* When processing a packet from the future, we will eventually have to block
 * in wait for its RX event, so that we can either commit the processing for
 * the packet, or else roll back as necessary.
 *     Any dead time not consumed by protocol processing will be burned here,
 * and could be exposed by the API.  Coroutines??
 *
 * Return values:
 *
 *  0  - the expected RX event was received; no other user-visible
 *       events were seen
 *
 *  >0 - the expected RX event was received; other user-visible events
 *       were seen while waiting for it 
 *
 *  <0 - an error occurred 
 */
ZF_HOT int
zf_reactor_wait_for_rx_event(struct zf_stack* stack, int nic, pkt_id packet_id,
                             uint16_t len)
{
#ifndef NDEBUG
  constexpr int TOO_LONG = 100000000;
  int iterations = 0;
#endif
  int event_occurred = 0;
  ef_vi* vi = &stack->nic[nic].vi;

  while( true ) {
    /* We ask for a single event only, to avoid the complexity of having to
     * deal with an RX event subsequent to the one we're waiting for.  Strictly
     * speaking, this violates the ef_vi API, which stipulates that we must ask
     * for at least EF_VI_EVENT_POLL_MIN_EVS events, but on EF10 it's safe to
     * ignore this. */
    ef_event ev;
    unsigned n_ev = ef_eventq_poll(vi, &ev, 1);
    if( n_ev > 0 ) {
      zf_assume_equal(n_ev, 1);
      auto ev_type = EF_EVENT_TYPE(ev);
      if(ZF_LIKELY( ev_type == EF_EVENT_TYPE_RX )) {
        /* We received an RX event, which must be for the packet that we're
         * waiting for. */
        zf_assume_equal(EF_EVENT_RX_RQ_ID(ev), packet_id);
        zf_log_event_trace(stack, "%s: Packet %x has arrived\n",
                           __FUNCTION__, packet_id);
        if(ZF_UNLIKELY( len + stack->nic[nic].rx_prefix_len >
                        EF_EVENT_RX_BYTES(ev) ))
          return -EMSGSIZE;
        return event_occurred;
      }
      else if(ZF_LIKELY( ev_type == EF_EVENT_TYPE_RX_REF )) {
        zf_log_event_trace(stack, "%s: Packet %x (EFCT) has arrived\n",
                           __FUNCTION__, ev.rx_ref.pkt_id);
        zf_assume(stack->nic[nic].rx_prefix_len == ES_DZ_RX_PREFIX_SIZE);
        char* base = PKT_BUF_RX_START_BY_ID(&stack->pool, packet_id);
        const void* pkt = efct_vi_rxpkt_get(vi, ev.rx_ref.pkt_id);
        efct_pkt_prefix(vi, base, pkt);
        if( ev.rx_ref.len > BYTES_IN_FIRST_EFCT_LINE )
          efct_pkt_memcpy(base + ES_DZ_RX_PREFIX_SIZE + BYTES_IN_FIRST_EFCT_LINE,
                          stack->efct_current_rx + BYTES_IN_FIRST_EFCT_LINE,
                          ev.rx_ref.len - BYTES_IN_FIRST_EFCT_LINE);
        efct_vi_rxpkt_release(vi, ev.rx_ref.pkt_id);
        if(ZF_UNLIKELY( len > ev.rx_ref.len ))
          return -EMSGSIZE;
        return event_occurred;
      }
      else if( ev_type == EF_EVENT_TYPE_RX_DISCARD ) {
        /* Oh dear: something went wrong.  Let the caller know so that it can
         * do any rollback. */
        zf_assume_equal(EF_EVENT_RX_RQ_ID(ev), packet_id);
        zf_log_event_err(stack, "%s: Packet %x is bad\n",
                         __FUNCTION__, packet_id);
        return -EBADE;
      }
      else if( ev_type == EF_EVENT_TYPE_RX_REF_DISCARD ) {
        /* Not an error: we expect discards of unhandled packets from EFCT */
        zf_reactor_handle_rx_ref_discard(stack, nic, vi, &ev);
        return -EBADE;
      }
      else {
        /* Any other events can be processed as normal. */
        event_occurred |= zf_reactor_process_event(stack, nic, vi, &ev);
      }
    }

#ifndef NDEBUG
    ++iterations;
    zf_assert_lt(iterations, TOO_LONG);
#endif
  }
}


ZF_HOT int zf_pftf_wait(zf_stack* st, unsigned len)
{
  if( len > st->pftf.payload_len )
    len = st->pftf.payload_len;

  char* buf = st->pftf.payload;
  bool has_event = false;
  while( 1 ) {
    // ~1ns = ~1byte@10Gbps, 1ns ~ 3cycles
    // around as many nanos as bytes for 10Gbps:
    unsigned iterations = 100;
    for( unsigned i = iterations; i; i-- ) {
      /* 3 cycles */
      if( zfr_packet_portion_present(buf, len) )
        return len;
      /* 15 cycles */
      has_event = ef_eventq_has_event(&st->nic[st->future_nic_id].vi);
    }
    if( has_event )
      break;
  }
  return -1; /* Not found data before an event */
}


/* Returns non-zero iff a user-visible event occurred. */
static inline int
zf_reactor_process_timer(void* opaque, zf_timer_id id)
{
  struct zf_stack* st = (struct zf_stack*) opaque;
  struct zf_tcp* tcp = &st->tcp[id];
  return zf_tcp_timers_handle(tcp);
}


int zf_reactor_process_timers(struct zf_stack* st)
{
  /* Handle timers.  These might generate user-visible events, so propagate any
   * such to the caller. */
  int d = zf_timekeeping_check_tick(&st->times.time);
  return zf_wheel_tick_advance(&st->times.wheel, d, zf_reactor_process_timer,
                               (void*) st);
}


static int zf_reactor_process_tx_vi(struct zf_stack* st, int nic, ef_vi* vi)
{
  int got_it = 0;
  ef_event evs[16];
  int n_ev = ef_eventq_poll(vi, evs, sizeof(evs) / sizeof(evs[0]));
  for( int e = 0; e < n_ev; ++e )
    got_it |= zf_reactor_process_event(st, nic, vi, &evs[e]);
  return got_it;
}

/* Rx ring refilling
 *   Ring is attempted to be refilled each time __zf_reactor_perform()
 *   is called at the beginning of the function. The reason is that the
 *   beginning is the least likely moment the packet can arrive.
 *   However, pkt buffers are refilled in batches, and there must be enough
 *   space in the rx ring to have the actual refilling take place.
 *
 *   Additionally, rx ring is attempted to be refilled inside inner reactor loop.
 *   This refilling can be rate limited (every nth iteration). This additional
 *   refilling is only important when no user visible events happen to
 *   prevent the ring from running low.
 *
 *   Saturation scenario:
 *   In this scenario packets come at higher pace than can be handled by the
 *   application.
 *   And each call to __zf_reactor_perform will perform only one
 *   iteration, processing maximum number of events. Assuming this number is
 *   greater than the batch refill count, the rx ring will eventually be
 *   running in constant starvation mode.  This is good - the pkt loss is
 *   unavoidable while low number of pkt buffers in use will result in smaller
 *   working set.
 */
ZF_HOT static int
__zf_reactor_perform(struct zf_stack* st, unsigned spin_cnt)
{
  int rc = st->pftf.event_occurred_carry;
  st->pftf.event_occurred_carry = 0;
  if( rc )
    return rc;

  /* Refill rx ring */
  for( int nic = 0; nic < st->nics_n; ++nic ) {
    zf_stack_refill_rx_ring(st, nic, 0);
    if( zf_stack_nic_has_tx_vi(st, nic) &&
        ef_eventq_has_event(zf_stack_nic_tx_vi(st, nic)) ) {
        rc |= zf_reactor_process_tx_vi(st, nic, zf_stack_nic_tx_vi(st, nic));
    }
  }

  /* Check for LLAP staleness and pull any bond changes if necessary */
  if( st->encap_type & EF_CP_ENCAP_F_BOND )
    if(ZF_UNLIKELY( zf_bond_stale(st) ))
      zf_bond_update(st);

  zf_stack_udp_rx_flush(st);

  /* Flush pending TCP RX. */
  rc |= zf_stack_tcp_rx_flush(st);

  /* Handle timers.  These might generate user-visible events, so propagate any
   * such to the caller. */
  rc |= zf_reactor_process_timers(st);

  /* Handle deferred rebuilding of alternative queues. */
  if( ZF_UNLIKELY((st->alts_need_rebuild != 0) ||
                  (st->alts_rebuilding != 0)) )
    zf_alternatives_resend(st);

  /* Spin a little while until we find something to do. */
  unsigned refill_cnt = st->rx_ring_refill_interval;
  while( 1 ) {
    for( int i = 0; i < st->nics_n; ++i ) {
      int nic = st->next_poll_nic;
      ++st->next_poll_nic;
      if( st->next_poll_nic >= st->nics_n )
        st->next_poll_nic = 0;
      ef_vi* vi= &st->nic[nic].vi;

      if(ZF_LIKELY( !ef_eventq_has_event(vi) )) {
        if( ZF_LIKELY(ef_vi_receive_fill_level(vi) > 0) ) {
          /* We didn't see any events, so check for the presence of a packet
           * from the future in the next RX buffer. */
          pkt_id next_packet_id = 0;
          char* next_packet;
          bool is_efct = vi->nic_type.arch == EF_VI_ARCH_EFCT;
          bool packet_present;

          if( is_efct ) {
            char* vpkt = (char*)efct_vi_rx_future_peek(vi);
            packet_present = vpkt != NULL;
            if( packet_present ) {
              st->pftf.payload = vpkt;
              next_packet_id = zf_pool_get_free_pkt(&st->pool);
              if(ZF_UNLIKELY( next_packet_id == PKT_INVALID )) {
                /* Don't increment any counters here, because we'll be whizzing
                * around retrying really fast */
                continue;
              }
              zf_assume_equal(st->nic[nic].rx_prefix_len, ES_DZ_RX_PREFIX_SIZE);
              next_packet = PKT_BUF_RX_START_BY_ID(&st->pool, next_packet_id);
              efct_copy_62(next_packet + ES_DZ_RX_PREFIX_SIZE, vpkt);
              st->efct_current_rx = vpkt;
            }
          }
          else {
            next_packet_id = ef_vi_next_rx_rq_id(vi);
            next_packet = PKT_BUF_RX_START_BY_ID(&st->pool, next_packet_id);
            /* Is there a packet coming? */
            packet_present = zfr_packet_header_present(next_packet);
            if( packet_present )
              st->pftf.payload = next_packet;
          }

          if( packet_present ) {
            /* Record future state so that the protocol-handling paths can
             * act appropriately.  This is only needed if a packet is arriving,
             * but it's advantageous to set these sooner rather than later. */
            st->future_nic_id = nic;
            st->future_packet_id = next_packet_id;

            /* A packet is arriving from the future.  We can begin protocol-
             * processing in the hope that the rest of the packet arrives
             * successfully. */
            zf_log_event_trace(st, "%s: Packet %x is arriving\n",
                               __FUNCTION__, next_packet_id);

            /* Process the packet. We pass 0 as frame length, which indicates
             * this being a packet from the future. */
            int rc = zf_stack_handle_rx_pftf(st, nic, next_packet,
                                             next_packet_id);
            zf_assert_ge(rc, 0);

            if( rc != ZF_REACTOR_PFTF ) {
              /* Time-travel state should have been reset, and we should have
               * processed the RX/discard event for the packet. */
              zf_assert_lt(st->future_nic_id, 0);
              zf_assert_nequal(ef_vi_next_rx_rq_id(vi),
                               next_packet_id);
            }

            /* If the packet was bad or did not produce a user-visible event,
             * we'll loop back round and look at the event queue again.
             * Otherwise, let the caller know that something happened. */
            if(ZF_LIKELY( rc > 0 ))
              return rc;
          }

          /* No future RX at the moment: reset state. */
          st->future_nic_id = zf_stack::FUTURE_NIC_INVALID;
        }
      }
      else {
        /* We found events, so process them. */
        ef_event evs[16];
        unsigned n_ev = ef_eventq_poll(vi, evs,
                                       sizeof(evs) / sizeof(evs[0]));
        int gotit = 0;
        for( unsigned e = 0; e < n_ev; ++e )
          gotit |= zf_reactor_process_event(st, nic, vi, &evs[e]);
        if(ZF_LIKELY( gotit ))
          return 1;
      }

      /* If there is a receive user-visible event, then we return immediately.
       * In the case of transmit event we should process all other events.
       * It is necessary if user wants to send a large IP-fragmented
       * datagram. */
      if(ZF_UNLIKELY(
           ci_sllist_not_empty(&st->nic[nic].pollout_req_list) &&
           (unsigned) ef_vi_transmit_space(zf_stack_nic_tx_vi(st, nic)) > ZF_SEND_TXQ_THRESHOLD
           ) ) {
        while( ci_sllist_not_empty(&st->nic[nic].pollout_req_list) ) {
          struct zf_udp_tx* udp_tx;
          udp_tx = ZF_CONTAINER(struct zf_udp_tx, pollout_req,
                                ci_sllist_pop(&st->nic[nic].
                                                   pollout_req_list));
          zf_muxer_mark_waitable_ready(&udp_tx->w, EPOLLOUT);
        }
        return 1;
      }
    }
    --spin_cnt, --refill_cnt;
    if( spin_cnt == 0 )
      break;
    if( refill_cnt == 0 ) {
      for( int nic = 0; nic < st->nics_n; ++nic )
        zf_stack_refill_rx_ring(st, nic, 0);
      refill_cnt = st->rx_ring_refill_interval;
    }
  }

  return rc;
}

ZF_HOT int zf_reactor_perform(struct zf_stack* st)
{
  return __zf_reactor_perform(st, st->reactor_spin_count);
}

ZF_HOT int
zf_reactor_perform_attr(struct zf_stack* st, const struct zf_attr* attr)
{
  return __zf_reactor_perform(st, attr->reactor_spin_count);
}

/* zf_reactor_purge* are currently only used for test purpose to simulate loss,
 * however, they could be used for graceful cleanup of stack
 */
static int
zf_reactor_purge_event(struct zf_stack* st, int nic, ef_vi* vi, ef_event* ev)
{
  zf_assert(st);
  zf_assert(st->pool.pkt_bufs_n);
  zf_assert(st->pool.pkt_bufs);

  switch( EF_EVENT_TYPE(*ev) ) {
  case EF_EVENT_TYPE_RX:
    zf_assert_nequal(EF_EVENT_RX_SOP(*ev), 0);
    zf_assert_equal(EF_EVENT_RX_CONT(*ev), 0);
    zf_assert_nequal(vi->nic_type.arch, EF_VI_ARCH_EFCT);
    zf_pool_free_pkt(&st->pool, EF_EVENT_RX_RQ_ID(*ev));
    zf_log_event_trace(st, "%s: purged event %x\n", __FUNCTION__,
                       EF_EVENT_RX_RQ_ID(*ev));
    return ZF_REACTOR_PURGE_STATUS_RX;
  case EF_EVENT_TYPE_TX:
    zf_reactor_handle_tx_event(st, nic, vi, ev);
    return ZF_REACTOR_PURGE_STATUS_TX;
  case EF_EVENT_TYPE_RX_REF:
    zf_assert_equal(vi->nic_type.arch, EF_VI_ARCH_EFCT);
    efct_vi_rxpkt_release(vi, ev->rx_ref.pkt_id);
    zf_log_event_trace(st, "%s: purged event %x\n", __FUNCTION__, ev->rx_ref.pkt_id);
    return ZF_REACTOR_PURGE_STATUS_RX;
  default:
    zf_reactor_process_event(st, nic, vi, ev);
    break;
  }
  return ZF_REACTOR_PURGE_STATUS_IDLE;
}


int zf_reactor_purge(struct zf_stack* st)
{
  int gotit = 0;
  for( int nic = 0; nic < st->nics_n; ++nic ) {
    ef_event evs[16];
    auto process_vi = [&] (ef_vi* vi) {
      int n_ev = ef_eventq_poll(vi, evs,
                              sizeof(evs) / sizeof(evs[0]));
      for( int e = 0; e < n_ev; ++e )
          gotit |= zf_reactor_purge_event(st, nic, vi, &evs[e]);
    };
    process_vi(&st->nic[nic].vi);
    if( zf_stack_nic_has_tx_vi(st, nic) )
      process_vi(zf_stack_nic_tx_vi(st, nic));
  }
  return gotit;
}


ZF_HOT int zf_stack_has_pending_events(const struct zf_stack* st)
{
  for( int nic = 0; nic < st->nics_n; ++nic )
    if( ef_eventq_has_event(&st->nic[nic].vi) )
      return 1;
  return 0;
}


ZF_HOT int zf_stack_has_pending_work(const struct zf_stack* st)
{
  for( int nic = 0; nic < st->nics_n; ++nic )
    if( ef_eventq_has_event(&st->nic[nic].vi) )
      return 1;

  for( int nic = 0; nic < st->nics_n; ++nic )
    if( zf_stack_nic_has_tx_vi(st, nic) &&
        ef_eventq_has_event(zf_stack_nic_tx_vi(st, nic)) )
        return 1;
  /* This test checks to see if there are any TCP sockets before doing
   * TCP-specific tests, as some of them (e.g. elapsed_ticks) take
   * significant numbers of instructions and limit the rate at which
   * this function can be called.
   *
   * The check is slightly stricter than necessary - true if TCP
   * zockets have ever been allocated - but avoids extra state.
   */
  const struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);
  if( (sti->tcp.alloc_state.next_lazy_index != 0) ||
      (sti->tcp_listen.alloc_state.next_lazy_index != 0) ) {
    if( st->tcp_deferred_rx_bitmap != 0 )
      return 1;

    /* ZF alts are currently TCP only, so safe to require TCP zocket
     * allocated before performing this check */
    if( ZF_UNLIKELY((st->alts_need_rebuild != 0) ||
                    (st->alts_rebuilding != 0)) )
      return 1;

    if( zf_timekeeping_elapsed_ticks(&st->times.time) )
      return 1;
  }

  return 0;
}
