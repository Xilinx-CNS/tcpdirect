/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_STACK_RX_H__
#define __ZF_INTERNAL_STACK_RX_H__

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
#include <zf_internal/zf_pool_res.h>
#include <zf_internal/lazy_alloc.h>
#include <zf_internal/tx_res.h>
#include <zf_internal/bitmap.h>

#include <zf_internal/allocator.h>
#include <zf_internal/utils.h>

#include <zf_internal/zf_stack_common.h>
#include <zf_internal/private/zf_stack_def.h>
#include <zf_internal/private/reactor.h>
#include <zf_internal/private/tcp_fast.h>

#include <etherfabric/ef_vi.h>

extern int
tcp_input(struct zf_stack* stack, struct zf_tcp* tcp,
          struct tcphdr* tcp_hdr, size_t segment_len);


ZF_HOT static inline void
zf_stack_tcp_set_deferred_rx(struct zf_stack* stack, uint64_t zocket_mask)
{
  zf_assume(ZF_IS_POW2(zocket_mask));
  stack->tcp_deferred_rx_bitmap |= zocket_mask;
}

ZF_HOT static inline void
zf_stack_tcp_clear_deferred_rx(struct zf_stack* stack, int index)
{
  zf_bitmap_word_clear_bit(&stack->tcp_deferred_rx_bitmap, index);
}

/* Get the index of the next zocket in the set of those pending RX processing,
 * and remove that zocket from the set.  The caller must ensure that there is
 * at least one such zocket. */
static inline int
zf_stack_tcp_pop_deferred_rx(struct zf_stack* stack)
{
  return zf_bitmap_word_pop_bit(&stack->tcp_deferred_rx_bitmap);
}

ZF_HOT static inline void
zf_stack_udp_set_deferred_rx(struct zf_stack* stack, uint64_t zocket_mask)
{
  zf_assume(ZF_IS_POW2(zocket_mask));
  stack->udp_deferred_rx_bitmap |= zocket_mask;
}

ZF_HOT static inline void
zf_stack_udp_clear_deferred_rx(struct zf_stack* stack, int index)
{
  zf_bitmap_word_clear_bit(&stack->udp_deferred_rx_bitmap, index);
}

static inline int
zf_stack_udp_pop_deferred_rx(struct zf_stack* stack)
{
  return zf_bitmap_word_pop_bit(&stack->udp_deferred_rx_bitmap);
}


/* Ensure that the current RX packet has arrived successfully.  If we're
 * reading a packet from the future, this means waiting for it to arrive and
 * checking that this succeeds; otherwise, we succeed trivially. 
 *
 * Return values:
 *
 *   0 - the packet was received; no other user-visible events were
 *       seen
 *
 *  >0 - the packet was received; other user-visible events were seen
 *       while waiting for it
 *
 *  <0 - an error occurred 
 */
ZF_HOT static inline int
zf_stack_sync_future_rx(struct zf_stack* stack, uint16_t hw_frame_len,
                                                uint16_t derived_frame_len)
{
  int nic = stack->future_nic_id;
  if(ZF_UNLIKELY( nic < 0 ))
    return derived_frame_len <= hw_frame_len ? 0 : -EMSGSIZE;
  stack->future_nic_id = zf_stack::FUTURE_NIC_INVALID;

  zf_assume_nequal(stack->future_packet_id, PKT_INVALID);
  return zf_reactor_wait_for_rx_event(stack, nic, stack->future_packet_id,
                                      derived_frame_len);
}


/* Only ACK and PSH flags may be set */
ZF_HOT static inline int /* bool */ tcp_flags_frequent(struct tcphdr* tcp_hdr)
{
  return !tcp_hdr->fin && !tcp_hdr->syn && !tcp_hdr->rst && !tcp_hdr->urg;
}


ZF_HOT static inline int /* bool */
tcp_test_frequent_path(struct tcp_pcb* pcb, struct tcphdr* tcp_hdr,
                       uint32_t seq_he, uint32_t ack_he, uint32_t len,
                       struct zf_rx_ring* rx_ring)
{
  return seq_he == pcb->rcv_nxt &&
    TCP_SEQ_BETWEEN(ack_he, pcb->lastack, pcb->snd_nxt) &&
    len > 0 &&
    tcp_hdr->doff == TCP_DOFF_NO_OPTIONS &&
    tcp_flags_frequent(tcp_hdr) &&
    pcb->state == ESTABLISHED &&
    TCP_SEQ_LEQ(seq_he + len, pcb->rd_nxt + TCP_WND) &&
    zfr_tcp_queue_has_space(rx_ring);
}

#ifdef ZF_DEVEL
/* hook for verification and selectively dropping incoming frames */
extern "C" __attribute__((weak))
int tcp_frame_hook(zf_tcp* tcp, const char* data, uint32_t len, uint32_t seq)
  { return 1; }
#endif

ZF_HOT static inline int
zf_stack_handle_rx_tcp(struct zf_stack* stack, const char* iov_base,
                       const iphdr* ip_hdr, uint16_t len)
{
  zf_log_event_trace(stack, "%s:\n", __FUNCTION__);

  const uint16_t ip_hdr_len = ip_hdr->ihl * 4;
  const uint16_t tot_len = zf_ntohs(ip_hdr->tot_len);
  const uint16_t frame_len = (char*)ip_hdr + tot_len - iov_base;
  /* N.B.: Not const!  Will be modified by TCP processing. */
  struct tcphdr* tcp_hdr = (struct tcphdr*) ((char*) ip_hdr + ip_hdr_len);
  /* Claimed length of the tcp header */
  const uint16_t tcp_hdr_len = tcp_hdr->doff * 4;
  /* Remaining length of the buffer including tcp header and payload */
  const uint16_t tcp_len = tot_len - ip_hdr_len;
  int rc = 0;


  zf_assume_ge(tcp_len, BASE_TCP_HDR_LEN);
  /* This is a bit of a hacky optimisation to check both that tcp_hdr_len < 20
   * AND tcp_hdr_len > tcp_len can be done in a single comparison.
   * This can be done in a single comparison by utilising the fact that unsigned
   * values will wrap around if they go "below" 0. By assuming tcp_len > 20 and
   * so tcp_len - 20 > 0, then if tcp_hdr_len - 20 wraps around it will be
   * greater than tcp_len - 20.
   * A more readable version of the check would be:
   * tcp_hdr_len < 20 || tcp_hdr_len > tcp_len
   */
  if(ZF_UNLIKELY((uint16_t)(tcp_hdr_len - BASE_TCP_HDR_LEN) >
                 (uint16_t)(tcp_len - BASE_TCP_HDR_LEN))) {
    zf_log_event_warn(stack, "Bad data offset in tcp header.\n");
    dump_pkt(stack, iov_base, len);
    rc = zf_stack_sync_future_rx(stack, len, frame_len);
    zf_pool_free_pkt(&stack->pool, PKT_BUF_ID_FROM_PTR(&stack->pool, iov_base));
    return rc > 0;
  }

  uint16_t index;
  if(ZF_LIKELY( zf_rx_table_lookup(stack->rx_table[ZF_STACK_RX_TABLE_TCP],
                         ip_hdr->daddr, ip_hdr->saddr, tcp_hdr->dest,
                         tcp_hdr->source, &index) == 0 )) {
    struct zf_tcp* tcp = &stack->tcp[index];
    int event_occurred = 1;

    zf_log_tcp_rx_trace(tcp, "%s: seq %u (%u) ack %u\n", __func__,
                        ntohl(tcp_hdr->seq), tcp_len-BASE_TCP_HDR_LEN,
                        iov_base, len, ntohl(tcp_hdr->ack_seq));

    /* We must ensure that we have flushed deferred TCP processing before
     * enqueuing further RX segments. */
    if(ZF_LIKELY( tcp_test_frequent_path(&tcp->pcb, tcp_hdr,
                                         ntohl(tcp_hdr->seq),
                                         ntohl(tcp_hdr->ack_seq),
                                         tcp_len-BASE_TCP_HDR_LEN,
                                         &tcp->tsr.ring) &&
                  zfr_queue_all_packets_processed(&tcp->tsr) )) {
      char* payload = (char*)tcp_hdr + BASE_TCP_HDR_LEN;
      uint16_t payload_len = tcp_len - BASE_TCP_HDR_LEN;

      zf_assume(tcp_hdr->ack);

      tcp_cut_through(tcp, payload, payload_len);

      if( len == 0 &&
          tcp->w.event.events & ZF_EPOLLIN_OVERLAPPED &&
          /* make sure there has been no other pkt on rxq */
          zfr_queue_packets_unread_n(&tcp->tsr) == 1 ) {
        zf_assert_nflags(tcp->w.readiness_mask, ZF_EPOLLIN_OVERLAPPED);

        zf_muxer_mark_waitable_not_ready(&tcp->w, EPOLLIN);
        stack->pftf.w = &tcp->w;
        stack->pftf.frame_len = frame_len;
        stack->pftf.payload_len = payload_len;
        stack->pftf.payload += payload - iov_base;
        zf_log_tcp_rx_trace(tcp, "%s: PFTF %x data %p len %d\n", __func__,
                            PKT_BUF_ID_FROM_PTR(&stack->pool, payload),
                            iov_base, len);
        return ZF_REACTOR_PFTF;
      }

      rc = zf_stack_sync_future_rx(stack, len, frame_len);
      if( rc > 0 )
        event_occurred |= rc;
      if(ZF_UNLIKELY( rc < 0 )) {
        tcp_cut_through_rollback(tcp, payload_len);
        goto receive_error;
      }

#ifdef ZF_DEVEL
      if( !tcp_frame_hook(tcp, payload, payload_len, ntohl(tcp_hdr->seq)) ) {
        tcp_cut_through_rollback(tcp, payload_len);
        rc = -ENOBUFS;
        goto receive_error;
      }
#endif

      return event_occurred;
    }
    else {
      event_occurred = tcp_rx_flush(stack, tcp);
      zf_assume(zfr_queue_all_packets_processed(&tcp->tsr));

      /* FIXME: For the proof of concept future-packet implementation, we wait
       * for the event as soon as we've done the demux.  This requires no
       * rollback if things go wrong, but there is potentially more to be gained
       * by doing more processing first. */
      rc = zf_stack_sync_future_rx(stack, len, frame_len);

      if(ZF_UNLIKELY( rc < 0 ))
        goto receive_error;

#ifdef ZF_DEVEL
      if( !tcp_frame_hook(tcp, (char*)tcp_hdr + BASE_TCP_HDR_LEN,
                          tcp_len - BASE_TCP_HDR_LEN, ntohl(tcp_hdr->seq)) ) {
        rc = -ENOBUFS;
        goto receive_error;
      }
#endif

      event_occurred |= rc;

      event_occurred |= tcp_input(stack, tcp, tcp_hdr, tcp_len);

      zf_assume(zfr_queue_all_packets_processed(&tcp->tsr));

      return event_occurred;
    }
  }
  else if( zf_rx_table_lookup(stack->rx_table[ZF_STACK_RX_TABLE_TCP_LISTEN],
                         ip_hdr->daddr, 0, tcp_hdr->dest, 0, &index) == 0 ) {
    /* FIXME: As above. */
    rc = zf_stack_sync_future_rx(stack, len, frame_len);
    if(ZF_UNLIKELY( rc < 0 ))
      goto receive_error;

    const struct ethhdr* eth_hdr = (const struct ethhdr*) iov_base;
    return tcp_listen_input(stack, &stack->tcp_listen[index], eth_hdr, ip_hdr,
                            tcp_hdr) || rc;
  }

  /* No match.  Wait for it to appear from the future if necessary before
   * complaining about it and freeing it.  We complain only if it arrived
   * successfully, but must free it either way. */
  rc = zf_stack_sync_future_rx(stack, len, frame_len);

receive_error:
  if(ZF_UNLIKELY( rc >= 0 )) {
#ifndef NDEBUG
    zf_log_event_warn(stack, "No RX-lookup match.  TCP Packet:\n");
    dump_pkt(stack, iov_base, len);
#endif
  }

  zf_pool_free_pkt(&stack->pool, PKT_BUF_ID_FROM_PTR(&stack->pool, iov_base));
  return rc > 0;
}

/* Waits for pftf event completion, returns true if packet is good */
ZF_HOT static inline bool
zf_stack_tcp_finish_pftf(zf_stack* st, zf_tcp* tcp)
{
  zf_assert(st->pftf.w);
  zf_assert_equal(st->pftf.w, &tcp->w);

  st->pftf.w = NULL;

  uint16_t frame_len = st->pftf.frame_len;
  int rc = zf_stack_sync_future_rx(st, 0, frame_len);

  if( rc >= 0 ) {
    /* Remember that some other user visible event occurred */
    st->pftf.event_occurred_carry = rc;
    /* Return true that we received the successfull event addressing outstanding pftf
     * This will always be an user visible event */
    return true;
  }

  /* packet got discarded, lets rollback, discarded packet is never
   * an user visible event */
  uint16_t payload_len = st->pftf.payload_len;
  tcp_cut_through_rollback(tcp, payload_len);

  char* payload = st->pftf.payload;
  zf_pool_free_pkt(&st->pool, PKT_BUF_ID_FROM_PTR(&st->pool, payload));
  return false;
}


ZF_HOT static inline int
__zf_stack_handle_rx_udp(struct zf_stack* st, struct zf_udp_rx* udp_rx,
                         char* iov_base, unsigned len)
{
  struct zf_rx *rx = &udp_rx->rx;
  struct iovec iov = {
    .iov_base = iov_base,
    .iov_len = len
  };
  struct iovec* iov_p = &iov;

  if(ZF_LIKELY( zfr_udp_queue_has_space(&rx->ring) )) {
    zf_log_udp_rx_trace(udp_rx, "%s: pkt %x data %p len %d\n", __func__,
                        PKT_BUF_ID_FROM_PTR(&st->pool, iov_base),
                        iov_base, len);
    zfr_pkt_queue(&rx->ring, iov_p);
    ++iov_p;
    zf_muxer_mark_waitable_ready(&udp_rx->w, EPOLLIN);
    return true;
  }

  /* No space in RX ring. */
  zf_log_udp_rx_trace(udp_rx, "%s: drop pkt %x data %p len %d\n", __func__,
                      PKT_BUF_ID_FROM_PTR(&st->pool, iov_base),
                      iov_base, len);
  zf_pool_free_pkt(&st->pool, PKT_BUF_ID_FROM_PTR(&st->pool, iov_base));
  ++udp_rx->counters.q_drops;
  return false;
}


ZF_HOT static inline int
zf_stack_handle_rx_udp(struct zf_stack* st, const char* iov_base,
                       const iphdr* ip, uint16_t len)
{
  zf_log_event_trace(st, "%s:\n", __FUNCTION__);

  const struct udphdr* udp = (const struct udphdr*)
                             (((const char*)ip) + (ip->ihl*4));
  uint16_t tot_len = zf_ntohs(ip->tot_len);
  uint16_t frame_len = (char*)ip + tot_len - iov_base;
  int rc;
  uint16_t index;
  /* Do a full-match lookup first, as these must take priority over wild
   * matches. */
  if(ZF_LIKELY( zf_rx_table_lookup(st->rx_table[ZF_STACK_RX_TABLE_UDP],
                         ip->daddr, ip->saddr, udp->dest, udp->source,
                         &index) == 0 ||
      zf_rx_table_lookup(st->rx_table[ZF_STACK_RX_TABLE_UDP],
                         ip->daddr, 0, udp->dest, 0, &index) == 0 )) {
    struct zf_udp_rx* udp_rx = &st->udp_rx[index];

    if( len == 0 &&
        udp_rx->w.event.events & ZF_EPOLLIN_OVERLAPPED ) {

      zf_assert_nflags(udp_rx->w.readiness_mask, ZF_EPOLLIN_OVERLAPPED);

      st->pftf.w = &udp_rx->w;
      st->pftf.frame_len = frame_len;
      st->pftf.payload_len = tot_len - (ip->ihl*4) - sizeof(udphdr);
      st->pftf.copied_payload = (char*) (udp + 1);
      st->pftf.payload += (char*) (udp + 1) - iov_base;
      zf_log_udp_rx_trace(udp_rx, "%s: PFTF %x data %p len %d\n", __func__,
                        PKT_BUF_ID_FROM_PTR(&st->pool, iov_base),
                        iov_base, len);
      return ZF_REACTOR_PFTF;
    }

    /* Wait for future RX to complete.  There is no rollback to do if this
     * fails. */
    rc = zf_stack_sync_future_rx(st, len, frame_len);
    if(ZF_UNLIKELY( rc < 0 ))
      goto receive_error;

    return __zf_stack_handle_rx_udp(st, udp_rx, ((char*)udp) + sizeof(udphdr),
                                    tot_len - (ip->ihl*4) -
                                    sizeof(udphdr)) || rc;
  }

  /* No match.  Wait for it to appear from the future if necessary before
   * complaining about it and freeing it.  We complain only if it arrived
   * successfully, but must free it either way. */
  rc = zf_stack_sync_future_rx(st, len, frame_len);

receive_error:
  if(ZF_UNLIKELY( rc >= 0 )) {
#ifndef NDEBUG
    zf_log_event_warn(st, "No RX-lookup match.  UDP Packet:\n");
    dump_pkt(st, iov_base, frame_len);
#endif
  }

  zf_pool_free_pkt(&st->pool, PKT_BUF_ID_FROM_PTR(&st->pool, iov_base));
  return rc > 0;
}

ZF_HOT static inline bool
zf_stack_udp_finish_pftf(struct zf_stack* st, struct zf_udp_rx* udp_rx)
{
  zf_assert(st->pftf.w);
  zf_assert_equal(st->pftf.w, &udp_rx->w);

  st->pftf.w = NULL;

  uint16_t frame_len = st->pftf.frame_len;
  int rc = zf_stack_sync_future_rx(st, 0, frame_len);

  char* payload = st->pftf.copied_payload;
  uint16_t payload_len = st->pftf.payload_len;
  if( rc >= 0 ) {
    /* we cannot handle event occurred now, we need to report it at next
     * reactor perform */
    st->pftf.event_occurred_carry = rc;
    return __zf_stack_handle_rx_udp(st, udp_rx, payload, payload_len);
  }

  zf_pool_free_pkt(&st->pool, PKT_BUF_ID_FROM_PTR(&st->pool, payload));
  return false;
}

extern void
zf_stack_udp_rx_flush(struct zf_stack* stack);

extern int
zf_stack_tcp_rx_flush(struct zf_stack* stack);

extern ZF_HOT int
zf_stack_handle_rx(struct zf_stack* st, int nic, const char* iov_base,
                   pkt_id id, uint16_t frame_len);
extern ZF_HOT int
zf_stack_handle_rx_pftf(struct zf_stack* st, int nic, const char* iov_base,
                        pkt_id id);


#endif /* __ZF_INTERNAL_STACK_RX_H__ */
