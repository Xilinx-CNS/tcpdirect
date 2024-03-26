/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/tcp.h>
#include <zf_internal/tcp_tx.h>
#include <zf_internal/zf_tcp.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_stack_impl.h>


static inline zf_alt *zf_alternatives_find(struct zf_stack *stack,
                                           zf_althandle handle)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl,
                                           st, stack);
  if( handle >= (unsigned) sti->n_alts )
    return NULL;
  else
    return &sti->alt[handle];
}


int zf_alternatives_alloc(struct zf_stack* stack,
                          const struct zf_attr* attr,
                          zf_althandle* out)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl,
                                           st, stack);

  for( int i = 0; i < sti->n_alts; ++i ) {
    if( !sti->alt[i].is_allocated ) {
      sti->alt[i].is_allocated = 1;
      sti->alt[i].alt_zocket = NULL;
      sti->alt[i].n_prealloc = 0;

      /* Note: we must not reset n_queued_packets or is_draining here,
       * because it is possible for an alternative to be freed and
       * reallocated while it is still in flight. */
      
      *out = i;

      return 0;
    }
  }

  return -ENOMEM;
}


void zf_alternatives_discard(struct zf_stack* stack, struct zf_alt* alt)
{
  ef_vi_transmit_alt_discard(zf_stack_nic_tx_vi(stack, 0), alt->handle);

  if( alt->n_queued_packets > 0 )
    alt->is_draining = 1;
  if( alt->alt_zocket != NULL )
    alt->alt_zocket->zocket_alts &= ~(1 << alt->handle);
  stack->alts_need_rebuild &= ~(1 << alt->handle);
  stack->alts_rebuilding &= ~(1 << alt->handle);
  alt->tcp.altq.middle = alt->tcp.altq.end;

  /* We shouldn't have anything on the prealloc queue if we don't have any
   * queued packets.
   */
  zf_assert_impl(alt->n_prealloc, alt->n_queued_packets);
  for( int i = 0; i < alt->n_prealloc; i++ ) {
    zf_assert_nequal(alt->prealloc[i], PKT_INVALID);
    zf_pool_free_pkt(&stack->pool, alt->prealloc[i]);
  }
  alt->n_prealloc = 0;

  /* Note: we have told the hardware to _start_ draining this
   * alternative; however we have not waited for it to _finish_, and
   * it is possible that the alt can be reallocated before this has
   * occurred, so we must keep the values of n_queued_packets and
   * is_draining.
   *
   * The altq will be freed once the queue has drained.
   */
  alt->alt_zocket = NULL;
}


void zf_alternatives_release_impl(struct zf_stack* stack, 
                                  struct zf_alt* alt)
{
  zf_alternatives_discard(stack, alt);
  alt->is_allocated = 0;
}


int zf_alternatives_release(struct zf_stack* stack, 
                            zf_althandle althandle)
{
  struct zf_alt* alt = zf_alternatives_find(stack, althandle);
  zf_alternatives_release_impl(stack, alt);

  return 0;
}


int zf_alternatives_cancel(struct zf_stack* stack, zf_althandle althandle)
{
  struct zf_alt* alt = zf_alternatives_find(stack, althandle);

  if( ZF_UNLIKELY(alt->alt_zocket == NULL) )
    return 0;

  zf_alternatives_discard(stack, alt);
  return 0;
}


/* zf_alternatives_send() consists of a latency-critical initial
 * doorbell write followed by a bunch of fixup work including
 * cancelling the other alternatives and putting the sent data into
 * the retransmission queue.
 *
 * Putting this fixup work in a separate, non-inlined function means
 * that its prologue happens _after_ the critical doorbell write, not
 * before. */

static int ZF_NOINLINE zf_alternatives_send2(struct zf_stack* stack,
                                             zf_althandle althandle);

int zf_alternatives_send(struct zf_stack* stack, zf_althandle althandle)
{
  struct zf_alt* alt = zf_alternatives_find(stack, althandle);

  if( ZF_UNLIKELY(alt->alt_zocket == NULL) )
    return 0;

  struct tcp_pcb* pcb = &alt->alt_zocket->pcb;

  if( ZF_UNLIKELY(!(pcb->state & FAST_SEND_STATE_MASK)) )
    return -EINVAL;

  if( ZF_UNLIKELY(tcp_has_unsent(&pcb->sendq)) )
    return -EINVAL;

  zf_assert_equal(pcb->snd_lbb, pcb->snd_nxt);

  if( ZF_UNLIKELY(pcb->snd_lbb != alt->tcp.first_byte) )
    return -EINVAL;

  if( ZF_UNLIKELY(alt->is_draining) )
    return -EBUSY;

  uint32_t busy = stack->alts_need_rebuild | stack->alts_rebuilding;
  if( ZF_UNLIKELY(busy & (1 << althandle)) )
    return -EBUSY;

  ef_vi_transmit_alt_go(zf_stack_nic_tx_vi(stack, 0), alt->handle);

  return zf_alternatives_send2(stack, althandle);
}


static int ZF_NOINLINE zf_alternatives_send2(struct zf_stack* stack,
                                             zf_althandle althandle)
{
  struct zf_alt* alt = zf_alternatives_find(stack, althandle);
  struct tcp_pcb* pcb = &alt->alt_zocket->pcb;
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, pcb, pcb);

  tcp_output_timers_common(stack, tcp, alt->tcp.alt_snd_nxt);

  if( alt->n_queued_packets )
    alt->is_draining = 1;
  alt->alt_zocket->zocket_alts &= ~(1 << alt->handle);

  /* Add the sent data to the retransmission queue.
   *
   * We don't have a sensible error path here, so we can't allow this to
   * fail.  However, we want to use the common tcp_queue_sent_segments function
   * for appropriately adding data to the send queue, and this function
   * will allocate packets for the segments being queued.  We know that we
   * have sufficient segments on the sendq, as this was checked when the
   * data was queued.  To handle the packets case we maintain extra
   * packets, which we free now, so that we know pkts will be available for
   * tcp_queue_sent_segments to use.
   */
  zf_assert_impl(alt->n_prealloc == 0, alt->n_queued_packets == 0);
  for( int i = 0; i < alt->n_prealloc; i++ ) {
    zf_assert_nequal(alt->prealloc[i], PKT_INVALID);
    zf_pool_free_pkt(&stack->pool, alt->prealloc[i]);
  }
  alt->n_prealloc = 0;

  tcp_send_queue* altq = &alt->tcp.altq;
  zf_assert_equal(altq->begin, altq->middle);
  for( uint16_t idx = altq->begin; idx != altq->end; idx++ ) {
    zf_assert_gt(tcp_snd_buf_avail(pcb, &pcb->sendq), 0);

    tcp_seg* seg = tcp_seg_at(altq, idx);
    iovec iov = seg->iov;

    /* We only want to queue the payload, so strip the header. */
    iov.iov_base = (char*)iov.iov_base + TCP_HLEN;
    iov.iov_len -= TCP_HLEN;
    zf_assert_equal(iov.iov_len, seg->len);

    int segs = tcp_queue_sent_segments(tcp, &pcb->sendq, &iov, &pcb->snd_lbb);
    zf_assert_ge(segs, 0);

    /* Set the PSH flag.  This is only relevant for retranmissions, but we
     * would like it set on those, and in fact we need it set to avoid
     * tcp_output assuming this is a segment with MSG_MORE set, and never
     * retransmitting it.
     */
    tcp_seg_tcphdr(tcp_seg_last(&pcb->sendq))->psh = 1;

    alt->tcp.altq.middle++;
  }

  /* The altq should now be entirely transferred to the sendq, but not
   * yet completed by the HW.
   */
  zf_assert_equal(altq->middle, altq->end);
  zf_assert_gt((int16_t)(altq->middle - altq->begin), 0);

  /* We've just queued stuff on the end of the sendq, and it's all been sent */
  zf_assert_equal(pcb->sendq.middle, pcb->sendq.end);

  /* Update pcb state */
  zf_assert_equal(alt->tcp.alt_snd_nxt, pcb->snd_lbb);
  pcb->snd_nxt = pcb->snd_lbb;
  pcb->snd_buf = tcp_snd_buf_avail(pcb, &pcb->sendq);

  /* The interaction between delayed ACKs and alternatives is tricky since the
   * ACKs in the packets that we've just sent to the wire could be stale, and
   * so in general we can't clear the delayed-ACK state. */
  auto hdr = tcp_seg_tcphdr(tcp_seg_last(altq));
  if( ntohl(hdr->ack_seq) == pcb->rcv_nxt ) {
    /* The alternative send acked all rx, so update state accordingly */
    tcp_tx_cancel_delayed_ack(tcp);
  }
  else {
    /* It is desirable tosuppress the ACK-the-next-packet-immediately behaviour
     * in the case where the sequence of events is "RX, alt_send, RX", though,
     * and clearing this flag does exactly that. */
    pcb->flags &= ~TF_ACK_NEXT;
  }
  /* Record what information on our receive window has been sent to peer */
  uint32_t new_ann_right_edge = ntohl(hdr->ack_seq) + ntohs(hdr->window);
  if( TCP_SEQ_GT(new_ann_right_edge, pcb->rcv_ann_right_edge) )
    pcb->rcv_ann_right_edge = new_ann_right_edge;

  tcp_fix_fast_send_length(pcb);

  /* Update writability of this zocket. */
  struct zf_waitable* w = &alt->alt_zocket->w;
  if( ! tcp_tx_advertise_space(alt->alt_zocket) ) {
    zf_log_tcp_tx_trace(alt->alt_zocket, 
                        "%s: clearing EPOLLOUT\n", __FUNCTION__);
    zf_muxer_mark_waitable_not_ready(w, EPOLLOUT);
  }
  else {
    zf_assert(w->readiness_mask & EPOLLOUT);
  }

  /* Alternative can now be used with a different zocket */
  alt->alt_zocket = NULL;

  return 0;
}


int zf_alternatives_handle_event(struct zf_stack* st, int nic, ef_event* ev)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);
  int alt_id = EF_EVENT_TX_ALT_ALT_ID(*ev);
  struct zf_alt* alt = &sti->alt[alt_id];

  zf_assert_equal(alt->is_draining, 1);
  zf_assert_gt(alt->n_queued_packets, 0);

  alt->n_queued_packets -= 1;

  if( alt->n_queued_packets == 0 ) {
    tcp_send_queue* altq = &alt->tcp.altq;
    alt->is_draining = 0;

    zf_assert_impl(altq->middle == altq->end,
                   !(st->alts_rebuilding & (1<<alt_id)));

    if( altq->middle == altq->end ) {
      /* The altq has been sent or cancelled.  We don't free the buffers in
       * the rebuild case, where altq->middle == altq->end, as we re-use the
       * same buffers when re-queueing.
       */
      zf_assert_gt((int16_t)(altq->middle - altq->begin), 0);
      tcp_send_queue* altq = &alt->tcp.altq;
      for( uint16_t idx = altq->begin; idx != altq->end; idx++ ) {
        tcp_seg_free(&st->pool, tcp_seg_at(altq, idx));
        altq->begin++;
      }
    }

    zf_altbm_alt_reset(&sti->alt_buf_model, alt_id);

    if( st->alts_need_rebuild & (1 << alt_id) ) {
      /* Now that this alt has drained completely, we need to rebuild
       * and resend its desired contents. */
      ef_vi_transmit_alt_stop(zf_stack_nic_tx_vi(st, 0), alt_id);
      st->alts_rebuilding |= (1 << alt_id);
      st->alts_need_rebuild &= ~(1 << alt_id);
      zf_alternatives_resend(st);
    }
    return 1;
  }
  return 0;
}


/* Make as much progress as possible on retransmitting queued data
 * into alternatives. While doing so, keep the state updated so that
 * we can stop at any time if the ring fills up, and restart from the
 * same point when more space becomes available. */
void zf_alternatives_resend(struct zf_stack* stack)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl,
                                           st, stack);
  ef_vi* vi = zf_stack_nic_tx_vi(stack, 0);

  if( ZF_UNLIKELY(stack->alts_need_rebuild !=0) ) {
    for( int i = 0; i < zf_stack::MAX_ALTERNATIVES; i++ ) {
      struct zf_alt* alt = &sti->alt[i];

      if( !(stack->alts_need_rebuild & (1 << i)) )
        continue;

      zf_assert_equal(alt->is_allocated, 1);
      zf_assert_nequal(alt->alt_zocket, NULL);

      if( alt->is_draining )
        continue;

      if( alt->n_queued_packets > 0 ) {
        zf_log_stack_trace(stack, "%s: starting rebuild of alt %d\n",
                           __func__, i);

        ef_vi_transmit_alt_discard(vi,
                                   alt->handle);
        zft_alt_reset(stack, alt, &alt->alt_zocket->pcb);
        alt->is_draining = 1;
        alt->tcp.altq.middle = alt->tcp.altq.begin;

      } else {
        stack->alts_rebuilding |= (1 << i);
        stack->alts_need_rebuild &= ~(1 << i);
      }
    }
  }

  for( ;; ) {

    if( stack->alts_rebuilding == 0 )
      return;

    /* ef_vi_transmit_alt_select(), tcp_segment_to_vi() and
     * ef_vi_transmit_alt_select_normal() each post one descriptor to
     * the ring. Therefore we need at least 3 slots free in order to
     * make progress. */
    if( ef_vi_transmit_space(vi) < 3 )
      return;

    int idx = __builtin_ffsl(stack->alts_rebuilding) - 1;
    struct zf_alt* alt = &sti->alt[idx];

    if( !tcp_has_unsent(&alt->tcp.altq) ) {
      stack->alts_rebuilding &= ~(1 << idx);
      continue;
    }

    zf_log_stack_trace(stack, "%s: sending data for alt %d\n",
                     __func__, idx);

    ef_vi_transmit_alt_select(vi, idx);

    struct tcp_pcb* pcb = &alt->alt_zocket->pcb;
    struct tcp_seg* seg = tcp_seg_at(&alt->tcp.altq, 
                                     alt->tcp.altq.middle);

    tcp_output_populate_header((struct tcphdr*)seg->iov.iov_base, 
                               pcb->local_port,
                               pcb->remote_port, 
                               alt->tcp.alt_snd_nxt, 
                               pcb->rcv_nxt,
                               pcb->rcv_ann_wnd);

    alt->tcp.alt_snd_nxt += seg->len;

    int rc = tcp_segment_to_vi(alt->alt_zocket, seg, ZF_REQ_ID_PROTO_TCP_ALT);

    /* We checked the free space in the ring above, so it shouldn't be
     * possible to get -EAGAIN here. */
    zf_assert_nequal(rc, -EAGAIN);

    /* This is a workaround to avoid preventing tcp_seg_free() from freeing
     * this packet when it is ACKed. See bug65503 and reviewboard /r/19216/ for
     * discussion. */
    seg->in_flight = 0;

    ef_vi_transmit_alt_select_normal(vi);

    alt->tcp.altq.middle++;
    alt->n_queued_packets++;

    if( !tcp_has_unsent(&alt->tcp.altq) ) {
      /* We have finished rebuilding the contents of this alt. Clear
       * the flags and rewind the associated queue. */
      zf_log_stack_trace(stack, "%s: finished rebuild of alt %d\n",
                       __func__, idx);
      stack->alts_rebuilding &= ~(1 << idx);
      alt->tcp.altq.middle = alt->tcp.altq.begin;
    }
  }
}


unsigned
zf_alternatives_free_space(struct zf_stack* stack, zf_althandle alt)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl,
                                           st, stack);
  return zf_altbm_bytes_free(&sti->alt_buf_model, alt);
}


int
zf_alternatives_query_overhead_tcp(struct zft* ts, 
                                   struct ef_vi_transmit_alt_overhead *out)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  zf_stack* stack = zf_stack_from_zocket(tcp);

  int rc = ef_vi_transmit_alt_query_overhead(zf_stack_nic_tx_vi(stack, 0), out);
  if( rc < 0 )
    return rc;

  out->pre_round += zft_get_header_size(ts);
  return 0;
}


void zf_alt_dump(SkewPointer<zf_stack_impl> stimpl, zf_althandle alt_id)
{
  zf_assert_lt((int) alt_id, stimpl->n_alts);

  struct zf_alt* alt = &stimpl->alt[alt_id];
  zf_dump("ALT %." ZF_STRINGIFY(ZF_STACK_NAME_SIZE)
          "s:%d handle=%d queued=%u draining=%d alloced=%d zocket=%d\n",
          stimpl->st.st_name, alt_id, alt->handle, alt->n_queued_packets,
          alt->is_draining, alt->is_allocated,
          alt->alt_zocket != NULL ?
            TCP_ID(&stimpl->st, stimpl.adjust_pointer(alt->alt_zocket)) : -1);
  zf_dump(" TCP:\n");
  zf_dump("  alt_snd_nxt=%u first_byte=%u\n",
          alt->tcp.alt_snd_nxt, alt->tcp.first_byte);
  tcp_dump_sendq(&alt->tcp.altq);
  zf_dump("------------------------------------------------------------\n");
}
