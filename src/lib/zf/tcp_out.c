/* SPDX-License-Identifier: BSD-3-Clause */
/* SPDX-FileCopyrightText: (c) 2016-2022 Advanced Micro Devices, Inc. */
/*
 * This file contains code based on the lwIP TCP/IP stack.
 *
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.  2. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.  3. The name of the author may not
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Adam Dunkels <adam@sics.se>
 */

#include <zf/zf.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/tcp_opt.h>
#include <zf_internal/tcp.h>
#include <zf_internal/tcp_tx.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/tx_send.h>
#include <zf_internal/zf_tcp_timers.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_alts.h>

#include <zf_internal/private/zf_stack_rx.h>

#include <arpa/inet.h>


#define TCP_STATS_INC(x)

static int
tcp_output_segment(struct zf_tcp* tcp, struct tcp_seg *seg);


void tcp_populate_header_common(struct tcphdr* tcp_hdr, uint16_t local_port_he,
                                uint16_t remote_port_he)
{
  tcp_hdr->source = htons(local_port_he);
  tcp_hdr->dest = htons(remote_port_he);
  tcp_hdr->res1 = 0;
  tcp_hdr->doff = 5;
  tcp_hdr->fin = 0;
  tcp_hdr->syn = 0;
  tcp_hdr->rst = 0;
  tcp_hdr->psh = 0;
  tcp_hdr->ack = 1;
  tcp_hdr->urg = 0;
  tcp_hdr->res2 = 0;
  tcp_hdr->check = 0;
  tcp_hdr->urg_ptr = 0;
}


void tcp_output_timers_common(struct zf_stack* stack, struct zf_tcp* tcp,
                              uint32_t seq)
{
  if ( ! zf_tcp_timers_timer_is_active(tcp, ZF_TCP_TIMER_RTO) )
    zf_tcp_timers_timer_start(tcp, ZF_TCP_TIMER_RTO,
                              zf_tcp_timers_rto_timeout(tcp));

  struct tcp_pcb* pcb = &tcp->pcb;
  if (pcb->rttest == 0) {
    pcb->rttest = zf_wheel_get_current_tick(&stack->times.wheel);
    pcb->rtseq = seq;

    zf_log_tcp_tx_trace(tcp, "%s: rtseq %u\n", __func__, seq);
  }
}


/** \brief Fills in all fields in a TCP header based on pcb values.
 *
 * \param pcb
 * \param tcp_hdr
 *
 * This sets the default values for the fields, based on the pcb state.  If
 * flags are required they must be set separately.
 *
 * TCP TX internal
 */
void tcp_output_populate_header(struct tcphdr* tcp_hdr,
                                uint16_t local_port_he,
                                uint16_t remote_port_he, uint32_t seq_he,
                                uint32_t ack_he, uint32_t window_he)
{
  tcp_populate_header_common(tcp_hdr, local_port_he, remote_port_he);
  tcp_hdr->seq = htonl(seq_he);
  tcp_hdr->ack_seq = htonl(ack_he);
  tcp_hdr->window = htons(window_he);
}

/** \brief Send a segment including FIN flag but not data.
 *
 * \param
 *
 * \return 0 if sent ok
 *         other error if sending failed
 *
 * TCP shared
 */
int tcp_send_fin(struct zf_tcp* tcp)
{
  tcp_send_queue* sendq = &tcp->pcb.sendq;

  if( tcp_has_unsent(sendq) ) {
    struct tcp_seg* seg = tcp_seg_at(sendq, sendq->end - 1);
    if( ! seg->in_flight ) {
      /* Add FIN to the existing segment. */
      zf_log_tcp_tx_trace(tcp, "%s: update "TCP_SEG_FMT"\n", __func__,
                          TCP_SEG_ARGS(seg));
      tcp_seg_tcphdr(seg)->fin = 1;
      tcp->pcb.snd_lbb++;
      return 0;
    }
  }

  int rc = tcp_enqueue_flags(tcp, 0, 1, 1);

  if( rc < 0 && tcp_snd_queuelen(sendq) > 0 ) {
    struct tcp_seg* seg = tcp_seg_at(sendq, sendq->end - 1);
    /* We must not modify in-flight packets; we should not modify
     * sent-but-unacked-yet packets, but what can we do?
     *
     * Corrupted packet may go out, but it is not a big issue; we'll
     * retransmit it. */
    tcp_seg_tcphdr(seg)->fin = 1;
    tcp->pcb.snd_lbb++;
    zf_log_tcp_tx_trace(tcp, "%s: fallback update "TCP_SEG_FMT"\n",
                        __func__, TCP_SEG_ARGS(seg));
    return 0;
  }

  if( rc != 0 )
    zf_assert_equal(rc, -ENOMEM);

  return rc;
}


/** \brief Add options to TCP header
 *
 * \param seg
 * \param optflags
 *
 * Currently only supports the MSS option.
 *
 * Assumes that seg->iov is long enough to contain the option - this should
 * always be the case as all seg buffers are backed with a pkt buf
 *
 * TCP TX internal
 */
static void tcp_add_options(struct zf_tcp* tcp, struct tcp_seg* seg, uint8_t optflags)
{
  uint8_t optlen = 0;
  struct tcphdr* tcp_hdr = tcp_seg_tcphdr(seg);
  uint32_t* opts = (uint32_t *)((char*)tcp_hdr + TCP_HLEN);

  /* Only support the MSS option */
  zf_assert_nflags(optflags, ~TF_SEG_OPTS_MSS);

  if( optflags & TF_SEG_OPTS_MSS ) {
    zf_assert_equal(tcp->tst.path.rc, ZF_PATH_OK);
    /* Send maximum MSS we support is sent,
     * note pcb.mss is set to TCP_MSS_MIN at zocket init */
    *opts = htonl(TCP_OPT_MSS_HE(tcp_mtu2mss(tcp->tst.path.mtu)));
    optlen += 4;
  }

  tcp_hdr->doff = 5 + (optlen/4);
  seg->iov.iov_len += optlen;

  /* Check we haven't exceeded the packet buffer size.  Given that we only
   * add options to a SYN this should always be true.
   */
  zf_assert_le(seg->iov.iov_len, PKT_BUF_SIZE);

  /* We haven't changed the TCP payload, so seg->len remains the same */
  zf_assert_equal(seg->len, seg->iov.iov_len - (TCP_HLEN + optlen));
  /* And this is a SYN, so the payload length should be 0 */
  zf_assert_equal(seg->len, 0);
}


/** \brief Updates the unacknowledged queue appropriately for this segment
 *
 * \param tcp
 * \param seg
 *
 * TCP TX internal
 */
static inline void
tcp_add_to_unack_queue(struct tcp_pcb* pcb, struct tcp_seg* seg)
{
  zf_assert(tcp_has_unsent(&pcb->sendq));
  zf_assert_equal(seg, tcp_seg_at(&pcb->sendq, pcb->sendq.middle));
  ++pcb->sendq.middle;
}


static inline void tcp_check_is_sendq_tail(struct tcp_send_queue* sendq,
                                            tcp_seg *seg)
{
  /* seg should be already at the end of sendq queue */
  zf_assert_equal(tcp_seg_at(sendq, sendq->end - 1), seg);
}


static inline void
tcp_copy_data_to_segment(struct tcp_seg* seg, const iovec* iov_hdr,
                         const iovec* iov_payload)
{
  if( iov_hdr ) {
    zf_assert_equal(seg->iov.iov_len, iov_hdr->iov_len);
    memcpy(seg->iov.iov_base, iov_hdr->iov_base, iov_hdr->iov_len);
  }

  if( iov_payload ) {
    memcpy((char*)seg->iov.iov_base + seg->iov.iov_len,
           iov_payload->iov_base, iov_payload->iov_len);
    seg->iov.iov_len += iov_payload->iov_len;
    seg->len += iov_payload->iov_len;
  }
}


static inline tcp_seg*
tcp_init_next_segment(struct zf_stack* stack, struct zf_tcp* tcp,
                      struct tcp_send_queue* sendq, pkt_id id)
{
  int idx = sendq->end++;
  tcp_seg* seg = tcp_seg_at(sendq, idx);
  seg->iov.iov_base = PKT_BUF_BY_ID(&stack->pool, id) + ETH_IP_HLEN +
                      zf_tx_do_vlan(&tcp->tst) * VLAN_HLEN;
  seg->iov.iov_len = TCP_HLEN;
  seg->len = 0;
  seg->in_flight = 0;

  return seg;
}


/** \brief Allocates a tcp_seg and initialises it to refer to provided pkt
 *
 * \param tcp
 * \param id           The pkt this seg should refer to
 * \param payload_len  The length of the TCP payload data
 *
 * There must be free segs on the sendq to call this function.
 *
 * \return A populated tcp_seg
 */
static inline tcp_seg*
tcp_alloc_segment_in_flight(struct zf_tcp* tcp, pkt_id id, int payload_len)
{
  /* This must be checked by the caller */
  zf_assert_lt(tcp_snd_queuelen(&tcp->pcb.sendq), TCP_SND_QUEUE_SEG_COUNT );

  zf_stack* stack = zf_stack_from_zocket(tcp);
  tcp_seg* seg = tcp_init_next_segment(stack, tcp, &tcp->pcb.sendq, id);
  seg->iov.iov_len += payload_len;
  seg->len += payload_len;
  seg->in_flight = 1;

  return seg;
}


/** \brief Allocates a tcp_seg and pkt
 *
 * \param tcp
 * \param sendq The sendq to allocate the segment on
 *
 * If a packet cannot be allocated, the pre-allocated fast_pkt buffer will
 * be used if available.
 *
 * There must be free segs on the sendq to call this function.
 *
 * \return A populated tcp_seg on success
 *         NULL on failure
 */
static inline tcp_seg*
tcp_alloc_segment_with_pkt(struct zf_tcp* tcp, struct tcp_send_queue* sendq)
{
  /* This must be checked by the caller */
  zf_assert_lt(tcp_snd_queuelen(sendq), TCP_SND_QUEUE_SEG_COUNT );
  zf_stack* stack = zf_stack_from_zocket(tcp);
  pkt_id id;
  int rc = zft_alloc_pkt(&stack->pool, &id);
  if( rc < 0 ) {
    /* Disable fast send */
    tcp_disable_fast_send(&tcp->pcb);
    if( tcp->pcb.fast_pkt != PKT_INVALID ) {
      id = tcp->pcb.fast_pkt;
      tcp->pcb.fast_pkt = PKT_INVALID;
    }
    else {
      return NULL;
    }
  }

  tcp_seg* seg = tcp_init_next_segment(stack, tcp, sendq, id);
  return seg;
}


void tcp_fast_send_tail(zf_tcp* tcp, const iovec* iov_, pkt_id pkt)
{
  struct zf_stack* stack = zf_stack_from_zocket(tcp);

  /* Avoid need to undo effects of this function after warm.
   * Also no need to warm non-critical path code. */
  if( stack->flags & ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED )
    return;

  tcp_pcb* pcb = &tcp->pcb;
  struct tcphdr* hdr = zf_tx_tcphdr(&tcp->tst);
  iovec iov = *iov_;
  /* We now need to tidy up after ourselves.  This involves:
   *
   * - updating the pcb state
   * - starting retransmission timer
   * - updating statistics
   * - setting up a tcp_seg structure with this data
   * - queueing the new seg on the unacknowledged queue
   */

  /* Update pcb */
  pcb->rcv_ann_right_edge = pcb->rcv_nxt + pcb->rcv_ann_wnd;

  /* Set retransmission timer running if it is not currently enabled */
  tcp_output_timers_common(stack, tcp, ntohl(hdr->seq));
  zf_log_tcp_tx_trace(stack, "tcp_output_segment: %u:%zu "
                        "snd_right_edge %u pkt %x\n",
                        htonl(hdr->seq), htonl(hdr->seq) + iov.iov_len,
                        pcb->snd_right_edge, pkt);

  TCP_STATS_INC(tcp.xmit);
  if( stack->tx_reports.enabled() )
    zf_tx_reports::prepare(&stack->tx_reports, TCP_ID(stack, tcp), true,
                           pcb->snd_lbb - tcp->pcb.snd_iss,
                           iov.iov_len, 0);

  const struct iovec iov_hdr = {
    .iov_base = hdr,
    .iov_len = TCP_HLEN
  };

  tcp_seg* seg;

  zf_assert_equal(pcb->snd_nxt, pcb->snd_lbb);

  if( tcp_has_sendq(&pcb->sendq) ) {
    /* The implementation below strives for roubustness.
     * The assumption is that we have some sent but unacked data
     * in the queue. In any case we add data to the end of the queue
     * using snd_lbb. */
    zf_assert(tcp_has_unacked(&pcb->sendq));
    zf_assert(!tcp_has_unsent(&pcb->sendq));
    seg = tcp_seg_last(&pcb->sendq);
    zf_assert_equal(pcb->snd_lbb, tcp_seg_seq(seg) + tcp_seg_len(seg));

    /* This segment may be in-flight, so we should not modify any data
     * under DMA.  But we can append some data to the end. */
    uint16_t seglen = MIN((unsigned)(tcp_mss_max_seg(pcb) - seg->len),
                          (unsigned)iov.iov_len);
    struct iovec payload = {
      .iov_base = iov.iov_base,
      .iov_len = seglen
    };
    tcp_copy_data_to_segment(seg, NULL, &payload);

    iov.iov_base = (char*) iov.iov_base + seglen;
    iov.iov_len -= seglen;
    if( iov.iov_len == 0 )
      goto skip_next;
    pcb->snd_nxt = pcb->snd_lbb + seglen;
    hdr->seq = htonl(pcb->snd_lbb + seglen);

    /* tell tx_complete to drop the packet we've sent */
    pkt = PKT_INVALID;
  }

  if( pkt != PKT_INVALID ) {
    seg = tcp_alloc_segment_in_flight(tcp, pkt, iov.iov_len);
    /* This doesn't need to allocate a pkt, and we check there are segs
     * available on the sendq, so we should always get a seg.
     */
    zf_assert(seg);
  }
  else {
    seg = tcp_alloc_segment_with_pkt(tcp, &tcp->pcb.sendq);
    /* We should only come down this path if we have a pre-allocated segment
     * available, so we should always be able to obtain one.
     */
    zf_assert(seg);
    tcp_copy_data_to_segment(seg, &iov_hdr, &iov);
  }

  pcb->snd_buf -= pcb->mss;

  tcp_check_is_sendq_tail(&pcb->sendq, seg);
  tcp_add_to_unack_queue(pcb, seg);

skip_next:
  pcb->snd_lbb += iov_->iov_len;
  pcb->snd_nxt = pcb->snd_lbb;

  zf_assert_equal(pcb->snd_buf, tcp_snd_buf_avail(pcb, &pcb->sendq));

  tcp_fix_fast_send_length(pcb);
  tcp_tx_cancel_delayed_ack(tcp);
}


static inline int tcp_free_seg_space(tcp_send_queue* sendq, uint16_t mss)
{
  return ((TCP_SND_QUEUE_SEG_COUNT - tcp_snd_queuelen(sendq)) * mss);
}


static int tcp_queue_segments(struct zf_tcp* tcp, struct tcp_send_queue* sendq,
                              const iovec* iov, uint32_t* seq, bool use_tail)
{
  /* Before segmenting data we ensure that we can place all the data we
   * need on the queue.  This means we must ensure that:
   *
   * - we have enough space in the sendq
   * - we have enough free pkts
   *
   * The tcp_write_checks() ensures that we have enough free packets for
   * a maximum length send, so all we need to check here is that there is
   * space on the sendq.
   */
  struct tcp_pcb* pcb = &tcp->pcb;
  int data_to_seg = iov->iov_len;
  uint16_t mss_local = tcp_mss_max_seg(pcb);
  struct tcp_seg* seg = NULL;

  /* See if we can stuff the first part of our data in the tail of the sendq */
  if( use_tail && tcp_has_sendq(sendq) ) {
    seg = tcp_seg_at(sendq, sendq->end - 1);
    data_to_seg -= (mss_local - seg->len);
  }

  /* If we need to allocate new segments check that we've got enough space
   * on the queue.
   */
  if( data_to_seg > 0 &&
      tcp_free_seg_space(sendq, mss_local) < data_to_seg ) {
    /* We haven't got space at the moment, bail out now */
    zf_log_tcp_tx_trace(tcp, "%s: queue too long %u/%u for %d bytes\n",
                        __func__, tcp_snd_queuelen(sendq),
                        TCP_SND_QUEUELEN, data_to_seg);
    return -EAGAIN;
  }

  /* We know know that we can allocate packet and segments for everything
   * we need, so go ahead and do it.
   */
  int segs_queued = 0;
  unsigned pos = 0; /* position in 'arg' data */
  while( pos < iov->iov_len ) {
    unsigned left = iov->iov_len - pos;
    unsigned seglen = mss_local;

    /* if we have an existing segment on unsentq and there is space there */
    if( seg == NULL || seg->len >= seglen ) {
      zf_assert_lt(tcp_snd_queuelen(sendq), TCP_SND_QUEUELEN);
      zf_assert_lt(tcp_snd_queuelen(sendq), TCP_SND_QUEUE_SEG_COUNT);

      seg = tcp_alloc_segment_with_pkt(tcp, sendq);
      /* tcp_write_checks should have assured enough space in the pool */
      zf_assert(seg);
      zf_assert_equal(seg->len, 0 );
      segs_queued++;

      tcp_output_populate_header(tcp_seg_tcphdr(seg), pcb->local_port,
                                 pcb->remote_port, *seq + pos,
                                 pcb->rcv_nxt, pcb->rcv_ann_wnd);
    }
    else {
      seglen -= seg->len;
    }

    seglen = MIN(seglen, left);

    /* Copy the data into the initialised tcp_seg */
    struct iovec payload = {
      .iov_base = (char*)iov->iov_base + pos,
      .iov_len = seglen
    };
    tcp_copy_data_to_segment(seg, NULL, &payload);
    zf_assert_le(seg->len, mss_local);

    zf_log_tcp_tx_trace(tcp, "%s: queueing "TCP_SEG_FMT"\n", __func__,
                        TCP_SEG_ARGS(seg));

    pos += seglen;
    tcp_check_is_sendq_tail(sendq, seg);
  }

  *seq += iov->iov_len;
  return segs_queued;
}


/* The use_tail param is used to control whether this data can be coalesced.
 * We don't do this for alt sends as this would require a rebuild of the
 * alt.  Coalecsing on alt queue would allow the full length of the queue
 * to be used, at the cost of triggering a rebuild on every call to queue
 * when the altq is not empty, as well as additional code complexity.  As
 * alts are not expected to be queueing vast amounts of data I'm not going
 * to do this for now.  An alternative would be to coalesce the whole
 * altq only when it gets filled beyond a certain threshold, rather than
 * queueing directly into incomplete tail segments.
 * For regular sends we only do this if there's unsent data on the queue, as
 * our boundary between sent and unsent data is a queue index, not a byte
 * index.
 */
static int
tcp_queue_unsent_segments(struct zf_tcp* tcp, struct tcp_send_queue* sendq,
                          const iovec* iov, uint32_t* seq, int use_tail)
{
  return tcp_queue_segments(tcp, sendq, iov, seq,
                            use_tail && tcp_has_unsent(sendq));
}


/* In the case of alternatives and delegated sends we want to queue data that
 * we know has already been sent. Unless something is terribly wrong that
 * implies that all earlier data on the queue has been sent. However, it
 * doesn't imply that all earlier data on the queue is considered unsent by
 * ZF. This is because in the case of a RTO we handle this by moving the
 * middle pointer backwards. This means that we normally want to advance the
 * middle point when we queue known sent segments, but not in the case that
 * we're currently retransmitting.
 * Whatever the case with retransmits we can always use the tail for sent
 * segments, as we always want it to be treated as having the same send state
 * as the sendq tail.
 */
int tcp_queue_sent_segments(struct zf_tcp* tcp, struct tcp_send_queue* sendq,
                            const iovec* iov, uint32_t* seq)
{
  bool advance_middle = !tcp_has_unsent(sendq);

  int rc = tcp_queue_segments(tcp, sendq, iov, seq, true);
  if( rc > 0 && advance_middle )
    sendq->middle += rc;

  return rc;
}


void tcp_fix_fast_send(zf_stack* stack, tcp_pcb* pcb)
{
  if( ZF_UNLIKELY(pcb->fast_pkt == PKT_INVALID) )
    zft_alloc_pkt(&stack->pool, &pcb->fast_pkt);
  tcp_fix_fast_send_length(pcb);
}

/** \brief Write data for sending
 *
 * \param tcp
 * \param iov
 * \param flags optional MSG_MORE to prevent pushing last unfilled segment
 *
 * In tcp_write(), if the criteria for a fast send are met, the data is
 * immediately sent, and then queued.  Otherwise we must go through the slow
 * path, which is implemented in this function.
 *
 * ZF
 */
int tcp_write_slow(zf_stack* stack, zf_tcp* tcp, const iovec *iova,
                   int iov_cnt, int flags)
{
  tcp_pcb* pcb = &tcp->pcb;

  zf_log_tcp_tx_trace(tcp, "%s: send via q:%s mss_local = %d snd_buf = %u "
                      "snd_right_edge = %u cwnd = %d lastack = %u qlen = %d "
                      "flags = %d\n",
                      __FUNCTION__,
                      tcp_has_unsent(&pcb->sendq) ? " unsent" : "",
                      tcp_mss_max_seg(pcb),
                      pcb->snd_buf, pcb->snd_right_edge, pcb->cwnd,
                      pcb->lastack, tcp_snd_queuelen(&pcb->sendq), flags);

  if( flags & ~MSG_MORE )
    return -EINVAL;

  /* We must do this first, as we don't want to proceed if we are not in a
   * valid state.
   */

  int err = tcp_write_checks(stack, pcb, 1);
   if( ZF_UNLIKELY( err != 0) ) {
     zf_log_tcp_tx_trace(tcp, "%s: can't send: err = %d\n", __FUNCTION__, err);
     return err;
   }

  size_t tot_queued = 0;
  int local_mss = tcp_mss_max_seg(&tcp->pcb);
  for( int i = 0; i < iov_cnt; ++i ) {
    int segs;
    const iovec *iov = &iova[i];
    iovec new_iov;
    if(ZF_UNLIKELY( iov->iov_len > pcb->snd_buf )) {
      /* ensure we queue the exact amount of data to fill up sendqueue
       * This is important to make sure the last segment can be posted to the
       * wire without PSH flag */
      int tail = tcp_has_unsent(&pcb->sendq) ?
                 local_mss - tcp_seg_last(&pcb->sendq)->len : 0;
      size_t sendq_space = pcb->snd_buf + tail;
      if( sendq_space < iov->iov_len ) {
        /* No PSH flag as only part of the message has been fitted */
        flags |= MSG_MORE;
        if(ZF_UNLIKELY( sendq_space == 0 ))
          break;
        new_iov = iovec { iov->iov_base, sendq_space };
        iov = &new_iov;
        iov_cnt = i; /* end the loop at this iteration */
      }
    }
    segs = tcp_queue_unsent_segments(tcp, &pcb->sendq, iov, &pcb->snd_lbb,
                                     true);
    if( ZF_UNLIKELY(segs < 0) ) {
      zf_log_tcp_tx_trace(tcp, "%s: queueing segments failed rc = %d\n",
                          __func__, segs);
      /* checks above should have assured we never come this path,
       * however in presence of tcp_mss_max_seg() based on snd_wnd_max this
       * is hard to verify */
      if( tot_queued == 0 )
        return segs;
      /* something went wrong, let's do not hold any queued data */
      flags &= ~MSG_MORE;
      break;
    }
    tot_queued += iov->iov_len;
    /*
     * Finally update the pcb state.
     */
    pcb->snd_buf = tcp_snd_buf_avail(pcb, &pcb->sendq);
  }

  zf_log_tcp_tx_trace(tcp, "%s: snd_buf %u qlen %d (after enqueued), "
                      "space in last seg %d, msg_more %d\n",
                      __func__, pcb->snd_buf, tcp_snd_queuelen(&pcb->sendq),
                      (tcp_has_unsent(&pcb->sendq) ?
                       local_mss - tcp_seg_last(&pcb->sendq)->len : -1),
                      flags & MSG_MORE);

  zf_assert_impl(tcp_snd_queuelen(&pcb->sendq) != 0,
                 tcp_has_unacked(&pcb->sendq) || tcp_has_unsent(&pcb->sendq));

  /* Set the PSH flag in the last segment that we enqueued unless told not to do it. */
  if( ~flags & MSG_MORE && tcp_has_unsent(&pcb->sendq) )
    tcp_seg_tcphdr(tcp_seg_last(&pcb->sendq))->psh = 1;

  tcp_output(tcp);

  /* We may have come done this path because we didn't have a pre-allocated
   * pkt to do a fast send.  If we've got here then we managed to allocate a
   * pkt for this send, so probably the out of bufs condition has cleared and
   * we can set up for fast sends again.
   */
  if( ZF_UNLIKELY(pcb->fast_pkt == PKT_INVALID) )
    tcp_fix_fast_send(stack, pcb);

  return tot_queued;
}


/** \param Allocate a segment containing just TCP headers, with flags set
 *
 * \param tcp
 * \param syn
 * \param fin
 *
 * Exactly one of the syn or fin flags should be set.
 *
 * This can probably be tidied up, as there's a reasonable amount of
 * commonality between this, and other things that allocate outgoing data
 * segments.
 *
 * TCP shared
 */
int
tcp_enqueue_flags(struct zf_tcp* tcp, uint8_t syn, uint8_t fin, uint8_t ack)
{
  struct tcp_seg *seg;
  struct tcp_pcb *pcb = &tcp->pcb;

  zf_log_tcp_tx_trace(tcp, "%s: queuelen: %u\n", __func__,
                      tcp_snd_queuelen(&pcb->sendq));

  /* The API requires that a flag be set ... */
  zf_assert_nequal(syn | fin, 0);
  /* ... but not both */
  zf_assert(!(syn && fin));
  /* Also, not-SYN implies ACK. */
  zf_assert_impl(! syn, ack);

  /* check for configured max queuelen and possible overflow */
  if( (tcp_snd_queuelen(&pcb->sendq) >= TCP_SND_QUEUELEN) ) {
    zf_log_tcp_tx_trace(tcp, "%s: too long queue %u (max %u)\n", __func__,
                        tcp_snd_queuelen(&pcb->sendq), TCP_SND_QUEUELEN);
    TCP_STATS_INC(tcp.memerr);
    return -EAGAIN;
  }

  /* Allocate memory for tcp_seg, and fill in fields. */
  seg = tcp_alloc_segment_with_pkt(tcp, &pcb->sendq);
  if(!seg) {
    TCP_STATS_INC(tcp.memerr);
    return -ENOMEM;
  }

  /* Make necessary changes from the default header values */
  tcp_output_populate_header(tcp_seg_tcphdr(seg), pcb->local_port,
                             pcb->remote_port, pcb->snd_lbb,
                             pcb->rcv_nxt, pcb->rcv_ann_wnd);

  struct tcphdr* tcp_hdr = tcp_seg_tcphdr(seg);
  if( syn ) {
    tcp_add_options(tcp, seg, TF_SEG_OPTS_MSS);
    if ( ! ack )
      tcp_hdr->ack = 0;
    tcp_hdr->syn = 1;
  }
  else if( fin ) {
    tcp_hdr->fin = 1;
  }
  pcb->snd_buf -= pcb->mss;
  zf_assert_equal(pcb->snd_buf, tcp_snd_buf_avail(pcb, &pcb->sendq));

  zf_log_tcp_tx_trace(tcp, "%s: queueing "TCP_SEG_FMT" %s %s %s\n", __func__,
                      TCP_SEG_ARGS(seg),
                      syn ? "SYN" : "", fin ? "FIN" : "", ack ? "ACK" : "");

  tcp_check_is_sendq_tail(&pcb->sendq, seg);

  pcb->snd_lbb++;

  /* update number of segments on the queues */
  zf_log_tcp_tx_trace(tcp, "%s: queuelen %d(after enqueued)\n", __func__,
                      tcp_snd_queuelen(&pcb->sendq));

  if( tcp_snd_queuelen(&pcb->sendq) ) {
    zf_assert(tcp_has_unacked(&pcb->sendq) || tcp_has_unsent(&pcb->sendq) );
  }

  return 0;
}


/* Sends packet with ip header from zocket cache.
 * TCP header is expected to be at beginning of buf */
static int
tcp_send_with_ip_header(struct zf_tcp* tcp, struct tcp_seg* seg,
                        uint32_t flags)
{
  struct zf_tx* tx = &tcp->tst;
  const void* buf = seg->iov.iov_base;
  size_t buflen = seg->iov.iov_len;
  zf_assert_nflags(flags, ~(ZF_REQ_ID_CONTROL_MASK|ZF_REQ_ID_PKT_ID_MASK));
  zf_assert_impl((flags & ZF_REQ_ID_PKT_ID_MASK),
                 (~flags & ZF_REQ_ID_PKT_ID_MASK) == 0);

  /* Note with PIO we can only copy continous blocks of 8 bytes
   * starting with alignment 8, no gaps allowed mid cache line */
  uint8_t headers_buf[ROUND_UP(ETH_IP_HLEN + VLAN_HLEN + TCP_HLEN, 8)] alignas(8);

  const bool has_vlan = zf_tx_do_vlan(tx);
  const uint8_t eth_vlan_ip_hlen = ETH_IP_HLEN + VLAN_HLEN * has_vlan;

  /* we pack it all into dword multiple, so pio copy is efficient
   * and ef10_ef_vi_transmitv_pio down the line can deal with it. */
  const int hdrfilllen = sizeof(headers_buf) - eth_vlan_ip_hlen;
  memcpy(headers_buf, zf_tx_ethhdr(&tcp->tst), eth_vlan_ip_hlen);
  zf_tx_req_id req_id = flags | tcp_seg_pkt(seg);
  zf_tx_req_id* txq_req_id = NULL;
  int rc = send_with_hdr(tx, buf, buflen, headers_buf,
                         eth_vlan_ip_hlen, hdrfilllen, req_id, &txq_req_id);
  /* If our seg was sent successfully we should have a txq_req_id for it */
  zf_assert_impl(rc >= 0, txq_req_id != NULL);

  if( ZF_LIKELY(rc >= 0) ) {
    /* Filling txq's req_id with more details after actual send
     * saved cycles on critical path */
    if( (flags & ZF_REQ_ID_PROTO_MASK) != ZF_REQ_ID_PROTO_TCP_ALT )
      *txq_req_id |= tcp_output_req_id(tcp, 0, seg - tcp->pcb.sendq.segs);
    /* set in flight when no PIO and pkt ids match */
    if( tcp_seg_pkt(seg) ==
        (*txq_req_id & (ZF_REQ_ID_PIO_FLAG | ZF_REQ_ID_PKT_ID_MASK)) )
      seg->in_flight = true;
  }

  return rc;
}

/** \brief Send an ACK without data.
 *
 * \param tcp
 *
 * Empty acks do not need queueing, so there's no need to allocate a packet
 * to do this.  Instead we just send using the zf_tx headers.
 *
 * TCP shared
 */
int tcp_send_empty_ack(struct zf_tcp* tcp, bool zero_win_probe)
{
  int err = 0;
  struct tcp_pcb* pcb = &tcp->pcb;
  struct tcphdr* tcp_hdr = zf_tx_tcphdr(&tcp->tst);

  tcp_output_populate_header_fast
    (tcp_hdr, pcb->snd_nxt - zero_win_probe + pcb->snd_delegated,
     pcb->rcv_nxt, pcb->rcv_ann_wnd, 0);

  zf_log_tcp_tx_trace(tcp, "%s: sending ACK for %u rcv ann win %u\n",
                      __func__, tcp->pcb.rcv_nxt, pcb->rcv_ann_wnd);

  zf_tx_iphdr(&tcp->tst)->tot_len = htons(TCP_HLEN + IP_HLEN);

  tcp_send_with_tcp_header(tcp, 0, 0,
                           ZF_REQ_ID_NORMAL | ZF_REQ_ID_PROTO_TCP_FREE);
  tcp_tx_cancel_delayed_ack(tcp);

  /* Now update pcb */
  pcb->rcv_ann_right_edge = pcb->rcv_nxt + pcb->rcv_ann_wnd;

  return err;
}


/** \brief Find out what we can send and send it
 *
 * \param tcp
 *
 * This pokes along the TCP state machine, sending out queued data and acks.
 *
 * TCP shared
 */
int tcp_output(struct zf_tcp* tcp)
{
  struct tcp_seg *seg;
  uint32_t eff_right_edge, snd_nxt;
  struct tcp_pcb* pcb = &tcp->pcb;

  /* pcb->state LISTEN not allowed here */
  zf_assert_nequal(pcb->state, LISTEN);

  eff_right_edge = pcb->lastack +
                   MIN(TCP_SEQ_SUB(pcb->snd_right_edge, pcb->lastack),
                       pcb->cwnd);

  seg = tcp_has_unsent(&pcb->sendq) ? tcp_unsent(&pcb->sendq) : NULL;

  /* If the TF_ACK_NOW flag is set and no data will be sent (either
   * because the ->unsent queue is empty or because the window does
   * not allow it), construct an empty ACK segment and send it.
   *
   * If data is to be sent, we will just piggyback the ACK (see below).
   */
  if( pcb->flags & TF_ACK_NOW && (seg == NULL ||
      TCP_SEQ_GT(tcp_seg_seq(seg) + seg->len, eff_right_edge)) ) {
     tcp_fix_fast_send_length(pcb);
     return tcp_send_empty_ack(tcp);
  }

  zf_log_tcp_tx_trace(tcp, "%s: snd_right_edge %u, cwnd %u, "
                           "eff_right_edge %u, ack %u\n", __func__,
                      pcb->snd_right_edge, pcb->cwnd, eff_right_edge,
                      pcb->lastack);
  if( seg )
    zf_log_tcp_tx_trace(tcp, "%s: "TCP_SEG_FMT"\n",
                        __func__, TCP_SEG_ARGS(seg));

  /* data available and window allows it to be sent? */
  while( seg != NULL && TCP_SEQ_LEQ(tcp_seg_seq(seg) + seg->len,
                                    eff_right_edge) ) {
    struct tcphdr* tcp_hdr = tcp_seg_tcphdr(seg);

    /* This segment is a retransmission if:
     * - its sequence number is not the next sequence number (i.e., we have
     *   sent this sequence before, but have not yet had an ACK); or
     * - the segment is marked as `in_flight`. This means that we have sent the
     *   segment before, but have not yet processed a TX completion event for
     *   the segment.
     *
     * Notably, we must store the state of `seg->in_flight` **BEFORE** we call
     * `tcp_output_segment`, as that will result in `seg->in_flight` being set
     * for all (successfully sent) segments.
     */
    const bool is_retransmit = (tcp_seg_seq(seg) != pcb->snd_nxt ||
                                seg->in_flight);

    zf_assert_nequal(tcp_hdr->rst, 1);

    zf_log_tcp_tx_trace(tcp, "%s: snd_right_edge %u, cwnd %u, "
                        "eff_right_edge %u, seq %u, lastack %u, "
                        TCP_SEG_FMT"\n",
                        __func__,
                        pcb->snd_right_edge, pcb->cwnd, eff_right_edge,
                        tcp_seg_seq(seg), pcb->lastack, TCP_SEG_ARGS(seg));


    /* If this is the last sendq segment and has no push flag.
     * Then it means it was added with MSG_MORE - do not send it. Well,  two
     * execptions: segment is already full or an ACK is due. */
    if( tcp_seg_at(&pcb->sendq, pcb->sendq.end - 1) == seg &&
        ! tcp_hdr->psh && ! tcp_hdr->rst && ! tcp_hdr->syn && ! tcp_hdr->fin &&
        seg->len < tcp_mss_max_seg(pcb) &&
        ~pcb->flags & TF_ACK_NOW &&
        pcb->state == ESTABLISHED ) {
      pcb->stats.msg_more_send_delayed++;
      break;
    }

    /* We do not expect to send data until handshake is done */
    zf_assert_equal(tcp_hdr->syn && ! tcp_hdr->ack, pcb->state == SYN_SENT);
    zf_assert_equal(tcp_hdr->syn && tcp_hdr->ack, pcb->state == SYN_RCVD);

    if (pcb->state != SYN_SENT) {
      tcp_hdr->ack = 1;
      tcp_tx_cancel_delayed_ack(tcp);
    }

    int rc = tcp_output_segment(tcp, seg);
    if( rc < 0 ) {
      tcp_fix_fast_send_length(pcb);
      return rc;
    }

    zf_stack* stack = zf_stack_from_zocket(tcp);
    if( stack->tx_reports.enabled() ) {
      uint16_t flags = 0;
      uint32_t start = tcp_seg_seq(seg) - tcp->pcb.snd_iss;
      if( tcp_hdr->syn ) {
        flags |= ZF_PKT_REPORT_TCP_SYN;
        /* snd_iss is greater than seg by 1 for the SYN packet.
         * This is because we don't want to count the SYN in
         * reported bytes for TCP timestamp. (See tcp_init()).
         * We should increase the start variable by 1 to avoid
         * a negative value. */
        start++;
      }
      else if( tcp_hdr->fin ) {
        flags |= ZF_PKT_REPORT_TCP_FIN;
      }
      if( is_retransmit ) {
        flags |= ZF_PKT_REPORT_TCP_RETRANS;
      }
      zf_tx_reports::prepare(&stack->tx_reports,
        TCP_ID(stack, tcp), true, start,
        tcp_seg_len(seg) - tcp_hdr->syn - tcp_hdr->fin,
        flags);
    }

    snd_nxt = tcp_seg_seq(seg) + tcp_seg_len(seg);
    if (TCP_SEQ_LT(pcb->snd_nxt, snd_nxt)) {
      pcb->snd_nxt = snd_nxt;
    }

    /* we queue even segments with no payload
     * we do not expect pure ACKs though and SYN/FIN count as 1 */
    zf_assert_gt(tcp_seg_len(seg), 0);
    tcp_add_to_unack_queue(pcb, seg);
    seg = tcp_has_unsent(&pcb->sendq) ? tcp_unsent(&pcb->sendq) : NULL;
  }
  tcp_fix_fast_send_length(pcb);
  return 0;
}

/** \brief Send a TCP segment to the NIC without doing any other bookkeeping.
 *
 * \param tcp
 * \param seg
 *
 * TCP TX internal
 */
int tcp_segment_to_vi(struct zf_tcp* tcp, struct tcp_seg* seg,
                      uint32_t flags)
{
  struct tcp_pcb *pcb = &tcp->pcb;
  struct tcphdr* tcp_hdr = tcp_seg_tcphdr(seg);

  /* The TCP header has already been constructed, but the ackno and
   wnd fields remain. */
  tcp_hdr->ack_seq = htonl(pcb->rcv_nxt);

  /* advertise our receive window size in this TCP segment */
  tcp_hdr->window = htons(pcb->rcv_ann_wnd);

  tcp_hdr->check = 0;
  TCP_STATS_INC(tcp.xmit);

  zf_tx_iphdr(&tcp->tst)->tot_len = htons(seg->iov.iov_len + IP_HLEN);


  return tcp_send_with_ip_header(tcp, seg, flags);
}

/** \brief Called by tcp_output() to actually send a TCP segment over IP.
 *
 * \param tcp
 * \param seg
 *
 * The provided tcp segment should be initialised, with the TCP header
 * populated, with the exception of the ack and window fields.
 *
 * This function updates those fields, as well as the IP length.
 *
 * TCP TX internal
 */
static int tcp_output_segment(struct zf_tcp* tcp, struct tcp_seg *seg)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  int send_flags = ZF_REQ_ID_PIO_FLAG | ZF_REQ_ID_PROTO_TCP_KEEP;

  pcb->rcv_ann_right_edge = pcb->rcv_nxt + pcb->rcv_ann_wnd;

  /* Stop zwin timer */
  zf_tcp_timers_timer_stop(tcp, ZF_TCP_TIMER_ZWIN);

  /* If we have not yet processed a TX completion for this segment, then the
   * packet might still exist in a buffer, so we should send it either by PIO
   * or by copying the packet to a new buffer. */
  if( seg->in_flight ) {
    zf_log_tcp_tx_trace(tcp, "%s: in-flight %u:%u\n", __func__,
                        tcp_seg_seq(seg), tcp_seg_seq(seg) + seg->len);
    send_flags = ZF_REQ_ID_PIO_FLAG | ZF_REQ_ID_PROTO_TCP_KEEP | PKT_INVALID;
  }

  tcp_output_timers_common(stack, tcp, tcp_seg_seq(seg));

  zf_log_tcp_tx_trace(tcp, "%s: "TCP_SEG_FMT"\n", __func__, TCP_SEG_ARGS(seg));

  return tcp_segment_to_vi(tcp, seg, send_flags);
}


/** \brief Send a TCP reset
 *
 * \param seqno the sequence number to use for the outgoing segment
 * \param ackno the acknowledge number to use for the outgoing segment
 * \param local_ip the local IP address to send the segment from
 * \param remote_ip the remote IP address to send the segment to
 * \param local_port the local TCP port to send the segment from
 * \param remote_port the remote TCP port to send the segment to
 *
 * This is used either to
 * abort a connection or to show that there is no matching local connection
 * for a received segment.
 *
 * Since a RST segment is in most cases not sent for an active connection,
 * tcp_rst() has a number of arguments that are taken from a tcp_pcb for
 * most other segment output functions.
 *
 * Caller should ensure that tx->pkt contatins correct destination MAC.
 * In the most cases when we reset already-established connection, it is
 * done without any special effort.
 *
 * TCP shared
 */
void tcp_rst(struct zf_stack* stack, struct zf_tx* tx, uint32_t raddr_n,
             uint32_t seqno_h, uint32_t ackno_h, uint16_t window_h,
             uint16_t lport_h, uint16_t rport_h, bool no_ack)
{
  struct tcphdr* tcp_hdr;
  struct iovec iov;

  const bool has_vlan = zf_tx_do_vlan(tx);
  const uint8_t eth_vlan_ip_hlen = ETH_IP_HLEN + VLAN_HLEN * has_vlan;

  struct ethvlaniptcphdr vlan_rst_pkt alignas(8); /* aligned for zf_send */
  struct ethiptcphdr *rst_pkt = (struct ethiptcphdr *)&vlan_rst_pkt;
  iov.iov_base = rst_pkt;
  iov.iov_len = eth_vlan_ip_hlen + TCP_HLEN;
  memcpy(&vlan_rst_pkt, zf_tx_ethhdr(tx), iov.iov_len);
  if( has_vlan ) {
    vlan_rst_pkt.ip.daddr = raddr_n;
    tcp_hdr = &vlan_rst_pkt.tcp;
    vlan_rst_pkt.ip.tot_len = htons(IP_HLEN + TCP_HLEN);
  }
  else {
    rst_pkt->ip.daddr = raddr_n;
    tcp_hdr = &rst_pkt->tcp;
    rst_pkt->ip.tot_len = htons(IP_HLEN + TCP_HLEN);
  }

  tcp_output_populate_header(tcp_hdr, lport_h, rport_h, seqno_h, ackno_h,
                             window_h);

  /* This isn't necessarily part of a valid connection, so overwrite bits
   * of the header with the supplied values.
   */
  tcp_hdr->rst = 1;
  tcp_hdr->ack = ! no_ack;


  /* Sending a RST is a best-effort affair, so make no attempt to handle
   * failure here. */
  zf_send(tx, &iov, 1, iov.iov_len,
          ZF_REQ_ID_NORMAL | ZF_REQ_ID_PROTO_TCP_FREE, NULL);

  TCP_STATS_INC(tcp.xmit);
  zf_log_tcp_tx_trace(stack, "%s: seq %u ackno %u.\n", __func__,
                      seqno_h, ackno_h);
}

static void
tcp_rexmit_rto(tcp_pcb* pcb);

/** \brief Requeue the first unacked segment for retransmission
 *
 * \param pcb the tcp_pcb for which to retransmit the first unacked segment
 * 
 * Called by tcp_receive() for fast retramsmit.
 */
void tcp_rexmit(struct tcp_pcb *pcb)
{
  /* That might not be correct but we keep it simple. That is
   * we move all the unacked queue to unsent.
   * As doing so for selected pkts (as tcp_rexmit() originally did) breaks
   * sequence number ordering on joint sendq */
  tcp_rexmit_rto(pcb);
}


/** \brief Handle retransmission after three dupacks received
 *
 * \param pcb the tcp_pcb for which to retransmit the first unacked segment
 *
 * TCP shared
 */
void tcp_rexmit_fast(struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;

  if( tcp_has_unacked(&pcb->sendq) && !(pcb->flags & TF_INFR) ) {
    /* This is fast retransmit.
     * --Retransmit the first unacked segment.--
     * No, that would break sendqueue ordering respective to seqno.
     * For simplicity all unacked packets get onto unsent queue.
     */
    zf_log_tcp_tx_trace(tcp, "%s: dupacks %u (%u), fast rtx %u\n", __func__,
                        (uint16_t)pcb->dupacks, pcb->lastack,
                        tcp_seg_seq(tcp_unacked(&pcb->sendq)));
    tcp_rexmit(pcb);

    /* Set ssthresh to half of the minimum of the current
     * cwnd and the advertised window */
    uint32_t snd_wnd = pcb->snd_right_edge - pcb->lastack;
    if (pcb->cwnd > snd_wnd) {
      pcb->ssthresh = snd_wnd / 2;
    } else {
      pcb->ssthresh = pcb->cwnd / 2;
    }
    
    /* The minimum value for ssthresh should be 2 MSS */
    if (pcb->ssthresh < 2*pcb->mss) {
      zf_log_tcp_tx_trace(tcp, "%s: The minimum value for ssthresh %u "
                          "should be min 2 mss %u...\n", __func__,
                          pcb->ssthresh, 2*pcb->mss);
      pcb->ssthresh = 2*pcb->mss;
    }
    
    pcb->cwnd = pcb->ssthresh + 3 * pcb->mss;
    pcb->flags |= TF_INFR;
  }
  tcp_fix_fast_send_length(pcb);
}


static inline void tcp_requeue_unacked(tcp_pcb* pcb)
{
  pcb->sendq.middle = pcb->sendq.begin;
}

static void
tcp_rexmit_rto(tcp_pcb* pcb)
{
  if( ! tcp_has_unacked(&pcb->sendq) )
    return;

  struct zf_stack* stack = zf_stack_from_zocket(pcb);
  tcp_requeue_unacked(pcb);

  /* increment number of retransmissions */
  ++pcb->nrtx;
  ++pcb->stats.retransmits;
  ++stack->stats.tcp_retransmits;
  /* Don't take any RTT measurements after retransmitting. */
  pcb->rttest = 0;

}

/**
 * Send persist timer zero-window probes to keep a connection active
 * when a window update is lost.
 *
 * Called by tcp_slowtmr()
 *
 * @param pcb the tcp_pcb for which to send a zero-window probe packet
 */
int
tcp_zero_window_probe(zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  int err;

  zf_log_tcp_tx_trace(tcp,
                      "%s: sending ZERO WINDOW probe\n", __func__);

  if( tcp_has_unacked(&pcb->sendq) )
    return 1;

  err = tcp_send_empty_ack(tcp, true);

  zf_log_tcp_tx_trace(tcp, "%s: seqno %u ackno %u err %d.\n", __func__,
                      pcb->snd_nxt - 1, pcb->rcv_nxt, (int)err);
  return err;
}


/* Backoff multipliers
 * Each subsequent rto timer will use next entry in the tcp_backoff table.
 * While each subsequent zwin probe will use entry next entry in tcp_persist_backoff.
 */
static const uint8_t tcp_backoff[] =
    { 1, 2, 3, 4, 5, 6, 7 };
static const uint8_t tcp_persist_backoff[8] =
    { 1, 3, 6, 12, 24, 48, 96, 120 };

/* zero win probe initiall timeout around 500ms */
static const zf_tick ZWIN_TIMEOUT = (500 + TCP_TMR_INTERVAL - 1) /
                                    TCP_TMR_INTERVAL;
extern zf_tick
tcp_timers_zwin_timeout(struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  return ZWIN_TIMEOUT * tcp_persist_backoff[pcb->persist_backoff];
}

/* Returns non-zero iff a user-visible event occurred. */
int
tcp_tmr(struct zf_tcp* tcp, int timers_expired)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  struct zf_stack* stack = zf_stack_from_zocket(tcp);

  uint16_t eff_wnd;

  zf_log_timer_trace(tcp, "%s: processing active pcb %d\n", __func__,
                     timers_expired);
  zf_assert_nequal(pcb->state, CLOSED);
  zf_assert_nequal(pcb->state, LISTEN);
  /* Check that no flags are set outside the range of timers we know about */
  zf_assert_nflags(timers_expired, ~ZF_TCP_ALL_TIMERS);
  if( timers_expired & (1u << ZF_TCP_TIMER_TIMEWAIT) ) {
    /* note: ZF_TCP_TIMER_TIMEWAIT == ZF_TCP_TIMER_FINWAIT */
    zf_assert_nequal(pcb->state & (TIME_WAIT | FIN_WAIT_STATE_MASK), 0);
  }

  /* Avoid unnecessary retransmissions, and make sure that any ACKs that we
   * send out are up-to-date. */
  int event_occurred = tcp_rx_flush(stack, tcp);

  if( timers_expired & (1u << ZF_TCP_TIMER_DACK)) {
    zf_assume_impl(pcb->flags & TF_ACK_NEXT, pcb->flags & TF_ACK_DELAY);
    if( pcb->flags & TF_ACK_DELAY ) {
      tcp_send_empty_ack(tcp);
    }
  }

  if( timers_expired & (1u << ZF_TCP_TIMER_ZWIN)) {
    zf_log_timer_trace(tcp, "%s: zwin\n", __func__);
    if( tcp_zero_window_probe(tcp) == 0 ) {
      if (pcb->persist_backoff + 1u < sizeof(tcp_persist_backoff))
        ++pcb->persist_backoff;
      zf_tcp_timers_timer_start(tcp, ZF_TCP_TIMER_ZWIN,
                                tcp_timers_zwin_timeout(tcp));
    }
  }

  if( timers_expired & (1u << ZF_TCP_TIMER_TIMEWAIT)) {
    if( pcb->state == TIME_WAIT ) {
      zf_log_timer_trace(tcp, "%s: timewait\n", __func__);
      tcp_timewait_timeout(stack, tcp);
      return event_occurred;
    }
    zf_log_timer_trace(tcp, "%s: finwait\n", __func__);
    tcp_finwait_timeout(stack, tcp);
    return event_occurred;
  }

  if( ~timers_expired & (1u << ZF_TCP_TIMER_RTO))
    return event_occurred;

  const int syn = pcb->state == SYN_SENT;

  /* we know this is RTO timer firing as the others were handled above */
  if( tcp_has_unacked(&pcb->sendq) || syn ) {
    struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl,
                                             st, stack);

    /* Time for a retransmission. */
    zf_log_timer_trace(tcp, "%s: rto\n", __func__);

    int nrtx_lim = sti->tcp_retries;
    if( syn )
      nrtx_lim = sti->tcp_syn_retries;
    else if( pcb->state == SYN_RCVD )
      nrtx_lim = sti->tcp_synack_retries;

    if( pcb->nrtx >= nrtx_lim ) {
      zf_log_timer_trace(tcp, "%s: drop because of rto\n", __func__);
      zf_muxer_mark_waitable_ready(&tcp->w,
                                   EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR);
      pcb->error = ETIMEDOUT;
      if( ! tcp_is_orphan(tcp) )
        tcp_queue_append_EOF_marker(stack, tcp);
      tcp_pcb_release(stack, tcp);
      return 1; /* this event occured */
    }

    /* Double retransmission time-out unless we are trying to
     * connect to somebody (i.e., we are in SYN_SENT). */
    zf_tcp_timers_timer_start(tcp, ZF_TCP_TIMER_RTO,
                              zf_tcp_timers_rto_timeout(tcp) <<
                              (syn ? 0 :
                               pcb->nrtx < sizeof(tcp_backoff) ?
                               tcp_backoff[pcb->nrtx] :
                               tcp_backoff[sizeof(tcp_backoff) - 1]));

    /* Reduce congestion window and ssthresh. */
    eff_wnd = MIN(pcb->cwnd, pcb->snd_right_edge - pcb->lastack);
    pcb->ssthresh = eff_wnd >> 1;
    if (pcb->ssthresh < pcb->mss) {
      pcb->ssthresh = pcb->mss * 2;
    }
    pcb->cwnd = pcb->mss;
    zf_log_timer_trace(tcp, "%s: cwnd %u ssthresh %u\n", __func__,
                       pcb->cwnd, pcb->ssthresh);

    /* The following needs to be called AFTER cwnd is set to one mss */
    tcp_rexmit_rto(pcb);
    /* Do the actual retransmission */
    tcp_output(tcp);
  }

  return event_occurred;
}


void zft_alt_reset(struct zf_stack* stack,
                   struct zf_alt* alt,
                   struct tcp_pcb* pcb)
{
  alt->tcp.first_byte = pcb->snd_lbb;
  alt->tcp.alt_snd_nxt = pcb->snd_lbb;
  stack->tcp_alt_first_ack[alt->handle] = pcb->rcv_nxt;
}


/* Return the total byte length of this segment on the wire, including
 * all protocol headers. */
static inline unsigned tcp_seg_wire_len(struct zft* ts,
                                        tcp_seg* seg)
{
  return seg->len + zft_get_header_size(ts);
}


int zft_alternatives_queue(struct zft* ts, zf_althandle althandle,
                           const struct iovec* iov, int iov_cnt,
                           int flags)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  zf_stack* stack = zf_stack_from_zocket(tcp);
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl,
                                           st, stack);
  struct tcp_pcb* pcb = &tcp->pcb;
  struct zf_alt* alt = &sti->alt[althandle];

  zf_log_tcp_tx_trace(tcp, "%s: zocket=%u althandle=%u iov_cnt=%d flags=%d.\n",
                      __FUNCTION__, TCP_ID(stack, tcp), althandle, iov_cnt,
                      flags);

  if( ZF_UNLIKELY(althandle >= (unsigned)sti->n_alts) ) {
    zf_log_tcp_tx_trace(tcp, "%s: Invalid handle %u.\n", __FUNCTION__,
                        althandle);
    return -EINVAL;
  }

  if( ZF_UNLIKELY(iov_cnt != 1) ) {
    zf_log_tcp_tx_trace(tcp, "%s: Invalid iov_cnt %d.\n", __FUNCTION__,
                        iov_cnt);
    return -EINVAL;
  }

  if( alt->alt_zocket != NULL && ZF_UNLIKELY(tcp != alt->alt_zocket) ) {
    zf_log_tcp_tx_trace(tcp, "%s: Wrong zocket: %u vs %u.\n", __FUNCTION__,
                        TCP_ID(stack, tcp), TCP_ID(stack, alt->alt_zocket));
    return -EINVAL;
  }

  if( ZF_UNLIKELY(alt->is_draining) ) {
    zf_log_tcp_tx_trace(tcp, "%s: Alternative is draining.\n", __FUNCTION__);
    return -EBUSY;
  }

  uint32_t busy = stack->alts_need_rebuild | stack->alts_rebuilding;
  if( ZF_UNLIKELY(busy & (1 << althandle)) ) {
    zf_log_tcp_tx_trace(tcp, "%s: Alternative is in rebuild.\n", __FUNCTION__);
    return -EBUSY;
  }

  if( ZF_UNLIKELY(tcp_has_unsent(&pcb->sendq)) ) {
    zf_log_tcp_tx_trace(tcp, "%s: Sendq non-empty.\n", __FUNCTION__);
    return -EAGAIN;
  }

  int rc = tcp_write_checks(stack, pcb, iov->iov_len);
  if( ZF_UNLIKELY(rc != 0) ) {
    zf_log_tcp_tx_trace(tcp, "%s: tcp_write_checks() failed: rc=%d.\n",
                        __FUNCTION__, rc);
    return rc;
  }

  auto altq_len = tcp_snd_queuelen(&alt->tcp.altq);
  if( ZF_UNLIKELY(altq_len >= TCP_SND_QUEUE_SEG_COUNT) ) {
    zf_log_tcp_tx_trace(tcp, "%s: Alternative queue is too long: %u.\n",
                        __FUNCTION__, altq_len);
    return -ENOBUFS;
  }

  /* If this is the first packet for this alternative then take its
   * sequence number etc from the main PCB. */
  if( tcp_snd_queuelen(&alt->tcp.altq) == 0 ) {
    zft_alt_reset(stack, alt, pcb);

    /* This alternative is now tied to this zocket */
    alt->alt_zocket = tcp;
    tcp->zocket_alts |= (1 << althandle);
  }

  /* If enqueuing the caller's buffer would increase the length of the queue
   * beyond that of the entire congestion window, then there's no guarantee
   * that we will ever be able to service this call, so fail with EMSGSIZE
   * rather than EAGAIN. */
  if( ZF_UNLIKELY(alt->tcp.alt_snd_nxt - alt->tcp.first_byte + iov->iov_len >
                  pcb->cwnd) ) {
    zf_log_tcp_tx_trace(tcp, "%s: Queue would be larger than congestion "
                              "window: iov_len=0x%08x, alt_snd_nxt=0x%08x "
                              "first_byte=0x%08x cwnd=0x%08x.\n",
                        __FUNCTION__, iov->iov_len, alt->tcp.alt_snd_nxt,
                        alt->tcp.first_byte, pcb->cwnd);
    return -EMSGSIZE;
  }

  /* Check that there is send and congestion window space available */
  if(ZF_UNLIKELY( TCP_SEQ_GT(alt->tcp.alt_snd_nxt + iov->iov_len,
                  pcb->snd_right_edge)) ||
     ZF_UNLIKELY( TCP_SEQ_GT(alt->tcp.alt_snd_nxt + iov->iov_len,
                  pcb->lastack + pcb->cwnd) )) {
    zf_log_tcp_tx_trace(tcp, "%s: Out of window: alt_snd_nxt=0x%08x "
                             "iov_len=0x%08x snd_right_edge=0x%08x "
                             "lastack=0x%08x cwnd=0x%08x.\n",
                        __FUNCTION__, alt->tcp.alt_snd_nxt, iov->iov_len,
                        pcb->snd_right_edge, pcb->lastack, pcb->cwnd);
    return -EAGAIN;
  }

  int saved_altq_end = alt->tcp.altq.end;
  uint32_t saved_seq = alt->tcp.alt_snd_nxt;
  int segs;
  ef_vi* vi = zf_stack_nic_tx_vi(stack, 0);

  /* Preallocate any packets we'll need for moving this to the sendq.  This
   * uses a byte count of the entire alt rather than tracking segs as we will
   * coalesce when adding to the sendq.
   */
  int q_bytes = (alt->tcp.alt_snd_nxt - alt->tcp.first_byte) + iov->iov_len;
  int n_prealloc_orig = alt->n_prealloc;
  while( (alt->n_prealloc * tcp_mss_max_seg(pcb)) < q_bytes ) {
    /* TCP checks should ensure we don't exceed the sendq size */
    zf_assert_lt(alt->n_prealloc, (int)TCP_SND_QUEUE_SEG_COUNT);

    rc = zft_alloc_pkt(&stack->pool, &alt->prealloc[alt->n_prealloc]);
    if( rc < 0 ) {
      zf_log_tcp_tx_trace(tcp, "%s: Failed to allocate packet buffer.\n",
                          __FUNCTION__);
      rc = -ENOMEM;
      goto err_free_prealloc;
    }
    alt->n_prealloc++;
  }

  segs = tcp_queue_unsent_segments(tcp, &alt->tcp.altq, iov,
                                   &alt->tcp.alt_snd_nxt, false);
  if( segs < 0 ) {
    zf_log_tcp_tx_trace(tcp, "%s: tcp_queue_unsent_segments() failed: rc=%d.\n",
                        __FUNCTION__, rc);
    rc = segs;
    goto err_free_prealloc;
  }

  /* Check that we have enough TXQ space to queue these segments and the alt
   * control descriptors.  If not we have to roll back.
   */
  if( ef_vi_transmit_space(vi) < (2 + segs) ) {
    zf_log_tcp_tx_trace(tcp, "%s: Insufficient TXQ space: txq_space=%u "
                             "segs=%d\n",
                        __FUNCTION__, ef_vi_transmit_space(vi),
                        segs);
    rc = -EBUSY;
    goto err_rollback;
  }

  int tx_idx;
  for( tx_idx = 0; tx_idx < segs; tx_idx++ ) {
    struct tcp_seg* seg = tcp_seg_at(&alt->tcp.altq, saved_altq_end + tx_idx);
    /* Check that there is space in the hardware to hold this packet. */
    if( ZF_UNLIKELY(zf_altbm_send_packet(&sti->alt_buf_model, althandle,
                                         tcp_seg_wire_len(ts, seg)) == 0) ) {
      zf_log_tcp_tx_trace(tcp, "%s: Buffer model reports insufficient space.\n",
                          __FUNCTION__);
      rc = -ENOBUFS;
      goto err_unsend;
    }
  }

  ef_vi_transmit_alt_stop(vi, alt->handle);
  ef_vi_transmit_alt_select(vi, alt->handle);

  /* Push the segments to the NIC.  We can't roll this back, so at this
   * point we've checked everything that could go wrong, and nothing should
   * fail.
   */
  for(tx_idx = 0; tx_idx < segs; tx_idx++ ) {
    struct tcp_seg* seg = tcp_seg_at(&alt->tcp.altq, saved_altq_end + tx_idx);
    zf_log_tcp_tx_trace(tcp, "%s: Queueing at altq[%d] seg "TCP_SEG_FMT"\n",
                        __func__, saved_altq_end + tx_idx, TCP_SEG_ARGS(seg));

    zf_assume_equal(tcp_seg_tcphdr(seg)->syn, false);
    zf_assume_equal(tcp_seg_tcphdr(seg)->fin, false);

    rc = tcp_segment_to_vi(tcp, seg, ZF_REQ_ID_PROTO_TCP_ALT);

    /* This is a workaround to avoid preventing tcp_seg_free() from freeing
     * this packet when it is ACKed. See bug65503 and reviewboard /r/19216/ for
     * discussion. */
    seg->in_flight = 0;

    /* We've checked there are enough TXQ spaces to push our descriptors,
     * so this should never fail.
     */
    zf_assert_equal(rc, (int)seg->iov.iov_len);

    alt->n_queued_packets++;
  }

  ef_vi_transmit_alt_select_normal(vi);

  return 0;

 err_unsend:
  zf_log_tcp_tx_trace(tcp, "%s: Unsending.\n", __FUNCTION__);
  zf_assert_lt(tx_idx, segs);
  for(int i = 0; i < tx_idx; i++) {
    struct tcp_seg* seg = tcp_seg_at(&alt->tcp.altq, saved_altq_end + i);
    zf_altbm_unsend_packet(&sti->alt_buf_model, althandle,
                           tcp_seg_wire_len(ts, seg));
  }
 err_rollback:
  zf_log_tcp_tx_trace(tcp, "%s: Rolling back.\n", __FUNCTION__);
  tcp_free_segs(stack, &alt->tcp.altq, saved_altq_end, alt->tcp.altq.end);
  alt->tcp.altq.end = saved_altq_end;
  alt->tcp.alt_snd_nxt = saved_seq;

 err_free_prealloc:
  zf_log_tcp_tx_trace(tcp, "%s: Freeing pre-allocated packets.\n",
                      __FUNCTION__);
  for( int i = n_prealloc_orig; i < alt->n_prealloc; i++ ) {
    zf_assert_nequal(alt->prealloc[i], PKT_INVALID);
    zf_pool_free_pkt(&stack->pool, alt->prealloc[i]);
  }
  alt->n_prealloc = n_prealloc_orig;
  return rc;
}


ZF_HOT int zf_stack_handle_tx_tcp(struct zf_tcp* tcp, zf_tx_req_id req_id)
{
  zf_pool* pool = &zf_stack_from_zocket(tcp)->pool;
  pkt_id pkt = req_id & ZF_REQ_ID_PKT_ID_MASK;
  int idx = (req_id & ZF_REQ_ID_AUX_MASK) >> ZF_REQ_ID_AUX_SHIFT;
  tcp_send_queue* sendq = &tcp->pcb.sendq;
  struct tcp_seg* seg = &sendq->segs[idx];
  if( seg->in_flight && seg->iov.iov_base != NULL &&
      tcp_seg_pkt(seg) == pkt ) {
    zf_log_tcp_tx_trace(tcp, "%s: tx complete %x idx %d "TCP_SEG_FMT
                        " sendq %u-%u-%u\n", __func__,
                        pkt, idx, TCP_SEG_ARGS(seg),
                        sendq->begin, sendq->middle, sendq->end);
    /* The seg is still in queue: */
    zf_assert_le(((unsigned)idx - sendq->begin) &
                 (TCP_SND_QUEUE_SEG_COUNT - 1),
                 tcp_snd_queuelen(sendq));
    seg->in_flight = 0;
    return 0;
  }
  zf_log_tcp_tx_trace(tcp, "%s: tx complete %x idx %d free now\n",
                      __func__, pkt, idx);
  /* Zocket has already released the packet: free it. */
  zf_pool_free_pkt(pool, pkt);
  return 0;
}
