/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_TCP_RX_H__
#define __ZF_INTERNAL_TCP_RX_H__

#include <zf_internal/tcp.h>
#include <zf_internal/tcp_tx.h>
#include <zf_internal/utils.h>

/* Update the window */
static inline void
tcp_update_window(struct zf_tcp* tcp, struct tcphdr* tcp_hdr)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  uint32_t ackno = ntohl(tcp_hdr->ack_seq);
  uint32_t seqno = ntohl(tcp_hdr->seq);
  uint16_t window = ntohs(tcp_hdr->window);

  /* These are the conditions for a window update as specified by RFC793.  That
   * RFC also stipulates that the window should be tracked as an offset from
   * SND.UNA (which we call pcb->lastack).  This is problematic, as the window
   * advertised in the segment is relative not to lastack but to snd_wl2, i.e.
   * the ACK in that packet.  There is some discussion at [1] of Solaris's
   * solution to the problem, but it has its own difficulties.  Instead, we do
   * what Onload does, and record the current right edge of the send window
   * rather than its extent, and so avoid ambiguities.
   *
   * [1] https://blogs.oracle.com/kcpoon/entry/solaris_tcp_window_update.
   *     Retrieved 2016-07-26.
   */

  /* The conditions for a window update are, respectively:
   *   (a) that we have new payload; or
   *   (b) that the segment is no older in sequence space than the most recent,
   *       and has a newer ACK; or
   *   (c) that the the ACK is the same as the last that triggered a window-
   *       update, and the segment expands the window.
   */
  if (TCP_SEQ_LT(pcb->snd_wl1, seqno) ||
      (pcb->snd_wl1 == seqno && TCP_SEQ_LT(pcb->snd_wl2, ackno)) ||
      (pcb->snd_wl2 == ackno && TCP_SEQ_LT(pcb->snd_right_edge,
                                           ackno + window))) {
    pcb->snd_right_edge = ackno + window;

    /* keep track of the biggest window announced by the remote host to
     * calculate the maximum segment size
     */
    if (pcb->snd_wnd_max < window)
      pcb->snd_wnd_max = window;

    pcb->snd_wl1 = seqno;
    pcb->snd_wl2 = ackno;
    tcp_fix_fast_send_length(pcb);
    zf_log_tcp_rx_trace(tcp, "%s: window update %u+%u; snd_nxt=%u\n",
                        __func__,
                        pcb->snd_wl2, window, pcb->snd_nxt);
  }
}


ZF_HOT static inline int16_t
tcp_calculate_rtt_last(struct zf_stack* stack, struct tcp_pcb* pcb)
{
  zf_assert(pcb->rttest);
  return MAX((int16_t)(zf_wheel_get_current_tick(&stack->times.wheel) -
                       pcb->rttest),
             1);
}


ZF_HOT static inline void
tcp_calculate_rtt_est(struct zf_tcp* tcp, uint32_t ackno)
{
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  struct tcp_pcb* pcb = &tcp->pcb;
  int16_t m;

  /* RTT estimation calculations. This is done by checking if the
   * incoming segment acknowledges the segment we use to take a
   * round-trip time measurement.
   */
  if( pcb->rttest && TCP_SEQ_LT(pcb->rtseq, ackno) ) {
    /* diff between this shouldn't exceed 32K since this are tcp timer ticks
     * and a round-trip shouldn't be that long...
     */
    m = tcp_calculate_rtt_last(stack, pcb);

    zf_log_tcp_rx_trace(tcp,
                        "%s: experienced rtt %u ticks (%u msec).\n",
                        __func__, m, m * TCP_TMR_INTERVAL);

    /* Initial RTT should be calculated in different way */
    zf_assert(pcb->sa);

    /* This is Jacobson's algorithm. */
    m = m - (pcb->sa >> 3);
    pcb->sa += m;
    if (m < 0)
      m = -m;

    m = m - (pcb->sv >> 2);
    pcb->sv += m;

    zf_log_tcp_rx_trace(tcp, "%s: RTO %u (%u milliseconds)\n", __func__,
                        zf_tcp_timers_rto_timeout(tcp),
                        zf_tcp_timers_rto_timeout(tcp) * TCP_TMR_INTERVAL);

    pcb->rttest = 0;
  }
}


static inline void
tcp_seg_mark_acked_and_free(zf_stack* stack, tcp_pcb* pcb, tcp_seg* seg)
{
  zf_assert_gt(tcp_snd_queuelen(&pcb->sendq), 0);
  tcp_seg* rseg = tcp_seg_at(&pcb->sendq, pcb->sendq.begin);
  zf_assert_equal(rseg, seg);
  /* if unacked list is empty it means we are freeing unsent we need to move
   * head of unsent as well */
  pcb->sendq.middle += pcb->sendq.middle == pcb->sendq.begin;
  ++pcb->sendq.begin;
  pcb->snd_buf += pcb->mss;
  tcp_seg_free(&stack->pool, rseg);
}


static inline void
handle_acked_segment(struct zf_stack* stack, struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  zf_assert(tcp_has_unacked(&pcb->sendq) || tcp_has_unsent(&pcb->sendq));
  struct tcp_seg* next = tcp_seg_at(&pcb->sendq, pcb->sendq.begin);
  zf_log_tcp_rx_trace(tcp, "%s: removing "TCP_SEG_FMT" from pcb->%s\n",
                      __func__, TCP_SEG_ARGS(next),
                      tcp_has_unacked(&pcb->sendq) ? "unacked" : "unsent");

  zf_log_tcp_rx_trace(tcp, "%s: queuelen %u ... \n", __func__,
                      tcp_snd_queuelen(&pcb->sendq));
  /* Unacked segments count towards our send queue limit.  We've got at
   * least one of those, so should have a non-zero send queue length.
   */

  tcp_seg_mark_acked_and_free(stack, pcb, next);
  zf_log_tcp_rx_trace(tcp, "%s: %u (after freeing acked seg)\n", __func__,
                      tcp_snd_queuelen(&pcb->sendq));

}


ZF_HOT static inline void
tcp_sendq_check_acked(struct zf_tcp* tcp, uint32_t ackno)
{
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  struct tcp_pcb* pcb = &tcp->pcb;

  /* We go through the joint unacked/unsent list to see if any of the segments
   * on the list are acknowledged by the ACK. In respect to unsent segments
   * this may seem strange since an "unsent" segment shouldn't be acked.  The
   * rationale is that we put all outstanding segments on the unsent list after
   * a retransmission, so these segments may in fact have been sent once. */
  while( tcp_snd_queuelen(&pcb->sendq) != 0 &&
         TCP_SEQ_BETWEEN(ackno, tcp_seg_seq(tcp_seg_at(&pcb->sendq, pcb->sendq.begin)) +
                         tcp_seg_len(tcp_seg_at(&pcb->sendq, pcb->sendq.begin)),
                         pcb->snd_nxt + pcb->snd_delegated) )
    handle_acked_segment(stack, tcp);
}


static inline void
tcp_handle_ack_common(struct zf_tcp* tcp, struct tcphdr* tcp_hdr)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  (void) pcb;

  tcp_update_window(tcp, tcp_hdr);

  tcp_calculate_rtt_est(tcp, ntohl(tcp_hdr->ack_seq));

  zf_log_tcp_rx_trace(tcp, "%s: pcb->rttest %u rtseq %u ackno %u\n",
                      __func__,
                      pcb->rttest, pcb->rtseq, ntohl(tcp_hdr->ack_seq));
}


/* Handle ACK of new data */
ZF_HOT static inline void
tcp_handle_ack_new(struct zf_tcp* tcp, struct tcphdr* tcp_hdr)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  uint32_t ackno = ntohl(tcp_hdr->ack_seq);

  /* Update the send buffer space. */
  uint32_t acked = ackno - pcb->lastack;
  if( acked == 0 )
    return;

  /* Reset the "IN Fast Retransmit" flag, since we are no longer
   * in fast retransmit. Also reset the congestion window to the
   * slow start threshold.
   */
  if (pcb->flags & TF_INFR) {
    pcb->flags &= ~TF_INFR;
    pcb->cwnd = pcb->ssthresh;
  }

  /* Reset the number of retransmissions. */
  pcb->nrtx = 0;

  /* Reset the fast retransmit variables. */
  pcb->dupacks = 0;
  pcb->lastack = ackno;

  /* Update the congestion control variables (cwnd and
   * ssthresh).
   */
  if (pcb->state >= ESTABLISHED) {
    if (pcb->cwnd < pcb->ssthresh) {
      if ((uint16_t)(pcb->cwnd + pcb->mss) > pcb->cwnd)
        pcb->cwnd += pcb->mss;
      zf_log_tcp_rx_trace(tcp, "%s: slow start cwnd %u\n", __func__, pcb->cwnd);
    }
    else {
      uint16_t new_cwnd = (pcb->cwnd + pcb->mss * pcb->mss / pcb->cwnd);
      if (new_cwnd > pcb->cwnd)
        pcb->cwnd = new_cwnd;
      zf_log_tcp_rx_trace(tcp, "%s: congestion avoidance cwnd %u\n",
                          __func__, pcb->cwnd);
    }
  }
  zf_log_tcp_rx_trace(tcp, "%s: ACK for %u, has%s unacked\n",
                      __func__,
                      ackno, tcp_has_unacked(&pcb->sendq) ? "" : " not");
  if( tcp_has_unacked(&pcb->sendq) )
    zf_log_tcp_rx_trace(tcp, "%s: unacked "TCP_SEG_FMT"\n",
                        __func__, TCP_SEG_ARGS(tcp_unacked(&pcb->sendq)));

  /* Remove segment from the unacknowledged list if the incoming
     ACK acknowlegdes them. */
  tcp_sendq_check_acked(tcp, ackno);
  zf_assert_equal(pcb->snd_buf, tcp_snd_buf_avail(pcb, &pcb->sendq));
  zf_log_tcp_rx_trace(tcp, "%s: acked %d, new snd_buf %d\n", __func__, acked,
                      pcb->snd_buf);

  tcp_fix_fast_send_length(pcb);

  /* Start or stop RTO timer. */
  tcp_configure_rto_zwin_timers(tcp);
}


static inline int
tcp_maybe_raise_epollout_edge(struct zf_tcp* tcp)
{
  /* Raise an edge if and only if we now have sufficient space but did not
   * last time we checked. */
  if( tcp_tx_advertise_space(tcp) && ! (tcp->w.readiness_mask & EPOLLOUT) ) {
    zf_muxer_mark_waitable_ready(&tcp->w, EPOLLOUT);
    return 1;
  }

  return 0;
}


/* This code path handles the common scenario of processing ACKs in order
 * without any other flags. */
ZF_HOT static inline void
tcp_frequent_path_common_head(struct zf_tcp* tcp, struct tcphdr* tcp_hdr)
{
  struct tcp_pcb* pcb = &tcp->pcb;

  /* ACK flag must be set on this path */
  zf_assert(tcp_hdr->ack);

  tcp_handle_ack_common(tcp, tcp_hdr);
  tcp_handle_ack_new(tcp, tcp_hdr);
  zf_assert_equal(pcb->snd_buf, tcp_snd_buf_avail(pcb, &pcb->sendq));

  /* We might have freed up some send-buffer space, which in turn
   * might have taken us over the threshold at which we advertise our
   * writability. We don't need to return the result of this, though,
   * because we're only ever called from paths where our caller is
   * going to return 1 anyway. */
  tcp_maybe_raise_epollout_edge(tcp);
}


#endif /* ! defined( __ZF_INTERNAL_TCP_RX_H__) */
