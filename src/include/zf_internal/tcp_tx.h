/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#pragma once

#include <zf_internal/tcp.h>
#include <zf_internal/zf_tcp_timers.h>
#include <zf_internal/tx_send.h>
#include <zf_internal/utils.h>

extern int
tcp_write_slow(zf_stack* stack, zf_tcp* tcp, const struct iovec *iov,
               int iov_cnt, int flags);
extern int
tcp_queue_sent_segments(struct zf_tcp* tcp, struct tcp_send_queue* sendq,
                        const iovec* iov, uint32_t* seq);

extern void
tcp_output_timers_common(struct zf_stack* stack, struct zf_tcp* tcp,
                         uint32_t seq);


/** \brief Checks if tcp_write is allowed or not
 *
 * \param pcb
 * \param len The amount of date desired to be written
 *
 * TCP TX internal
 */
static inline int tcp_write_checks_fast(tcp_pcb *pcb, uint16_t len)
{
  /* note: for fast send we do not need to check the pool size as
   * we have got a preallocated packet */

  /* connection is in invalid state for data transmission? */
  if( !(pcb->state & FAST_SEND_STATE_MASK) ) {
    if( pcb->state & SEND_STATE_MASK ) /* SYN_SENT/SYN_RCVD */
      return -EAGAIN;
    return -ENOTCONN;
  }

  if( len == 0 )
    return 0;

  /* Ensure we properly maintain snd_buf value. */
  zf_assert_equal(pcb->snd_buf, tcp_snd_buf_avail(pcb, &pcb->sendq));

  if( pcb->snd_delegated != 0 )
    return -EBUSY;

  /* fail on too much data. Note: partial send is supported, and even
   * filling the remainder of the last sendq segment when sendq is full */
  if( ZF_UNLIKELY(pcb->snd_buf == 0) &&
      (! tcp_has_unsent(&pcb->sendq) ||
       tcp_mss_max_seg(pcb) == tcp_seg_last(&pcb->sendq)->len) )
    return -EAGAIN;

  /* Sanity check queuelen - if there's something queued we should have an
   * unacked or unsent queue.  If there's not then those queues should be
   * empty.
   */
  zf_assert( (tcp_snd_queuelen(&pcb->sendq) == 0) ^
             (tcp_has_unacked(&pcb->sendq) || tcp_has_unsent(&pcb->sendq)) );

  /* For fast send check for number of free packets in the pool is not needed
   * as there is a preallocated packet held for insertion in retrans queue.
   * And in case of failure to allocate pkt for DMA, retransmit behaviour will
   * kick in */
  return 0;
}

static inline int tcp_write_checks(zf_stack* stack, tcp_pcb *pcb, uint16_t len)
{
  /* Possibly not enough pkt buffers to allocate.
   * Worst case maximum send size would fail as
   * each segment requires one pkt buffer to post and one to store
   * in send queue.
   * We avoid precise check to keep the condition simple.*/
  if( ZF_SEND_POOL_THRESHOLD > NUM_FREE_PKTS(&stack->pool) ) {
    ZF_ONCE(
      zf_log_stack_err(stack, "No free packet buffers to perform a send.  "
                              "Rerun application with more packet buffers, see "
                              "n_bufs attribute.\n") );
    pcb->stats.send_nomem++;
    return -ENOMEM;
  }
  return tcp_write_checks_fast(pcb, len);
}


static inline void
tcp_output_populate_header_fast(struct tcphdr* tcp_hdr, uint32_t seq_he,
                                uint32_t ack_he, uint32_t window_he,
                                uint8_t /* bool */ psh_flag)
{
  tcp_hdr->seq = htonl(seq_he);
  tcp_hdr->ack_seq = htonl(ack_he);
  tcp_hdr->window = htons(window_he);
  tcp_hdr->psh = psh_flag;
}


void tcp_output_populate_header(struct tcphdr* tcp_hdr,
                                uint16_t local_port_he,
                                uint16_t remote_port_he, uint32_t seq_he,
                                uint32_t ack_he, uint32_t window_he);


/* Sends packet with tcp header from zocket cache.
 * This  function does not indicate failure in any way. */
static inline pkt_id
tcp_send_with_tcp_header(struct zf_tcp* tcp, const void* buf, size_t buflen,
                         zf_tx_req_id req_id)
{
  struct zf_tx* tx = &tcp->tst;
  int rc;
  zf_tx_req_id* txq_req_id = NULL;
  if(ZF_LIKELY( ! zf_tx_do_vlan(tx) ))
    rc = send_with_hdr(tx, buf, buflen, (uint8_t*) zf_tx_ethhdr(tx),
                       TCP_HDR_SIZE, tx->tcp_hdr_fill_size,
                       req_id,
                       &txq_req_id);
  else
    rc = send_with_hdr(tx, buf, buflen, (uint8_t*) zf_tx_ethhdr(tx),
                       TCP_HDR_SIZE + VLAN_HLEN, tx->tcp_vlanhdr_fill_size,
                       req_id,
                       &txq_req_id);
  zf_assert_impl(rc < 0, txq_req_id == NULL);
  if( txq_req_id == NULL || (*txq_req_id & ZF_REQ_ID_PIO_FLAG) ||
      (req_id & ZF_REQ_ID_PROTO_MASK) == ZF_REQ_ID_PROTO_TCP_FREE )
    return PKT_INVALID;
  return *txq_req_id & ZF_REQ_ID_PKT_ID_MASK;
}


static inline zf_tx_req_id tcp_output_req_id(struct zf_tcp* tcp, pkt_id pkt,
                                             unsigned seg_idx)
{
  unsigned zock_id = TCP_ID(zf_stack_from_zocket(tcp), tcp);
  zf_assume_equal(pkt, pkt & ZF_REQ_ID_PKT_ID_MASK);
  zf_assume_equal(zock_id, zock_id &
                           (ZF_REQ_ID_ZOCK_ID_MASK >> ZF_REQ_ID_ZOCK_ID_SHIFT));
  zf_assume_equal(seg_idx, seg_idx &
                           (ZF_REQ_ID_AUX_MASK >> ZF_REQ_ID_AUX_SHIFT));
  return
    pkt |
    (seg_idx << ZF_REQ_ID_AUX_SHIFT) |
    (zock_id << ZF_REQ_ID_ZOCK_ID_SHIFT);
}

/* \brief Fast path output function.
 *
 * \param tcp
 * \param iov_base     iovec pointing at the ethernet/ip/tcphdr
 * \param iov_payload  iovec pointing at the TCP payload
 *
 * This output function does not require a tcp_seg to have been constructed.
 *
 * It uses the zf_tx header structure for header information.  This must be
 * complete, with the following exceptions:
 * IP: tot_len
 * TCP: ack_seq, window, psh
 */
static inline pkt_id tcp_output_segment_fast(struct zf_tcp* tcp,
                                             const struct iovec* iov_payload)
{
  zf_tx_iphdr(&tcp->tst)->tot_len = htons(IP_HLEN + TCP_HLEN +
                                          iov_payload->iov_len);

  /* We don't mind if this fails: the packet will be queued up for
   * retransmission at some point in the future. */
  pkt_id pkt =
    tcp_send_with_tcp_header(
      tcp, iov_payload->iov_base, iov_payload->iov_len,
      tcp_output_req_id(tcp, PKT_INVALID,
                        tcp->pcb.sendq.end % TCP_SND_QUEUE_SEG_COUNT) |
      ZF_REQ_ID_PIO_FLAG | ZF_REQ_ID_PROTO_TCP_KEEP);

  return pkt;
}


/** \brief Fast path send.  For use when send:
 * - is < MSS
 * - is inside window
 * - sendqueue is empty
 *
 * This updates the headers in the zf_tx structure, sends the data, then
 * updates the other state.
 *
 * \return 0 If all data was successfully sent
 *
 * TCP TX internal
 */
extern void tcp_fast_send_tail(zf_tcp* tcp, const iovec* iov, pkt_id pkt);

ZF_HOT static inline void tcp_fast_send(zf_tcp* tcp, const iovec* iov)
{
  struct tcp_pcb* pcb = &tcp->pcb;

  /* We need no delegated sends in progress */
  zf_assume_equal(pcb->snd_delegated, 0);

  /* We need to have an empty outgoing send queue so we know we can just jam
   * this straight out.
   */
  zf_assume( ! tcp_has_unsent(&pcb->sendq) );
  zf_assume_equal(pcb->snd_lbb, pcb->snd_nxt);

  /* We need to know this is small enough that we don't need to chop it up */
  zf_assume_le(iov->iov_len, pcb->mss);

  /* We need to know we're actually allowed to send this much data. */
  zf_assume(TCP_SEQ_LEQ((uint32_t) iov->iov_len + pcb->snd_lbb,
                        pcb->snd_right_edge));
  zf_assume_lt(iov->iov_len, pcb->cwnd);

  /* And we need to be in a valid state to send data */
  zf_assume_ge(pcb->state, ESTABLISHED);

  /* Right!  Looks good.  Firstly, update the headers based on pcb state.
   * For a fast send we use the zf_tx headers
   */
  tcp_output_populate_header_fast(zf_tx_tcphdr(&tcp->tst), pcb->snd_lbb,
                                  pcb->rcv_nxt, pcb->rcv_ann_wnd, 1);

  /* Now bung it onto the wire */
  pkt_id pkt = tcp_output_segment_fast(tcp, iov);

  tcp_fast_send_tail(tcp, iov, pkt);
}


static inline void
tcp_send_assert_validity(tcp_pcb* pcb, bool do_fast, int len)
{
  zf_assert_flags(pcb->flags, TF_FASTSEND_DBG);
  pcb->flags &= ~ TF_FASTSEND_DBG;

  /* these checks should have been incorporated into fast_send_len computation */
  int rc = tcp_write_checks_fast(pcb, len);
  zf_assert_impl(do_fast, rc == 0);

  int fast_send_len = pcb->fast_send_len;
  tcp_fix_fast_send_length(pcb);
  zf_assert_equal(fast_send_len, pcb->fast_send_len);
  /* Set this to zero so if this function is called again without
   * fast_send_len being updated we will see the assertion above
   * fire.  The caller has already checked there is enough space.
   */
  pcb->fast_send_len = 0;
}


ZF_HOT static inline bool
can_do_tcp_fast_send(const tcp_pcb* pcb, unsigned length)
{
  /* Note: fast_send_len was generated after critical path based on broad
   * tcp zocket state (see tcp_fix_fast_send_length()).
   * fast_send_len must be up to date.
   */
  return ( length <= pcb->fast_send_len );
}


ZF_HOT static inline int tcp_write(zf_tcp* tcp, const iovec *iov, int flags)
{
  tcp_pcb* pcb = &tcp->pcb;
  zf_stack* stack = zf_stack_from_zocket(tcp);

  zf_log_tcp_tx_trace(tcp, "tcp_write(pcb=%p, data=%p, len=%zd)\n", pcb,
                      iov->iov_base, iov->iov_len);

  bool do_fast = can_do_tcp_fast_send(pcb, iov->iov_len);
#ifndef NDEBUG
  tcp_send_assert_validity(pcb, do_fast, iov->iov_len);
#endif
  if(ZF_LIKELY( do_fast ) && ZF_LIKELY( flags == 0 )) {
    tcp_fast_send(tcp, iov);
    return iov->iov_len;
  }

  return tcp_write_slow(stack, tcp, iov, 1, flags);
}


/* A zocket will claim to be writable only when the free space in its sendq is
 * above a certain threshold.  This will not prevent sends from succeeding when
 * the space is below that threshold, however. */
static inline bool tcp_tx_advertise_space(struct zf_tcp* tcp)
{
  return tcp->pcb.snd_buf >= tcp->pcb.snd_buf_advertisement_threshold;
}

/* Update a zocket to indicate that all received data is acked and
 * no delayed ack will be needed.
 */
static inline void tcp_tx_cancel_delayed_ack(struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  pcb->flags &= ~(TF_ACK_DELAY | TF_ACK_NEXT | TF_ACK_NOW);
  pcb->rcv_ack_sent = pcb->rcv_nxt;
  zf_tcp_timers_timer_stop(tcp, ZF_TCP_TIMER_DACK);
}

