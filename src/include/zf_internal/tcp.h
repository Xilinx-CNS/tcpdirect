/* SPDX-License-Identifier: BSD-3-Clause */
/* SPDX-FileCopyrightText: (c) 2016-2021 Advanced Micro Devices, Inc. */
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
 * 
 * Author: Adam Dunkels <adam@sics.se>
 */
#ifndef __ZF_INT_TCP_H__
#define __ZF_INT_TCP_H__

#include <zf/zf.h>
#include <zf_internal/tcp_opt.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/timers.h>
#include <zf_internal/timekeeping.h>
#include <zf_internal/tcp_types.h>
#include <zf_internal/rx.h>
#include <zf_internal/zf_tcp_timers.h>

#include <sys/uio.h>
#include <netinet/tcp.h>


static const zf_logger zf_log_tcp_rx_err(ZF_LC_TCP_RX, ZF_LL_ERR);
static const zf_logger zf_log_tcp_conn_err(ZF_LC_TCP_CONN, ZF_LL_ERR);
#ifndef NDEBUG
static const zf_logger zf_log_tcp_rx_trace(ZF_LC_TCP_RX, ZF_LL_TRACE);
static const zf_logger zf_log_tcp_tx_trace(ZF_LC_TCP_TX, ZF_LL_TRACE);
static const zf_logger zf_log_tcp_conn_trace(ZF_LC_TCP_CONN, ZF_LL_TRACE);
#else
#define zf_log_tcp_rx_trace(...) do{}while(0)
#define zf_log_tcp_tx_trace(...) do{}while(0)
#define zf_log_tcp_conn_trace(...) do{}while(0)
#endif

#define TCP_SEG_FMT "seg %p %u:%u pkt %x%s"
#define TCP_SEG_ARGS(seg) \
  seg, tcp_seg_seq(seg), tcp_seg_seq(seg) + tcp_seg_len(seg), \
  tcp_seg_pkt(seg), seg->in_flight ? " in flight" : ""

struct tcp_pcb;

ZF_COLD extern const char* tcp_state_num_str(int state_i);


static inline tcp_seg*
tcp_seg_at(tcp_send_queue* sendq, unsigned i)
{
  zf_assert_le((uint16_t)(i - sendq->begin), TCP_SND_QUEUE_SEG_COUNT);
  zf_assert_le((uint16_t)(sendq->end - i - 1), TCP_SND_QUEUE_SEG_COUNT);
  return &sendq->segs[i % TCP_SND_QUEUE_SEG_COUNT];
}


/* First packet to send on unsent queue */
static inline tcp_seg*
tcp_unsent(tcp_send_queue* sendq)
{
  return tcp_seg_at(sendq, sendq->middle);
}

/* Last packet on the queue sent or unsent */
static inline tcp_seg*
tcp_seg_last(tcp_send_queue* sendq)
{
  return tcp_seg_at(sendq, sendq->end - 1);
}

static inline uint16_t
tcp_snd_queuelen(tcp_send_queue* sendq)
{
  return sendq->end - sendq->begin;
}
static inline uint32_t
tcp_snd_buf_avail(tcp_pcb* pcb, tcp_send_queue* sendq)
{
  return (TCP_SND_QUEUELEN - tcp_snd_queuelen(sendq)) * (uint32_t)pcb->mss;
}


/* First packet to ack on unacked queue */
static inline tcp_seg*
tcp_unacked(tcp_send_queue* sendq)
{
  return tcp_seg_at(sendq, sendq->begin);
}


static inline
int tcp_has_unsent(tcp_send_queue* sendq)
{
  return sendq->middle != sendq->end;
}


static inline
int tcp_has_unacked(tcp_send_queue* sendq)
{
  return sendq->middle != sendq->begin;
}

static inline
int tcp_has_sendq(tcp_send_queue* sendq)
{
  return sendq->begin != sendq->end;
}


static inline struct tcphdr* tcp_seg_tcphdr(struct tcp_seg* seg)
{
  return (struct tcphdr*) seg->iov.iov_base;
}


static inline uint16_t tcp_seg_len(struct tcp_seg* seg)
{
  struct tcphdr* tcp_hdr = tcp_seg_tcphdr(seg);

  if (ZF_UNLIKELY(tcp_hdr->fin || tcp_hdr->syn))
    return seg->len + 1;
  else
    return seg->len;
}


static inline uint32_t tcp_seg_seq(struct tcp_seg* seg)
{
  return ntohl(tcp_seg_tcphdr(seg)->seq);
}


ZF_HOT pkt_id tcp_seg_pkt(struct tcp_seg* seg);


static inline int tcp_mss_max_seg(tcp_pcb* pcb)
{
  /* We don't allocate segments bigger than half the maximum window we
   * ever received. This is because we don't have support for splitting
   * segments, so if we end up with a segment that is larger than the window
   * we get stuck. Testing with a linux peer with small recvbuf shows that
   * even after it's drained all data from the socket recvq it doesn't
   * necessarily fully open up the window to the initial value, hence the
   * halving to try and be on the safe side.
   */
  if( ZF_LIKELY( pcb->snd_wnd_max > 0 ) )
    return MIN(pcb->mss, pcb->snd_wnd_max/2);
  return pcb->mss;
}

static inline void tcp_disable_fast_send(tcp_pcb* pcb) {
  pcb->fast_send_len = 0;
}

static inline void tcp_fix_fast_send_length(tcp_pcb* pcb)
{
#ifndef NDEBUG
  pcb->flags |= TF_FASTSEND_DBG;
#endif
  if( !(pcb->state & FAST_SEND_STATE_MASK) ||
      tcp_has_unsent(&pcb->sendq) || /* unsent data or retransmitting */
      (pcb->snd_delegated != 0) ||
      (pcb->fast_pkt == PKT_INVALID) ||
      (tcp_snd_queuelen(&pcb->sendq) == TCP_SND_QUEUE_SEG_COUNT) ) {
    if( (pcb->state & FAST_SEND_STATE_MASK) && pcb->snd_lbb != pcb->snd_nxt )
      zf_assert(tcp_has_unsent(&pcb->sendq));
    pcb->fast_send_len = 0;
    return;
  }
  /* Since delegated send allows to send out-of-window data
   * available_rcv_wnd should be set to zero in this case */
  int available_rcv_wnd = MAX(0, TCP_SEQ_SUB(pcb->snd_right_edge,
                                             pcb->snd_lbb));
  int available_cwnd = MAX(0, TCP_SEQ_SUB(pcb->cwnd + pcb->lastack,
                                          pcb->snd_lbb));
  int fast_send_len =
          MIN(MIN(available_rcv_wnd,
                  available_cwnd),
          tcp_mss_max_seg(pcb));
#if 0
  /* It is too verbose for generic zf_log_*_trace(), but very useful in
   * some cases. */
  zf_log(NULL, "%s: fast_send_len=%d snd_nxt=%u snd_lbb=%u snd_right_edge=%u (%d) "
         "delegated=%u lastack=%u cwnd=%d (%d)  tcp_mss_max_seg=%d\n",
         __func__, fast_send_len, pcb->snd_nxt, pcb->snd_lbb,
         pcb->snd_right_edge, TCP_SEQ_SUB(pcb->snd_right_edge, pcb->snd_lbb),
         pcb->snd_delegated, pcb->lastack, pcb->cwnd,
         TCP_SEQ_SUB(pcb->cwnd + pcb->lastack, pcb->snd_lbb),
         tcp_mss_max_seg(pcb));
#endif

  zf_assert_ge(fast_send_len, 0);
  zf_assert_le(fast_send_len, tcp_mss_max_seg(pcb));

  pcb->fast_send_len = fast_send_len;
}


/* Interface to rest of ZF */
struct zf_stack;
struct zf_tcp;
struct zf_tcp_listen_state;
struct zf_tcp_listenq;


/* FIXME: these are stats points, but they're not wired up. */
#define TCP_STATS_INC(x)
#define MIB2_STATS_INC(x)

extern void tcp_fix_fast_send(zf_stack* stack, tcp_pcb* pcb);


ZF_HOT static inline void
tcp_dack_flags_flick(tcp_pcb* pcb)
{
  /* Acknowledge the segment(s), setting up delayed or immediate ACK.
   *
   * See flags_ack_delay definition for some comments.
   * If pcb->flags has TF_ACK_NEXT set it will therefore match and we
   * will get an immediate ack.
   * If pcb->flags doesn't have TF_ACK_NEXT it will only match if TF_ON
   * is set in flags_ack_delay, i.e. if we've requested delayed ack be
   * disabled, and we'll get an immediate ack.
   * The TF_ACK_DELAY flag is used to inform the delayed-ACK timer that
   * it should emit an ACK, and does not affect the ACK-every-other-
   * segment behaviour.
   */
  if( pcb->flags & pcb->flags_ack_delay ) {
    pcb->flags &= ~(TF_ACK_DELAY | TF_ACK_NEXT);
    pcb->flags |= TF_ACK_NOW;
  }
  else {
    pcb->flags |= TF_ACK_DELAY | TF_ACK_NEXT;
  }

  zf_assume_impl(pcb->flags & TF_ACK_NEXT, pcb->flags & TF_ACK_DELAY);
}


extern int
tcp_handle_ooo_pkts(struct zf_stack* stack, struct zf_tcp* tcp);

extern int
tcp_output(struct zf_tcp* tcp);

/* Operations performed after each (possibly batched) rx */
ZF_HOT static inline int
tcp_rx_common_tail(zf_stack* st, zf_tcp* tcp)
{
  int event_occurred = tcp_handle_ooo_pkts(st, tcp);

  /* Try to send something out */
  tcp_output(tcp);

  zf_assume_impl(tcp->pcb.flags & TF_ACK_NEXT, tcp->pcb.flags & TF_ACK_DELAY);
  if( tcp->pcb.flags & TF_ACK_DELAY )
    zf_tcp_timers_timer_start(tcp, ZF_TCP_TIMER_DACK,
                              zf_tcp_timers_dack_timeout(tcp));
  return event_occurred;
}


extern bool tcp_is_orphan(zf_tcp* tcp);

extern ZF_COLD int
tcp_listen_input(struct zf_stack* stack, struct zf_tcp_listen_state* tls,
                 const struct ethhdr* eth_hdr, const struct iphdr* ip_hdr,
                 const struct tcphdr* tcp_hdr);

extern ZF_COLD int
tcp_connect(struct zf_tcp* tcp, const struct sockaddr_in* raddr);

extern ZF_COLD int
tcp_bind(struct zf_tcp* tcp, const struct sockaddr_in* laddr);

extern ZF_COLD int
tcp_shutdown_tx(struct zf_tcp* tcp);

extern ZF_COLD void
tcp_abort(struct zf_stack*, struct zf_tcp*);

extern ZF_COLD void
tcp_shutdown(struct zf_tcp* tcp);

extern ZF_COLD int
tcp_shutdown_listen(struct zf_stack*, struct zf_tcp_listen_state*);

extern ZF_HOT void
tcp_recved(struct zf_tcp* tcp, int len);

extern ZF_COLD void
tcp_dump(struct zf_tcp* tcp);

extern ZF_COLD void
tcp_dump_sendq(struct tcp_send_queue* sendq);

extern ZF_COLD int zftl_listenq_alloc_size(uint16_t max_syn_backlog);

struct zf_allocator;
extern ZF_COLD int
zftl_listenq_init(zf_allocator* a, struct zf_tcp_listenq* listenq, uint16_t max_syn_backlog);

extern ZF_COLD void
zftl_listenq_fini(zf_allocator* a, struct zf_tcp_listenq* listenq);

extern ZF_COLD void
zftl_release(struct zf_stack* stack, struct zf_tcp_listen_state* tls);

extern ZF_HOT void
zft_init_tx_ip_hdr(struct iphdr* ip, uint32_t laddr_be,
                   uint32_t raddr_be);

/* Interface within TCP handling */
extern int
tcp_send_empty_ack(struct zf_tcp* tcp, bool zero_win_probe = false);
extern ZF_COLD void
tcp_init(struct zf_tcp* tcp);
extern uint32_t
tcp_update_rcv_ann_wnd(struct tcp_pcb *pcb);
extern int
tcp_enqueue_flags(struct zf_tcp* tcp, uint8_t syn, uint8_t fin, uint8_t ack);
extern zf_tick
tcp_timers_zwin_timeout(struct zf_tcp* tcp);

extern void
tcp_finwait_timeout_start(zf_stack* stack, zf_tcp* tcp);

/** \brief Frees a packet buffer belonging to a TCP segment (tcp_seg structure).
 *
 * \param pool
 * \param seg single tcp_seg to free
 *
 * Segment structs reside in sendq ring, no need to free memory.
 * Freeing segment from queue to be performed separately.
 *
 * TCP shared
 */
static inline void tcp_seg_free(zf_pool* pool, tcp_seg *seg)
{
  if( ! seg->in_flight )
    zf_pool_free_pkt(pool, tcp_seg_pkt(seg));
  /* In-flight packets will be freed by TX complete, but we should mark the
   * segment as unused.  To tell TX complete function that it should free
   * the packet, it is sufficient to set any of 'in_flight' ot 'pkt' fields
   * in the segment (see zf_stack_handle_tx_tcp). */
  seg->in_flight = false;
}

extern ZF_COLD void
tcp_queue_append_EOF_marker(zf_stack* stack, zf_tcp* tcp);


extern void
tcp_free_segs(zf_stack* st, tcp_send_queue* sendq, tcp_send_queue::idx begin,
              tcp_send_queue::idx end);
extern ZF_COLD void
tcp_free_sendq(zf_stack* st, tcp_send_queue* sendq);
extern ZF_COLD void
tcp_rexmit(struct tcp_pcb *pcb);
extern void
tcp_segs_free(struct zf_stack* stack, struct tcp_seg *seg);
extern ZF_COLD void
tcp_rexmit_fast(struct zf_tcp* tcp);
extern ZF_COLD int
tcp_send_fin(struct zf_tcp* tcp);
extern ZF_COLD void
tcp_rst(struct zf_stack* stack, struct zf_tx* tx, uint32_t raddr_h,
        uint32_t seqno_h, uint32_t ackno_h, uint16_t window_h,
        uint16_t lport_h, uint16_t rport_h, bool no_ack);
extern ZF_COLD void
tcp_pcb_purge(struct zf_tcp* tcp);
ZF_COLD extern void
tcp_rx_table_entry_free(struct zf_stack* stack, struct zf_tcp* tcp);
ZF_COLD extern void
tcp_pcb_release(struct zf_stack* stack, struct zf_tcp* tcp);
ZF_COLD extern void
tcp_timewait_timeout(struct zf_stack* stack, struct zf_tcp* tcp);
ZF_COLD extern void
tcp_finwait_timeout(struct zf_stack* st, struct zf_tcp* tcp);

ZF_COLD static inline ZF_NOINLINE void
dump_pkt(struct zf_stack* st, const char* buf, int len)
{
  int row = 0, index = 0;
  int rows = len/16;
  char row_buf[48];
  char* row_ptr;
  if( len % 16 )
    rows++;

  for(row = 0; row < rows; row++) {
    row_ptr = row_buf;
    row_ptr += sprintf(row_ptr, "%02x\t", row * 16);
    for(index = row * 16; (index < (row+1) * 16) && (index < len); index++) {
      row_ptr += sprintf(row_ptr, "%02x", (uint8_t)buf[index]);
      if(index % 2)
        row_ptr += sprintf(row_ptr, " ");
    }
    zf_log_tcp_rx_trace(st, "%s\n", row_buf);
  }
}

ZF_HOT void tcp_populate_header_common(struct tcphdr* tcp_hdr, uint16_t local_port_he,
                                       uint16_t remote_port_he);

uint16_t tcp_mss_restrict(uint16_t mss);
uint16_t tcp_mtu2mss(uint16_t mtu);

ZF_COLD extern void tcp_do_transition(struct zf_tcp* tcp, enum tcp_state new_state);

int tcp_segment_to_vi(struct zf_tcp* tcp, struct tcp_seg* seg,
                      uint32_t flags);

extern bool
tcp_process(struct zf_tcp* tcp, struct tcp_seg* seg, uint8_t* recv_flags);

extern int
tcp_process_reset(struct zf_tcp* tcp, uint8_t* recv_flags, uint32_t seqno,
                  uint32_t ackno);

extern int
tcp_post_process(struct zf_stack* stack, struct zf_tcp* tcp,
                 struct tcp_seg* seg, char* payload, uint8_t recv_flags);

ZF_HOT extern void tcp_configure_rto_zwin_timers(struct zf_tcp* tcp);

#endif /* __ZF_INT_TCP_H__ */
