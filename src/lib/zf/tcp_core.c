/* SPDX-License-Identifier: BSD-3-Clause */
/* SPDX-FileCopyrightText: (c) 2016-2021 Advanced Micro Devices, Inc. */
/*
 * Incorporates code from lwIP TCP/IP stack.
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


#include <zf_internal/zf_tcp.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/rx_res.h>
#include <zf_internal/tcp.h>
#include <zf_internal/zf_tcp_timers.h>
#include <zf_internal/stack_params.h>
#include <zf_internal/zf_alts.h>

#include <zf_internal/private/zf_stack_rx.h>


static const char* closed_str = "CLOSED";
static const char* syn_sent_str = "SYN-SENT";
static const char* syn_rcvd_str = "SYN-RCVD";
static const char* established_str = "ESTABLISHED";
static const char* close_wait_str = "CLOSE-WAIT";
static const char* last_ack_str = "LAST-ACK";
static const char* fin_wait_1_str = "FIN-WAIT1";
static const char* fin_wait_2_str = "FIN-WAIT2";
static const char* closing_str = "CLOSING";
static const char* time_wait_str = "TIME-WAIT";
static const char* invalid_str = "INVALID";

const char* tcp_state_num_str(int state_i)
{
  switch(state_i) {
    case CLOSED:
      return closed_str;
      break;
    case SYN_SENT:
      return syn_sent_str;
      break;
    case SYN_RCVD:
      return syn_rcvd_str;
      break;
    case ESTABLISHED:
      return established_str;
      break;
    case CLOSE_WAIT:
      return close_wait_str;
      break;
    case LAST_ACK:
      return last_ack_str;
      break;
    case FIN_WAIT_1:
      return fin_wait_1_str;
      break;
    case FIN_WAIT_2:
      return fin_wait_2_str;
      break;
    case CLOSING:
      return closing_str;
      break;
    case TIME_WAIT:
      return time_wait_str;
      break;
    default:
      return invalid_str;
      break;
  };
}


/** \brief Calculates a new initial sequence number for new connections.
 *
 * \return pseudo random sequence number
 *
 * TCP core internal
 */
uint32_t tcp_next_iss(void)
{
  uint64_t frc = zf_frc64();
  return __bswap_32((uint32_t) frc);
}


bool tcp_is_orphan(zf_tcp* tcp)
{
  /* non-orphans have user and state machine reference
   * orphans have state machine reference only
   * Zockets on the accept queue do not count as orphans, they will always
   * have either two references, or have tcp->pcb.state == CLOSED.
   */
  zf_assert_nequal(tcp->refcount, 0);
  return tcp->refcount == 1 && tcp->pcb.state != CLOSED;
}


void tcp_finwait_timeout_start(zf_stack* stack, zf_tcp* tcp)
{
  if( ! (stack->flags & ZF_STACK_FLAG_TCP_FIN_WAIT_TIMEOUT_DISABLED ) &&
      tcp_is_orphan(tcp) )
    zf_tcp_timers_timer_start(tcp, ZF_TCP_TIMER_FINWAIT,
                              zf_tcp_timers_finwait_timeout(stack));
}

void tcp_do_transition(struct zf_tcp* tcp, enum tcp_state new_state)
{
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  enum tcp_state old_state = tcp->pcb.state;

  zf_log_tcp_conn_trace(tcp, "%s: old_state 0x%x new_state 0x%x, flags %x\n",
                        __func__, old_state, new_state, stack->flags);

#ifndef NDEBUG
  /* Catch any state-changes not mediated by this function. */
  zf_assert_equal(tcp->pcb.state, tcp->pcb.mediated_state);
#endif

  /* No-op transitions are not allowed. */
  zf_assert_nequal(new_state, old_state);

  /* Do the transition. */
  tcp->pcb.state = new_state;
#ifndef NDEBUG
  tcp->pcb.mediated_state = new_state;
#endif

  switch( new_state ) {
  case SYN_RCVD:
  case SYN_SENT:
    /* This zocket now prevents stack quiescence. */
    zf_stack_busy_ref(stack);

    zf_muxer_mark_waitable_not_ready(&tcp->w, EPOLLOUT | EPOLLHUP);
    break;

  case TIME_WAIT:
    /* Entering TIME_WAIT causes the zocket to cease preventing stack
     * quiescence when the stack is so configured. */
    if( ! (stack->flags & ZF_STACK_FLAG_TCP_WAIT_FOR_TIME_WAIT) )
      zf_stack_busy_release(stack);

    zf_muxer_mark_waitable_ready(&tcp->w, EPOLLIN | EPOLLOUT | EPOLLHUP);
    zf_tcp_timers_timer_stop(tcp, ZF_TCP_TIMER_ZWIN);
    zf_tcp_timers_timer_start(tcp, ZF_TCP_TIMER_TIMEWAIT,
                              zf_tcp_timers_timewait_timeout(stack));
    break;

  case CLOSING:
    /* We've got FIN - show RDHUP */
    zf_muxer_mark_waitable_ready(&tcp->w, EPOLLIN | EPOLLRDHUP | EPOLLHUP);
    /*fallthrough*/
  case FIN_WAIT_1:
  case FIN_WAIT_2:
  case LAST_ACK:
    tcp_finwait_timeout_start(stack, tcp);
    break;

  case CLOSED:
    /* When leaving the state machine, we should drop the reference unless
     * we've already done so. */
    if( old_state != TIME_WAIT ||
        stack->flags & ZF_STACK_FLAG_TCP_WAIT_FOR_TIME_WAIT )
      zf_stack_busy_release(stack);

    zf_muxer_mark_waitable_ready(&tcp->w, EPOLLIN | EPOLLRDHUP |
                                          EPOLLOUT | EPOLLHUP);
    break;

  case CLOSE_WAIT:
    zf_muxer_mark_waitable_ready(&tcp->w, EPOLLIN | EPOLLRDHUP);
    break;

  default:
    break;
  }

  tcp_fix_fast_send_length(&tcp->pcb);
}


/** \brief Abort a TCP connection
 *
 * \param tcp
 *
 * Abandons a connection and sends a RST to the peer if needed.  Releases the
 * reference to the zf_tcp.
 *
 * Because this function actually does the RST and release we can't use the
 * zf_tcp after calling it.  That means it can't be used for zf_tcps that
 * are being processed via tcp_input.
 */
void tcp_abort(struct zf_stack* stack, struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  zf_log_tcp_conn_trace(tcp, "%s: state 0x%x\n", __func__, pcb->state);

  /* pcb->state LISTEN not allowed here */
  zf_assert_nequal(pcb->state, LISTEN);

  /* If we're already closed then just release the pcb.  Otherwise
   * send a RST first.
   */
  if( pcb->state & (SEND_STATE_MASK | FIN_WAIT_STATE_MASK) &&
      tcp->tst.path.rc == ZF_PATH_OK )
    tcp_rst(stack, &tcp->tst, zf_tx_iphdr(&tcp->tst)->daddr,
            pcb->snd_nxt + pcb->snd_delegated,
            pcb->rcv_nxt, pcb->rcv_ann_wnd, pcb->local_port, pcb->remote_port,
            false);

  tcp_pcb_release(stack, tcp);
}


/** \brief Call to shutdown TX side of a connection.
 * 
 * \param tcp
 *
 * \return 0         tx shutdown completed successfully
 *         -ENOTCONN tcp tx was not open
 *         other     failed to send FIN
 *
 * ZF
 */
int tcp_shutdown_tx(struct zf_tcp* tcp)
{
  int err = 0;
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
 
  zf_log_tcp_tx_trace(tcp, "%s: state 0x%x\n", __func__,
                      tcp->pcb.state);

  if( tcp->pcb.snd_delegated ) {
    zf_log_tcp_tx_trace(tcp, "%s: abort due to snd_delegated=%u", __func__,
                        tcp->pcb.snd_delegated);
    tcp_abort(stack, tcp);
    return 0; /* TODO would error be more appropriate? */
  }

  switch (tcp->pcb.state) {
    case ESTABLISHED:
      /* Flush any unprocessed rx packets before leaving ESTABLISHED state */
      zf_stack_tcp_rx_flush(stack);
      /*fallthrough*/
    case SYN_RCVD:
      err = tcp_send_fin(tcp);
      if (err == 0)
        tcp_do_transition(tcp, FIN_WAIT_1);
      break;
    case CLOSE_WAIT:
      err = tcp_send_fin(tcp);
      if (err == 0)
        tcp_do_transition(tcp, LAST_ACK);
      break;
    case SYN_SENT:
      /* Linux does not send RST when aborting SYN-SENT connection */
      tcp_pcb_release(stack, tcp);
      break;
    default:
      /* Has already been closed, do nothing. */
      err = -ENOTCONN;
      break;
  }

  /* Poke anything we've queued out */
  if( err == 0)
    tcp_output(tcp);

  zf_log_tcp_tx_trace(tcp, "%s: new state 0x%x, err %d\n", __func__,
                      tcp->pcb.state, err);

  return err;
}


void tcp_shutdown(struct zf_tcp* tcp)
{
  zf_stack* stack = zf_stack_from_zocket(tcp);
 
  zf_log_tcp_conn_trace(tcp, "%s: state 0x%x\n", __func__, tcp->pcb.state);

  bool rx_EOF_only = false;
  if( !zfr_queue_all_packets_read(&tcp->tsr) ) {
    uint32_t count = 2;
    iovec iov[2];
    zfr_pkts_peek(&tcp->tsr.ring, iov, &count);
    /* Check whether the only item left on receive queue is
     * zero-length EOF/RST marker.
     * We do not expect client to have necessarily read it. */
    rx_EOF_only = (count == 1 && iov[0].iov_len == 0);
  }

  int rx_count = zfr_drop_queue(&stack->pool, &tcp->tsr);

  if( rx_count && ! rx_EOF_only) {
    zf_log_tcp_conn_trace(tcp, "%s: data left on rxq\n", __func__);
    if( tcp->pcb.state != CLOSED )
      tcp_abort(stack, tcp);
    return;
  }

  if( tcp->pcb.state == TIME_WAIT || tcp->pcb.state == CLOSING ||
      tcp->pcb.state == LAST_ACK || tcp->pcb.state == CLOSED )
    return;

  tcp_shutdown_tx(tcp);
}


/** \brief Shutdown TCP listening zocket.
 *
 * \param tls
 *
 * \return -ENOTCONN  tls was already shut down
 *         0          shutdown completed successfully
 *
 * ZF
 */
int
tcp_shutdown_listen(struct zf_stack* stack, struct zf_tcp_listen_state* tls)
{
  if( tls->tls_flags & ZF_LISTEN_FLAGS_SHUTDOWN )
    return -ENOTCONN;
  tls->tls_flags |= ZF_LISTEN_FLAGS_SHUTDOWN;

  /* Drop all TCP states on the listenq for this zocket.  Onload and Linux do
   * not send resets here, so neither do we. */
  int listener_id = TCP_LISTEN_ID(stack, tls);
  for( int i = 0; i < stack->listenq.max_syn_backlog; ++i )
    if( stack->listenq.table[i].listener_id == listener_id )
      tcp_pcb_release(stack, &stack->tcp[stack->listenq.table[i].synrecv_id]);

  /* Drop all TCP states on the acceptq for this zocket. */
  while( tls->acceptq_head != ZF_ZOCKET_ID_INVALID ) {
    struct zf_tcp* tcp = &stack->tcp[tls->acceptq_head];
    tls->acceptq_head = tcp->pcb.acceptq_next;
    /* The acceptq has a zocket reference, that would have been given to the
     * application on accept, but that's not going to happen now, so we can
     * drop it.
     *
     * There is no need to drop alread-dropped CLOSED state.
     * As we've not sent FIN, the state can be CLOSED or in
     * SEND_STATE_MASK.
     */
    zf_assert_equal(! (tcp->pcb.state & SEND_STATE_MASK),
                    tcp->pcb.state == CLOSED);
    zfr_drop_queue(&stack->pool, &tcp->tsr);
    if( tcp->pcb.state != CLOSED )
      tcp_abort(stack, tcp);
    zf_tcp_release(stack, tcp);
  }

  return 0;
}



/** \brief Bind to a local address
 *
 * \param tcp
 * \param laddr The local address to bind to
 *
 * \return -EINVAL Invalid state for bind
 *         0       Bind completed successfully
 *
 * ZF
 */
int tcp_bind(struct zf_tcp* tcp, const struct sockaddr_in* laddr)
{
  if(tcp->pcb.state != CLOSED)
    return -EINVAL;

  tcp->pcb.local_port = ntohs(laddr->sin_port);

  zf_log_tcp_conn_trace(zf_stack_from_zocket(tcp),
                        "tcp_bind: bind to port %u\n", tcp->pcb.local_port);
  return 0;
}

/** \brief Update the state that tracks the available window space to advertise
 *
 * \param pcb
 *
 * \return how much extra window would be advertised if we sent an update now.
 *
 * TCP shared
 */
uint32_t tcp_update_rcv_ann_wnd(struct tcp_pcb *pcb)
{
  uint32_t new_right_edge = pcb->rd_nxt + TCP_WND;

  if( TCP_SEQ_GEQ(new_right_edge,
                  pcb->rcv_ann_right_edge + MIN( (TCP_WND/2), pcb->mss )) ) {
    /* we can advertise more window */
    pcb->rcv_ann_wnd = MAX(TCP_SEQ_SUB(new_right_edge, pcb->rcv_nxt), 0);
    return new_right_edge - pcb->rcv_ann_right_edge;
  }
  else {
    if (TCP_SEQ_GT(pcb->rcv_nxt, pcb->rcv_ann_right_edge)) {
      /* Can happen due to other end sending out of advertised window,
       * but within actual available (but not yet advertised) window */
      pcb->rcv_ann_wnd = 0;
    }
    else {
      /* keep the right edge of window constant */
      uint32_t new_rcv_ann_wnd = pcb->rcv_ann_right_edge - pcb->rcv_nxt;
      zf_assert_le(new_rcv_ann_wnd, 0xffff);
      pcb->rcv_ann_wnd = (uint16_t)new_rcv_ann_wnd;
    }
    return 0;
  }
}


/** \brief Inform TCP that RX data has been consumed
 *
 * \param tcp
 * \param len The amount of data consumed
 *
 * This function should be called by the application when it has
 * processed the data. The purpose is to advertise a larger window
 * when the data has been processed.
 *
 * ZF
 */
void tcp_recved(struct zf_tcp* tcp, int len)
{
  int wnd_inflation;
  struct tcp_pcb* pcb = &tcp->pcb;

  /* pcb->state LISTEN not allowed here */
  zf_assert_nequal(pcb->state, LISTEN);

  /* In a simpler world, we would assert here that we are not expanding the
   * receive window to a size larger than we advertised originally (i.e.
   * TCP_WND).  However, this need not be the case, as we accept partially out-
   * of-window segments.  This can result in up to (MSS - 1) bytes more than
   * we would otherwise expect. */
  zf_assert_lt((uint32_t)TCP_SEQ_SUB(pcb->rcv_nxt, pcb->rd_nxt),
               (uint32_t)(TCP_WND + pcb->mss));
  pcb->rd_nxt += len;
  zf_assert_ge(TCP_SEQ_SUB(pcb->rcv_nxt, pcb->rd_nxt), 0);

  wnd_inflation = tcp_update_rcv_ann_wnd(pcb);

  /* If the change in the right edge of window is significant (default
   * watermark is TCP_WND/4), then send an explicit update now.
   * Otherwise wait for a packet to be sent in the normal course of
   * events (or more window to be available later)
   */
  if (wnd_inflation >= TCP_WND_UPDATE_THRESHOLD) {
    pcb->flags |= TF_ACK_NOW;
    tcp_output(tcp);
  }

  zf_log_tcp_rx_trace(tcp, "tcp_recved: received %u bytes, wnd %u (%d).\n",
                      len, TCP_WND, pcb->rcv_nxt + TCP_WND - pcb->rd_nxt);
}


/* Limit the mss to TCP_MAX_MSS/TCP_MIN_MSS and prevent div by zero */
uint16_t tcp_mss_restrict(uint16_t mss)
{
  if( mss < TCP_MIN_MSS )
    return TCP_MIN_MSS;
  if( mss > TCP_MAX_MSS )
    return TCP_MAX_MSS;
  return mss;
}

/* Convert IP MTU to TCP MSS */
uint16_t tcp_mtu2mss(uint16_t mtu)
{
  return tcp_mss_restrict(mtu - sizeof(struct iphdr) - sizeof(struct tcphdr));
}

/** \brief Connects to another host.
 *
 * \param tcp
 * \param raddr Address of peer to connect to
 *
 * \return -EINVAL if invalid arguments are given
 *         0 if connect request has been sent
 *         other if connect request couldn't be sent
 *
 * ZF
 */
int tcp_connect(struct zf_tcp* tcp, const struct sockaddr_in* raddr)
{
  int ret;

  if(tcp->pcb.state != CLOSED)
    return -EISCONN;

  zf_log_tcp_conn_trace(zf_stack_from_zocket(tcp),
                        "tcp_connect to port %u\n", ntohs(raddr->sin_port));

  if(!raddr)
    return -EINVAL;

  tcp->pcb.remote_port = ntohs(raddr->sin_port);

  /* Send a SYN together with the MSS option. */
  ret = tcp_enqueue_flags(tcp, 1, 0, 0);
  if (ret == 0) {
    /* SYN segment was enqueued, changed the pcbs state now */
    tcp_do_transition(tcp, SYN_SENT);
    /* We become ready to queue data now, use minimal mss. */
    tcp_output(tcp);

    tcp_fix_fast_send_length(&tcp->pcb);
    zf_tcp_timers_restart(tcp);
  }
  return ret;
}


/** \brief Initialise the TCP protocol state
 *
 * \param tcp The structure to initialise
 *
 * This function must be called before this pcb is used by TCP.  It initialises
 * the TCP state to CLOSED.
 *
 * ZF
 */
void tcp_init(struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;

  memset(pcb, 0, sizeof(struct tcp_pcb));
  pcb->state = CLOSED;
#ifndef NDEBUG
  pcb->mediated_state = CLOSED;
#endif
  /* We're only allowed to send a SYN to start with. */
  pcb->rcv_nxt = 0;
  pcb->rcv_ann_wnd = TCP_WND;
  pcb->rcv_ann_right_edge = pcb->rcv_nxt + pcb->rcv_ann_wnd;
  pcb->mss = TCP_MIN_MSS;
  pcb->mss_lim = TCP_MIN_MSS;
  pcb->snd_buf = TCP_SND_QUEUELEN * TCP_MIN_MSS;
  pcb->sv = TCP_INITIAL_RTO / TCP_TMR_INTERVAL;
  pcb->cwnd = 1;
  pcb->snd_iss = tcp_next_iss();
  pcb->snd_wl2 = pcb->snd_iss;
  pcb->snd_nxt = pcb->snd_iss;
  pcb->snd_lbb = pcb->snd_iss;
  pcb->lastack = pcb->snd_iss;

  /* This is here as the only user of snd_iss is the TCP timestamp
   * report generation, and we don't want to count the SYN in those
   * reported bytes.  By making the state self-inconsistent here, we
   * avoid having to subtract 1 each time we report a timestamp */
  ++pcb->snd_iss;

  pcb->snd_right_edge = pcb->lastack + TCP_WND;
  pcb->snd_wnd_max = TCP_WND;
  pcb->ssthresh = ZF_TCP_INITIAL_SSTHRESH(pcb);
  pcb->parent_listener = ZF_ZOCKET_ID_INVALID;
  pcb->listenq_index = ZF_LISTENQ_INDEX_INVALID;
  pcb->flags = TF_ON;
  /* Default to ACKing an incoming segment iff the TF_ACK_NEXT bit is set on
   * the PCB. */
  pcb->flags_ack_delay = TF_ACK_NEXT;
  ci_dllist_init(&pcb->ooo_pkts);
  pcb->fast_pkt = PKT_INVALID;

  /* NB all other fields are set to zero by memset above */
}


/** \brief Purges a TCP PCB.
 *
 * \param tcp
 *
 * Removes any buffered data and frees the buffer memory
 *
 * TCP core internal
 */
void tcp_pcb_purge(struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  struct zf_stack* stack = zf_stack_from_zocket(tcp);

  zf_tcp_timers_stop(tcp);

  if (pcb->state != CLOSED && pcb->state != TIME_WAIT && pcb->state != LISTEN) {
    ci_dllist* ooo_list = &pcb->ooo_pkts;
    struct tcp_ooo_pkt* list_pkt;
    struct tcp_ooo_pkt* next_list_pkt;

    zf_log_tcp_conn_trace(tcp, "%s\n", __func__);

    /* Stop the retransmission timer as it will expect data on unacked
       queue if it fires */
    zf_tcp_timers_timer_stop(tcp, ZF_TCP_TIMER_RTO);

    tcp_free_sendq(stack, &pcb->sendq);

    CI_DLLIST_FOR_EACH3(struct tcp_ooo_pkt, list_pkt, ooo_pkt_link, ooo_list,
                        next_list_pkt) {
      zf_pool_free_pkt(&stack->pool,
                       PKT_BUF_ID_FROM_PTR(&stack->pool,
                                           (char*) list_pkt->pkt.iov_base));
      ci_dllist_remove(&list_pkt->ooo_pkt_link);
      free(list_pkt);
      ++pcb->ooo_removed;
    }
  }
}


/* releases rx table entry with associated backing socket */
void
tcp_rx_table_entry_free(struct zf_stack* stack, struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;

  /* Remove filters and RX-table entries. */
  struct sockaddr_in laddr = {
    AF_INET,
    htons(tcp->pcb.local_port),
    { zf_tx_iphdr(&tcp->tst)->saddr },
  };
  struct sockaddr_in raddr = {
    AF_INET,
    htons(tcp->pcb.remote_port),
    { zf_tx_iphdr(&tcp->tst)->daddr },
  };

  int rc;
  rc = zfrr_remove(stack, zf_stack_get_rx_table(stack, ZF_STACK_RX_TABLE_TCP),
                   0 /* nic */, &laddr, &raddr);

  /* We have two scenarios for SYN_RCVD state:
   * 1) Socket is fully initialized to SYN_RCVD state.
   *    In this case we have to remove RX-table entries.
   * 2) We call tcp_abort() before tcp_passive_rx_init().
   *    There are no RX-table entries. */
  if( rc == -ENOENT && pcb->state == SYN_RCVD )
    return;

  zf_assert_equal(rc, 0);
}


/** \brief Purges the PCB and releases the state machine's ref to the zf_tcp
 *
 * \param tcp The zf_tcp to release
 *
 * The PCB is left in a valid and consistent state, as although the state
 * machine no longer cares about this, we may still be asked to use it if the
 * application still has its reference.
 *
 * TCP
 */
void
tcp_pcb_release(struct zf_stack* stack, struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;

  zf_log_tcp_conn_trace(tcp, "%s\n", __FUNCTION__);

  /* if there is an outstanding delayed ACK, send it */
  zf_assume_impl(pcb->flags & TF_ACK_NEXT, pcb->flags & TF_ACK_DELAY);
  if( pcb->state != TIME_WAIT && pcb->state != LISTEN &&
      pcb->flags & TF_ACK_DELAY) {
     pcb->flags |= TF_ACK_NOW;
    tcp_output(tcp);
  }

  tcp_pcb_purge(tcp);
  zf_tcp_timers_stop_all(tcp);

  zf_assert(!tcp_has_unsent(&pcb->sendq));
  zf_assert(!tcp_has_unacked(&pcb->sendq));

  if( pcb->state == SYN_RCVD &&
      pcb->listenq_index != ZF_LISTENQ_INDEX_INVALID )
    zftl_listenq_free_entry(&stack->listenq, pcb->listenq_index);

  /* For passive-open zockets, release the reference that they hold to their
   * parent listening zockets. */
  if( tcp->pcb.parent_listener != ZF_ZOCKET_ID_INVALID ) {
    struct zf_tcp_listen_state* tls;
    tls = &stack->tcp_listen[tcp->pcb.parent_listener];
    zftl_release(stack, tls);
  }

  tcp_rx_table_entry_free(stack, tcp);

  if( pcb->fast_pkt != PKT_INVALID ) {
    zf_pool_free_pkt(&stack->pool, pcb->fast_pkt);
    pcb->fast_pkt = PKT_INVALID;
  }

  tcp_do_transition(tcp, CLOSED);
  zf_tcp_release(stack, tcp);
}


void
tcp_free_segs(zf_stack* st, tcp_send_queue* sendq, tcp_send_queue::idx begin,
              tcp_send_queue::idx end)
{
  for( auto i = begin; i != end; i = (i + 1) & TCP_SND_QUEUE_IDX_MASK )
    tcp_seg_free(&st->pool, tcp_seg_at(sendq, i));
}


void
tcp_free_sendq(zf_stack* st, tcp_send_queue* sendq)
{
  tcp_free_segs(st, sendq, sendq->begin, sendq->end);
  sendq->begin = sendq->middle = sendq->end;
}


void
tcp_timewait_timeout(struct zf_stack* st, struct zf_tcp* tcp)
{
  tcp_pcb_release(st, tcp);
}


void
tcp_finwait_timeout(struct zf_stack* st, struct zf_tcp* tcp)
{
  /* in FIN_WAIT_1 or CLOSING state when fin timeout occurs we might still
   * have some data to send, drop it */
  if( tcp->pcb.state & (FIN_WAIT_1 | CLOSING) )
    tcp_free_sendq(st, &tcp->pcb.sendq);
  tcp_pcb_release(st, tcp);
}


ZF_HOT pkt_id tcp_seg_pkt(struct tcp_seg* seg)
{
  return PKT_BUF_ID(&zf_stack_from_zocket(seg)->pool, seg->iov.iov_base);
}


void tcp_dump_sendq(struct tcp_send_queue* sendq)
{
  zf_dump("  snd: send=%u inflight=%u\n",
          sendq->end-sendq->begin, sendq->middle-sendq->begin);
  zf_dump("  snd: qbegin=%u qmiddle=%u qend=%u\n",
          sendq->begin, sendq->middle, sendq->end);
}


void
tcp_dump(struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  zf_dump("  tcp: flags=%x flags_ack_delay=%x error=%d\n",
          pcb->flags, pcb->flags_ack_delay, pcb->error);
  zf_dump("  tcp: parent=%d refcount=%d\n",
          pcb->parent_listener, tcp->refcount);
  zf_dump("  snd: snd_nxt=%u lastack=%u wnd=%u snd_wnd_max=%u\n",
          pcb->snd_nxt, pcb->lastack,
          TCP_SEQ_SUB(pcb->rd_nxt + TCP_WND, pcb->rcv_nxt), pcb->snd_wnd_max);
  zf_dump("  snd: snd_wl1=%u snd_wl2=%u snd_lbb=%u snd_right_edge=%u\n",
          pcb->snd_wl1, pcb->snd_wl1, pcb->snd_lbb, pcb->snd_right_edge);
  zf_dump("  snd: delegated=%u", pcb->snd_delegated);
  tcp_dump_sendq(&pcb->sendq);
  zf_dump("  snd: sndbuf=%u cwnd=%u ssthresh=%u mss_lim=%u\n",
          pcb->snd_buf, pcb->cwnd, pcb->ssthresh, pcb->mss_lim);
  zf_dump("  rcv: rcv_nxt=%u rcv_ann_wnd=%u rcv_ann_right_edge=%u\n",
          pcb->rcv_nxt, pcb->rcv_ann_wnd, pcb->rcv_ann_right_edge);
  zf_dump("  rcv: mss=%u\n",
          pcb->mss);
  zf_dump("  rtt: est=%u seq=%u sa=%d sv=%d\n",
          pcb->rttest, pcb->rtseq, pcb->sa, pcb->sv);
  zf_dump("  cong: nrtx=%u dupacks=%u persist_backoff=%u\n",
          pcb->nrtx, pcb->dupacks, pcb->persist_backoff);
  zf_dump("  timers: %s%s%s%s\n",
          pcb->timers.running & (1<<ZF_TCP_TIMER_RTO) ? "RTO " : "",
          pcb->timers.running & (1<<ZF_TCP_TIMER_DACK) ? "DACK " : "",
          pcb->timers.running & (1<<ZF_TCP_TIMER_ZWIN) ? "ZWIN " : "",
          pcb->timers.running & (1<<ZF_TCP_TIMER_TIMEWAIT) ? "TIMEWAIT " : "");
  zf_dump("  ooo: added=%u removed=%u replaced=%u\n", pcb->ooo_added,
          pcb->ooo_removed, pcb->ooo_replaced);
  zf_dump("  ooo: handling_deferred=%u dropped_nomem=%u drop_overfilled=%u\n",
          pcb->ooo_handling_deferred, pcb->ooo_dropped_nomem,
          pcb->ooo_drop_overfilled);
  zf_dump("  stats: msg_more_send_delayed=%d send_nomem=%d\n",
          pcb->stats.msg_more_send_delayed, pcb->stats.send_nomem);
}

#ifdef ZF_DEVEL
#define TCP_FLAGS_TO_STR(hdr) (({ \
    struct { \
      char buf[7]; \
    } buf; \
    sprintf(buf.buf, "%s%s%s%s%s%s", \
            hdr->fin?"F":"", hdr->syn?"S":"", hdr->rst?"R":"", \
            hdr->psh?"P":"", hdr->ack?"A":"", hdr->urg?"U":""); \
    buf; \
  }).buf)

void tcp_dump_sendpkt_hdr(zf_stack* stack, struct tcphdr* hdr, unsigned len)
{
  len -= sizeof(tcphdr);
  zf_dump(" pkt%4d seq %10u-%10u(%4d) ack %10u flags %s win %5u\n",
          PKT_BUF_ID(&stack->pool, hdr),
          htonl(hdr->seq), htonl(hdr->seq) + len, len, htonl(hdr->ack_seq),
          TCP_FLAGS_TO_STR(hdr), htons(hdr->window));
}

void tcp_dump_recvpkt_hdr(zf_stack* stack, struct tcphdr* hdr, unsigned len)
{
  zf_dump(" pkt%4d seq %10u-%10u(%4d) ack %10u flags %s win %5u\n",
          PKT_BUF_ID(&stack->pool, hdr),
          htonl(hdr->seq), htonl(hdr->seq) + len, len, htonl(hdr->ack_seq),
          TCP_FLAGS_TO_STR(hdr), htons(hdr->window));
}

static inline struct tcphdr*
zfr_find_recv_tcphdr(struct zf_stack* stack, char* ptr)
{
  unsigned rx_prefix_len = stack->nic[0].rx_prefix_len;

  char* packet = zf_packet_buffer_start(&stack->pool, ptr);
  char* ethhdr = packet + rx_prefix_len;
  char* iphdr = (char*)zf_ip_hdr(ethhdr);
  char* tcphdr = iphdr + ((struct iphdr *)iphdr)->ihl * 4;
  return (struct tcphdr*) tcphdr;
}

void tcp_dump_recvq(struct zf_rx_ring* ring) {
  zf_stack* stack = zf_stack_from_zocket(ring);
  auto start = zfr_tcp_queue_first_packet(ring);
  auto end = ring->end;
  for( auto i = start; i != end; ++i ) {
    iovec iov = ring->pkts[i % SW_RECVQ_MAX];
    auto tcphdr = zfr_find_recv_tcphdr(stack, (char*)iov.iov_base);
    tcp_dump_recvpkt_hdr(stack, tcphdr, iov.iov_len);
  }
}
void tcp_dump_sendq_pkts(struct tcp_send_queue* sendq)
{
  struct zf_stack* stack = zf_stack_from_zocket(sendq);
  for( int i = sendq->begin; i != sendq->end; ++i ) {
    iovec iov = tcp_seg_at(sendq,i)->iov;
    tcp_dump_sendpkt_hdr(stack, (tcphdr*) iov.iov_base, iov.iov_len);
  }
}

void tcp_dump_oooq(tcp_pcb* pcb)
{
  zf_stack* stack = zf_stack_from_zocket(pcb);
  ci_dllist* ooo_list = &pcb->ooo_pkts;
  struct tcp_ooo_pkt* list_pkt;
  struct tcp_ooo_pkt* next_list_pkt;
  CI_DLLIST_FOR_EACH3(struct tcp_ooo_pkt, list_pkt, ooo_pkt_link, ooo_list,
                      next_list_pkt) {
    iovec iov = list_pkt->pkt;
    auto tcphdr = zfr_find_recv_tcphdr(stack, (char*)iov.iov_base);
    tcp_dump_recvpkt_hdr(stack, tcphdr, iov.iov_len);
  }
}

/* Meant for use with gdb */
extern void tcp_dump_pkts(struct zf_tcp* tcp);
void tcp_dump_pkts(struct zf_tcp* tcp)
{
  tcp_dump(tcp);
  zf_dump(" sendq:\n");
  tcp_dump_sendq_pkts(&tcp->pcb.sendq);
  zf_dump(" recvq:\n");
  tcp_dump_recvq(&tcp->tsr.ring);
  zf_dump(" oooq:\n");
  tcp_dump_oooq(&tcp->pcb);
}
#endif
