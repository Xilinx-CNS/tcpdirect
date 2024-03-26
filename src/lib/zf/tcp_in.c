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

#include <zf_internal/zf_tcp.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/rx.h>
#include <zf_internal/tcp_opt.h>
#include <zf_internal/tcp.h>
#include <zf_internal/tcp_rx.h>
#include <zf_internal/tcp_tx.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/zf_tcp_timers.h>
#include <zf_internal/stack_params.h>
#include <zf_internal/zf_tcp_timers.h>
#include <zf_internal/cplane.h>

#include <zf_internal/private/zf_stack_rx.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


/* Forward declarations. */
static void tcp_receive(struct zf_tcp* tcp, struct tcp_seg* seg,
                        uint8_t* recv_flags);
static void tcp_parseopt(struct tcp_pcb *pcb, const struct tcphdr* tcp_hdr);
static void tcp_receive_timewait(struct zf_tcp* tcp, struct tcp_seg* seg,
                                 uint8_t* recv_flags);

ZF_HOT static inline void
tcp_handle_ack_new(struct zf_tcp* tcp, struct tcphdr* tcp_hdr);
static inline void
tcp_handle_ack_common(struct zf_tcp* tcp, struct tcphdr* tcp_hdr);


static int tcp_queue_ooo_pkt(struct zf_tcp* tcp, struct tcp_seg* seg)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  ci_dllist* ooo_list = &pcb->ooo_pkts;
  struct tcp_ooo_pkt* ooo_pkt;
  struct tcp_ooo_pkt* list_pkt;
  struct tcp_ooo_pkt* prev_list_pkt;
  struct tcphdr* ooo_tcp_hdr = (struct tcphdr*) seg->iov.iov_base;
  size_t ooo_payload_len = seg->iov.iov_len - (4 * ooo_tcp_hdr->doff);
  uint32_t ooo_seq = ntohl(ooo_tcp_hdr->seq);

  ooo_pkt = (struct tcp_ooo_pkt*) malloc(sizeof(struct tcp_ooo_pkt));
  if( ooo_pkt == NULL ) {
    zf_log_tcp_rx_trace(tcp, "%s: memory allocation failure, dropping seq %u ",
                        __func__, ooo_seq);
    ++pcb->ooo_dropped_nomem;
    return 0;
  }

  memcpy(&ooo_pkt->pkt, &seg->iov, sizeof(struct iovec));

  /* Packets in pcb->ooo_pkts are ordered by sequence number, so check the
   * list in reverse as the latest packet will most likely go at the end.
   */
  CI_DLLIST_FOR_EACH_REV3(struct tcp_ooo_pkt, list_pkt, ooo_pkt_link,
                          ooo_list, prev_list_pkt) {
    struct tcphdr* list_tcp_hdr = (struct tcphdr*) list_pkt->pkt.iov_base;
    uint32_t list_seq = ntohl(list_tcp_hdr->seq);
    size_t list_payload_len = list_pkt->pkt.iov_len - (4 * list_tcp_hdr->doff);

    if( TCP_SEQ_LEQ(ooo_seq, list_seq) ) {
      /* Incoming packet goes before current list item */
      if( TCP_SEQ_GT(ooo_seq + ooo_payload_len, list_seq) ) {
        /* Incoming packet overlaps the current list item */
        if( TCP_SEQ_GEQ(ooo_seq + ooo_payload_len,
                       list_seq + list_payload_len) ) {
          /* Incoming packet completely covers current list item, so drop
           * current packet from list.  An identical segment will be replaced.
           */
          struct zf_stack* stack = zf_stack_from_zocket(tcp);

          zf_pool_free_pkt(&stack->pool,
                           PKT_BUF_ID_FROM_PTR(&stack->pool,
                                               (char*) list_pkt->pkt.iov_base));
          ci_dllist_remove(&list_pkt->ooo_pkt_link);
          free(list_pkt);
          ++pcb->ooo_removed;
          ++pcb->ooo_replaced;
          zf_log_tcp_rx_trace(tcp, "%s: seq %u(%u) %u(%u) dropped and replaced in queue\n",
                              __func__, list_seq, list_payload_len, ooo_seq, ooo_payload_len);
        }
        else {
          uint32_t delta = TCP_SEQ_SUB(ooo_seq + ooo_payload_len, list_seq);

          zf_log_tcp_rx_trace(tcp, "%s: seq %u(%u) reducing by %u\n",
                              __func__, ooo_seq, ooo_payload_len, delta);
          ooo_pkt->pkt.iov_len -= delta;
          ooo_payload_len -= delta;
          if( ooo_payload_len == 0 ) {
            free(ooo_pkt);
            return 0;
          }
        }
      }
      continue;
    }

    if( TCP_SEQ_LT(ooo_seq, list_seq + list_payload_len) )
      /* Head of new packet overlaps the tail of the existing packet, so
       * shorten the existing one.
       */
      list_pkt->pkt.iov_len -= list_seq + list_payload_len - ooo_seq;

    ci_dllist_insert_after(&list_pkt->ooo_pkt_link, &ooo_pkt->ooo_pkt_link);
    goto ooo_added;
  }

  /* Either the list is empty or the new packet goes before all others, so
   * push the packet to the beginning of the list.
   */
  ci_dllist_push(ooo_list, &ooo_pkt->ooo_pkt_link);

 ooo_added:
  ++pcb->ooo_added;
  zf_log_tcp_rx_trace(tcp, "%s: seq %u added to queue: added %u removed %u\n",
                      __func__, ooo_seq, pcb->ooo_added, pcb->ooo_removed);

  /* We should limit the ooo buffer somehow, or it can consume all packet
   * buffers.  */
  while( pcb->ooo_added - pcb->ooo_removed > SW_RECVQ_MAX ) {
    ooo_pkt = CI_CONTAINER(struct tcp_ooo_pkt, ooo_pkt_link,
                           ci_dllist_pop_tail(ooo_list));
    zf_log_tcp_rx_trace(tcp, "%s: drop the last packet from ooo seq %u\n",
                        __func__,
                        ((struct tcphdr*)(ooo_pkt->pkt.iov_base))->seq);
    struct zf_stack* stack = zf_stack_from_zocket(tcp);
    zf_pool_free_pkt(&stack->pool,
                     PKT_BUF_ID_FROM_PTR(&stack->pool,
                                         (char*) ooo_pkt->pkt.iov_base));
    free(ooo_pkt);
    ++pcb->ooo_removed;
    ++pcb->ooo_drop_overfilled;
  }
  return 1;
}


int tcp_handle_ooo_pkts(struct zf_stack* stack, struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  ci_dllist* ooo_list = &pcb->ooo_pkts;
  struct tcp_ooo_pkt* list_pkt;
  struct tcp_ooo_pkt* next_list_pkt;
  int event_occurred = 0;

  /* all pkts in rcv queue are assumed to have been processed
   * otherwise zfr_zc_process_done() below would free wrong pkts */
  zf_assert(zfr_queue_all_packets_processed(&tcp->tsr));

  CI_DLLIST_FOR_EACH3(struct tcp_ooo_pkt, list_pkt, ooo_pkt_link, ooo_list,
                      next_list_pkt) {
    struct tcphdr* list_tcp_hdr = (struct tcphdr*) list_pkt->pkt.iov_base;
    uint32_t list_seq = ntohl(list_tcp_hdr->seq);
    struct iovec recv_data;
    /* TCP headers were byte-swapped when the packet was first received. */
    size_t tcp_hdr_len = 4 * list_tcp_hdr->doff;
    size_t payload_len = list_pkt->pkt.iov_len - tcp_hdr_len;

    /* In the diagrams below, packets labelled "out-of-order" were so when they
     * were received, but might now be able to be handled. */

    if( TCP_SEQ_LT(pcb->rcv_nxt, list_seq ) ) {
      /* In-order:     ---------------
       * Out-of-order:                             --------------
       * We haven't yet received segments to fill the gap to the next OOO
       * packet.  Stop processing the list. */
      break;
    }
    else if( TCP_SEQ_LT(pcb->rcv_nxt, list_seq + payload_len) ) {
      /* We didn't take the branch above, so we have caught up with the current
       * OOO packet.  Either
       *
       * In-order:     ---------------
       * Out-of-order:                -----------
       *
       * or
       *
       * In-order:     ---------------
       * Out-of-order:            ---------------
       *
       * This OOO packet contains at least some in-order data. */

      if( ! zfr_tcp_queue_has_space(&tcp->tsr.ring) &&
          zfr_queue_all_packets_processed(&tcp->tsr) ){
        zfr_queue_coalesce(&tcp->tsr, stack);
      }

      if( ! zfr_tcp_queue_has_space(&tcp->tsr.ring) ) {
        tcp->tcp_state_flags |= ZF_TCP_STATE_FLAGS_DEFER_OOO;
        ++pcb->ooo_handling_deferred;
        zf_log_tcp_rx_trace(tcp, "%s: deferring the handling of seq %u\n",
                            __func__, list_seq);
        break;
      }

      int overlap = TCP_SEQ_SUB(pcb->rcv_nxt, list_seq);
      zf_assert_ge(overlap, 0);
      payload_len -= overlap;
      recv_data.iov_base = (char*) list_tcp_hdr + tcp_hdr_len + overlap;
      recv_data.iov_len = payload_len;

      /* Pkt partially beyond the window are allowed */
      zf_assert_ge(TCP_SEQ_SUB(pcb->rcv_nxt, pcb->rd_nxt), 0);

      pcb->rcv_nxt += payload_len;
      zf_assert_lt((uint32_t)TCP_SEQ_SUB(pcb->rcv_nxt, pcb->rd_nxt),
                   (uint32_t)(TCP_WND + pcb->mss));

      zfr_pkt_queue(&tcp->tsr.ring, &recv_data);
      zf_log_tcp_rx_trace(tcp, "%s: seq %u processed from OOO queue\n",
                          __func__, list_seq);
      ++event_occurred;
    }
    else {
      /* In-order:     ---------------------------
       * Out-of-order:                ------------
       *
       * We've already (re-)received all of the data in the OOO packet, so we
       * need only drop the segment. */
      zf_pool_free_pkts(&stack->pool, &list_pkt->pkt, 1);
    }

    ci_dllist_remove(&list_pkt->ooo_pkt_link);
    free(list_pkt);
    ++pcb->ooo_removed;
  }

  if( event_occurred ) {
    zf_muxer_mark_waitable_ready(&tcp->w, EPOLLIN);
    zfr_zc_process_done(&stack->pool, &tcp->tsr, event_occurred);
  }

  zf_assert(zfr_queue_all_packets_processed(&tcp->tsr));

  return event_occurred != 0;
}


/* Adds a segment to the RX queue. */
static inline void
tcp_queue_rx(struct zf_stack* stack, struct zf_tcp* tcp, struct iovec* data)
{
  zf_assert(zfr_tcp_queue_has_space(&tcp->tsr.ring));
  zfr_pkt_queue(&tcp->tsr.ring, data);

  zf_muxer_mark_waitable_ready(&tcp->w, EPOLLIN);
}


void tcp_queue_append_EOF_marker(zf_stack* stack, zf_tcp* tcp)
{
  /* This function uses a pre-allocated packet so it doesn't have to
   * cope with failure to allocate.  We could potentially do without
   * the packet at all and set the iov_base to NULL.  To achieve this
   * we would need more sophisticated free of the queue in
   * zfr_drop_queue() to spot the EOF marker and handle it
   * appropriately rather than just pass into zfr_zc_read_done()
   */

  /* We mustn't call this function after the zocket has been closed, or else
   * we'll leak the EOF packet. */
  zf_assert(! tcp_is_orphan(tcp));

  /* Tempting to just assert this isn't true, but as this can be
   * called as the result of receiving a RST, this seems more robust
   */
  if( tcp->eof_pkt == PKT_INVALID ) { tcp->tcp_state_flags &=
     ~ZF_TCP_STATE_FLAGS_DEFER_EOF; return; }

  /* TODO: Ideally we have appended not a real packt buffer but
   * a vector of NULL/0 */

  struct iovec iov = {
    .iov_base = PKT_BUF_BY_ID(&stack->pool, tcp->eof_pkt),
    .iov_len = 0
  };

  /* Try coalescing if necessary. */
  if( ! zfr_tcp_queue_has_space(&tcp->tsr.ring) &&
      zfr_queue_all_packets_processed(&tcp->tsr) )
    zfr_queue_coalesce(&tcp->tsr, stack);

  /* This might have failed if there's a ZC-receive in progress, so check
   * again for space, and if we haven't got any, try again after the
   * ZC-receive is finished. */
  if( zfr_tcp_queue_has_space(&tcp->tsr.ring) ) {
    tcp_queue_rx(stack, tcp, &iov);
    tcp->tcp_state_flags &= ~ZF_TCP_STATE_FLAGS_DEFER_EOF;
    tcp->eof_pkt = PKT_INVALID;
  }
  else
    tcp->tcp_state_flags |= ZF_TCP_STATE_FLAGS_DEFER_EOF;
}


/* Complete packet processing by checking the return code and recv_flags
 * from earlier packet handling and then take any necessary actions, such
 * as passing data to the upper layer and sending out any required packets. */
int tcp_post_process(struct zf_stack* stack, struct zf_tcp* tcp,
                     struct tcp_seg* seg, char* payload, uint8_t recv_flags)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  int event_occurred = 0;

  /* We only release our reference to the zf_tcp once we've finished
   * processing.  We're going to fiddle with it below, so we should still have
   * at least our ref.
   */
  zf_assert_gt(tcp->refcount, 0);

  /* all pkts in rcv queue are assumed to have been processed,
   * therefore calling zfr_queue_mark_processed() below will only
   * affect the new incoming packet buffer */
  zf_assert(zfr_queue_all_packets_processed(&tcp->tsr));

  if (recv_flags & (TF_RESET | TF_ABORT) ) {
    /* TF_RESET means that the connection was reset by the other end.  TF_ABORT
     * means that we should reset it ourselves. */
    zf_muxer_mark_waitable_ready(&tcp->w, EPOLLERR);
    if( pcb->state == CLOSE_WAIT )
      pcb->error = EPIPE;
    else if (pcb->state == SYN_SENT )
      pcb->error = ECONNREFUSED;
    else
      pcb->error = ECONNRESET;
    if( ! tcp_is_orphan(tcp) ) {
      /* client has still got a reference */

      /* We're about to purge the PCB via tcp_pcb_release(), but the
       * EOF marker will survive on the zf_tcp.  As the PCB is purged,
       * no possiblity for OOO data, so always enqueue the EOF
       */
      tcp_queue_append_EOF_marker(stack, tcp);
      zfr_queue_mark_processed(&tcp->tsr);
      event_occurred = 1;
    }
    /* This must be last - PCB and zf_tcp could both disappear here */
    if( recv_flags & TF_ABORT )
      tcp_abort(stack, tcp);
    else
      tcp_pcb_release(stack, tcp);
  }
  else if (recv_flags & TF_CLOSED) {
    /* The connection has been closed and we will release the state machine's
     * reference to this zf_tcp.
     */
    zf_assert_nflags(pcb->state, SEND_STATE_MASK);
    /* No need to queue EOF marker - this state is only reached as
     * transition from LAST_ACK -> CLOSED and so we must have already
     * received the FIN and queued EOF marker below.  Assert that this
     * is the case. */
    zf_assert((tcp->tcp_state_flags & ZF_TCP_STATE_FLAGS_DEFER_EOF) ||
              (tcp->eof_pkt == PKT_INVALID));
    /* This must be last - PCB and zf_tcp could both disappear here */
    tcp_pcb_release(stack, tcp);
  }
  else {
    /* If we handled ACKs or entered ESTABLISHED, we might need to raise an
     * EPOLLOUT edge. */
    event_occurred = tcp_maybe_raise_epollout_edge(tcp);

    if (recv_flags & TF_ACCEPTQ &&
        pcb->parent_listener != ZF_ZOCKET_ID_INVALID) {
      /* This connection was pushed on to its parent-listener's acceptq.
       * Mark the listening zocket as ready. */
      struct zf_tcp_listen_state* tls;
      tls = &stack->tcp_listen[pcb->parent_listener];
      event_occurred = 1;
      zf_muxer_mark_waitable_ready(&tls->w, EPOLLIN);
    }

    /* The seg->iov.iov_base pointer is cleared in tcp_receive() if there
     * is a payload to deliver, as this ensures that the packet is not
     * freed while the application needs to access it. */
    if( seg->iov.iov_base == NULL && seg->len ) {
      /* Notify application that data has been received. */
      struct iovec recv_data;

      recv_data.iov_base = payload;
      recv_data.iov_len = seg->len;

      tcp_queue_rx(stack, tcp, &recv_data);

      /* we'd mark the packet as processed below, however we do it also here
       * for sake of tcp_queue_append_EOF_marker calling zfr_queue_coalesce */
      zfr_queue_mark_processed(&tcp->tsr);
      event_occurred = 1;
    }
    else if( (recv_flags & TF_OOO) && tcp_queue_ooo_pkt(tcp, seg) ) {
      /* Queued as OOO so clear iov_base to avoid freeing packet buffer. */
      seg->iov.iov_base = NULL;
    }

    /* If a FIN segment was received and the zocket hasn't been closed, we
     * append a zero-length buffer to the recvq to indicate EOF. */
    if( (recv_flags & TF_GOT_FIN) && ! tcp_is_orphan(tcp) ) {
      /* Notify application that data has been received by passing an
       * empty buffer.
       */
      /* pcb->ooo state only valid when not CLOSED */
      zf_assert_nequal(pcb->state, CLOSED);
      if( pcb->ooo_added == pcb->ooo_removed )
        tcp_queue_append_EOF_marker(stack, tcp);
      else
        tcp->tcp_state_flags |= ZF_TCP_STATE_FLAGS_DEFER_EOF;
      event_occurred = 1;
    }

    /* the pkt is processed, we can mark it so,
     * it is unread so no need to free */
    zfr_queue_mark_processed(&tcp->tsr);

    event_occurred |= tcp_rx_common_tail(stack, tcp);
  }
  return event_occurred;
}


/* Initialises the software RX state for a newly-created passive-open TCP
 * state. */
static void
tcp_passive_rx_init(struct zf_stack* stack,
                    struct zf_tcp* new_tcp,
                    const struct zf_tcp_listen_state* tls)
{
  struct zf_rx_res* new_tcp_res;
  struct sockaddr_in raddr = {
    .sin_family = AF_INET,
    .sin_port = htons(new_tcp->pcb.remote_port),
    .sin_addr = { .s_addr = zf_tx_iphdr(&new_tcp->tst)->daddr }
  };
  new_tcp->laddr = tls->laddr;
  new_tcp->raddr = raddr;
  zf_stack_tcp_to_res(stack, new_tcp, &new_tcp_res);
  zfrr_add(stack, new_tcp_res, TCP_ID(stack, new_tcp), ZFRR_ALL_NICS,
           IPPROTO_TCP, zf_stack_get_rx_table(stack, ZF_STACK_RX_TABLE_TCP),
           stack->rx_table[ZF_STACK_RX_TABLE_TCP], &new_tcp->laddr,
           &new_tcp->raddr, 0);
}

static void
tcp_passive_get_path(struct zf_stack* stack,
                     const struct ethhdr* eth_hdr,
                     const struct iphdr* ip_hdr,
                     const struct tcphdr* tcp_hdr,
                     struct zf_path* path)
{
  /* note that we have an incoming packet here; we need to swap the
   * addresses to find the returning path */
  zf_path_init(path, ip_hdr->saddr, ip_hdr->daddr);
  if( zf_cplane_get_path(stack, path, false/*!wait*/) == ZF_PATH_OK )
    return;

  struct in_addr laddr;
  struct in_addr raddr;
  laddr.s_addr = ip_hdr->daddr;
  raddr.s_addr = ip_hdr->saddr;
  (void) laddr;
  (void) raddr;
  /* cplane does not know about this.  We'll send our reply back.
   * If this is not correct, the client will re-send his SYN and
   * we hope to have the correct MAC at this time. */
  zf_log_tcp_rx_trace(stack, "Can not resolve MAC for incoming connection "
                      "%s:%u -> %s:%u, reuse remote MAC "
                      "%02x:%02x:%02x:%02x:%02x:%02x\n",
                      inet_ntoa(raddr), ntohs(tcp_hdr->source),
                      inet_ntoa(laddr), ntohs(tcp_hdr->dest),
                      eth_hdr->h_source[0], eth_hdr->h_source[1],
                      eth_hdr->h_source[2], eth_hdr->h_source[3],
                      eth_hdr->h_source[4], eth_hdr->h_source[5]);
  memcpy(path->mac, eth_hdr->h_source, ETH_ALEN);
}

/**
 * Called by tcp_demux() when a segment arrives for a listening connection.
 *
 * \param stack
 * \param tls
 * \param pkt
 *
 * TCP RX Internal
 */
int
tcp_listen_input(struct zf_stack* stack, struct zf_tcp_listen_state* tls,
                 const struct ethhdr* eth_hdr, const struct iphdr* ip_hdr,
                 const struct tcphdr* tcp_hdr)
{
  int rc = 0;

  /* In the LISTEN state, we check for incoming SYN segments.  When we receive
   * one, we create a new TCP state in the SYN_RCVD state, and respond with a
   * SYN-ACK. */
  zf_log_tcp_conn_trace(tls, "%s:\n", __FUNCTION__);

  if( ZF_UNLIKELY(tcp_hdr->rst) ) {
    /* An incoming RST should be ignored. */
    goto out;
  }
  else if( ZF_UNLIKELY(tcp_hdr->ack ||
                       (tls->tls_flags & ZF_LISTEN_FLAGS_SHUTDOWN)) ) {
    /* For incoming segments with the ACK flag set, respond with a RST.  Also,
     * if a listening zocket has been shut down, but there are still
     * outstanding references to it, then SYNs will still reach here, but
     * should be reset. */
    if( tcp_hdr->ack )
      zf_log_tcp_conn_trace(tls, "%s: ACK in LISTEN, sending reset\n",
                            __FUNCTION__);
    else
      zf_log_tcp_conn_trace(tls,
                            "%s: RX by shut-down listener, sending reset\n",
                            __FUNCTION__);
    tcp_passive_get_path(stack, eth_hdr, ip_hdr, tcp_hdr, &tls->tst.path);
    zf_init_tx_ethhdr(stack, &tls->tst);
    zft_init_tx_ip_hdr(zf_tx_iphdr(&tls->tst),
                       tls->laddr.sin_addr.s_addr, ip_hdr->saddr);
    zf_path_pin_zock(stack, &tls->tst);

    /* rfc793, page 64:
     * If the ACK bit is off, sequence number zero is used,
     *   <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
     * If the ACK bit is on,
     *   <SEQ=SEG.ACK><CTL=RST>
     */
    tcp_rst(stack, &tls->tst, ip_hdr->saddr,
            tcp_hdr->ack ? ntohl(tcp_hdr->ack_seq) : 0,
            ntohl(tcp_hdr->seq) + (tcp_hdr->ack ? 0 : 1), 0,
            ntohs(tcp_hdr->dest), ntohs(tcp_hdr->source),
            tcp_hdr->ack);
  }
  else if( ZF_LIKELY(tcp_hdr->syn) ) {
    zf_log_tcp_conn_trace(tls, "%s: TCP connection request %u -> %u.\n",
                          __FUNCTION__, ntohs(tcp_hdr->source),
                          ntohs(tcp_hdr->dest));

    /* Try to allocate some listenq space. */
    int listenq_index = zftl_listenq_add_entry(&stack->listenq,
                                               TCP_LISTEN_ID(stack, tls));
    if( listenq_index < 0 ) {
      rc = listenq_index;
      goto out;
    }

    /* Cook up a new TCP state for the nascent connection. */
    struct zf_tcp* new_tcp;
    rc = zf_tcp_new(stack, &new_tcp);
    if( rc != 0 ) {
      zf_log_tcp_conn_err(tls, "%s: could not allocate TCP state\n",
                          __FUNCTION__);
      zftl_listenq_free_entry(&stack->listenq, listenq_index);
      TCP_STATS_INC(tcp.memerr);
      goto out;
    }
    zftl_listenq_set_synrecv_id(&stack->listenq, listenq_index,
                                TCP_ID(stack, new_tcp));
    zf_init_tx_state(stack, &new_tcp->tst);
    tcp_passive_get_path(stack, eth_hdr, ip_hdr, tcp_hdr, &new_tcp->tst.path);

    /* Set up the new PCB, update defaults set in tcp_init() */
    zf_tcp_acquire(new_tcp);
    new_tcp->pcb.listenq_index = listenq_index;
    new_tcp->pcb.local_port = ntohs(tls->laddr.sin_port);
    new_tcp->pcb.remote_port = ntohs(tcp_hdr->source);
    new_tcp->pcb.rcv_nxt = ntohl(tcp_hdr->seq) + 1;
    new_tcp->pcb.rd_nxt = new_tcp->pcb.rcv_nxt;
    new_tcp->pcb.rcv_ann_right_edge = new_tcp->pcb.rcv_nxt;
    /* initialise to seqno-1 to force window update */
    new_tcp->pcb.snd_wl1 = ntohl(tcp_hdr->seq) - 1;

    ++tls->refcount;
    new_tcp->pcb.parent_listener = TCP_LISTEN_ID(stack, tls);

    /* Parse any options in the SYN. */
    tcp_parseopt(&new_tcp->pcb, tcp_hdr);
    uint16_t snd_wnd = ntohs(tcp_hdr->window);
    new_tcp->pcb.snd_right_edge = new_tcp->pcb.lastack + snd_wnd;
    new_tcp->pcb.snd_wnd_max = snd_wnd;
    tcp_do_transition(new_tcp, SYN_RCVD);

    if( ZF_UNLIKELY( new_tcp->tst.path.rc != ZF_PATH_OK ) ) {
      /* Even if we've failed to resolve MAC earlier, it can be ready now.
       * Let's re-ask about the path info and be ready to wait if
       * necessary. */
      zf_cplane_get_path(stack, &new_tcp->tst.path, true/*wait*/);
      if( new_tcp->tst.path.rc != ZF_PATH_OK ) {
        /* Can not get the return route: drop the connection. */
        struct in_addr daddr;
        daddr.s_addr = zf_tx_iphdr(&new_tcp->tst)->daddr;
        zf_log_tcp_conn_err(tls, "%s: no return route to %s, "
                            "drop incoming connection\n", __func__,
                            inet_ntoa(daddr));
        tcp_abort(stack, new_tcp);
        goto out;
      }
    }
    zf_assert_equal(new_tcp->tst.path.rc, ZF_PATH_OK);

    zf_init_tx_ethhdr(stack, &new_tcp->tst);
    zft_init_tx_ip_hdr(zf_tx_iphdr(&new_tcp->tst),
                       tls->laddr.sin_addr.s_addr, ip_hdr->saddr);

    tcp_populate_header_common(zf_tx_tcphdr(&new_tcp->tst),
                               new_tcp->pcb.local_port,
                               new_tcp->pcb.remote_port);
    zf_path_pin_zock(stack, &new_tcp->tst);

    /* Register the new TCP state so that we can begin receiving segments for
     * it. */
    tcp_passive_rx_init(stack, new_tcp, tls);

    /* pcb.mss was set to MSS_MIN, get maximum both us and peer can
     * cope with. */
    new_tcp->pcb.mss = tcp_mtu2mss(new_tcp->tst.path.mtu);
    if( new_tcp->pcb.mss > new_tcp->pcb.mss_lim )
      new_tcp->pcb.mss = new_tcp->pcb.mss_lim;
    new_tcp->pcb.ssthresh = ZF_TCP_INITIAL_SSTHRESH(&new_tcp->pcb);
    new_tcp->pcb.snd_buf = tcp_snd_buf_avail(&new_tcp->pcb, &new_tcp->pcb.sendq);
    zf_assert_equal(TCP_SND_QUEUELEN * new_tcp->pcb.mss, new_tcp->pcb.snd_buf);
    new_tcp->pcb.snd_buf_advertisement_threshold =
      TCP_SND_BUF_ADVERTISEMENT_THRESHOLD(new_tcp->pcb.snd_buf);

    if( stack->flags & ZF_STACK_FLAG_TCP_NO_DELACK )
      new_tcp->pcb.flags_ack_delay |= TF_ON;

    /* We're a fully-initialised SYN_RCVD zocket now. */
    new_tcp->tcp_state_flags |= ZF_TCP_STATE_FLAGS_INITIALISED;

    MIB2_STATS_INC(mib2.tcppassiveopens);

    /* Enqueue a SYN-ACK together with the MSS option. */
    rc = tcp_enqueue_flags(new_tcp, 1, 0, 1);
    if (rc != 0) {
      tcp_pcb_release(stack, new_tcp);
      goto out;
    }
    /* Push out the SYN-ACK. */
    rc = tcp_output(new_tcp);

    tcp_fix_fast_send_length(&new_tcp->pcb);
  }
 out:
  zf_pool_free_pkt(&stack->pool, PKT_BUF_ID_FROM_PTR(&stack->pool, tcp_hdr));

  if( rc != 0 )
    zf_log_tcp_rx_err(tls, "%s: failed (rc = %d)\n", __FUNCTION__, rc);

  /* No application-visible events happened here. */
  return 0;
}


int tcp_process_reset(struct zf_tcp* tcp, uint8_t* recv_flags, uint32_t seqno,
                      uint32_t ackno)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  int acceptable = 0;

  if (pcb->state == SYN_SENT) {
    if (ackno == pcb->snd_nxt) {
      acceptable = 1;
    }
  }
  else {
    acceptable = 1;
  }

  if (acceptable) {
    zf_log_tcp_conn_trace(tcp, "%s: connection reset\n", __func__);
    zf_assert_nequal(pcb->state, CLOSED);
    *recv_flags |= TF_RESET;
    pcb->flags &= ~(TF_ACK_DELAY | TF_ACK_NEXT);
    return -ECONNRESET;
  }
  else {
    zf_log_tcp_conn_trace(tcp, "%s: unacceptable reset seqno %u rcv_nxt %u",
                          __func__, seqno, pcb->rcv_nxt);
    return 0;
  }
}


void tcp_configure_rto_zwin_timers(struct zf_tcp* tcp)
{
  /* If there's nothing left to acknowledge, stop the retransmit timer,
   * otherwise reset it to start again.
   * Zwin timer can only be started when all data has been acknowledged and
   * receive window is small.
   */
  if( ! tcp_has_unacked(&tcp->pcb.sendq) ) {
    zf_tcp_timers_timer_stop(tcp, ZF_TCP_TIMER_RTO);

    struct tcp_pcb* pcb = &tcp->pcb;
    zf_assert(TCP_SEQ_GEQ(pcb->snd_right_edge, pcb->lastack));

    if(CI_UNLIKELY( ! zf_tcp_timers_timer_is_active(tcp, ZF_TCP_TIMER_ZWIN) &&
                    pcb->snd_right_edge - pcb->lastack < pcb->mss )) {
      pcb->persist_backoff = 0;
      zf_tcp_timers_timer_start(tcp, ZF_TCP_TIMER_ZWIN,
                                tcp_timers_zwin_timeout(tcp));
    }
  }
  else
    zf_tcp_timers_timer_start(tcp, ZF_TCP_TIMER_RTO,
                              zf_tcp_timers_rto_timeout(tcp));
}

/* Returns the configured initial congestion window, or 10 * MSS by default. */
static uint16_t
tcp_calc_initial_cwnd(struct zf_stack* stack, struct tcp_pcb* pcb)
{
  uint16_t cwnd;

  cwnd = stack->tcp_initial_cwnd == 0 ? 10 * pcb->mss :
                                        MAX(pcb->mss, stack->tcp_initial_cwnd);

  return MIN(TCP_WND, cwnd);
}


static bool tcp_invalid_seqno(struct zf_tcp* tcp, struct tcp_seg* seg)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  struct tcphdr* tcp_hdr = (struct tcphdr*) seg->iov.iov_base;
  uint16_t tcplen = tcp_seg_len(seg);
  uint32_t seq = htonl(tcp_hdr->seq);

  zf_assert_ge(pcb->state, ESTABLISHED);

  /* If the seq number is within the window, and
   * ( window is non-zero or the segment does not consume any seq space )
   * then the segment is valid. */
  if( ZF_LIKELY(
      ( tcplen == 0 || pcb->rcv_ann_wnd > 0 ) &&
      TCP_SEQ_BETWEEN(seq, pcb->rcv_nxt,
                      pcb->rcv_nxt + pcb->rcv_ann_wnd) ) ) {
    return false;
  }

  /* The end of the segment is in the window - valid */
  if( pcb->rcv_ann_wnd > 0 &&
      TCP_SEQ_BETWEEN(seq + tcplen - 1, pcb->rcv_nxt,
                      pcb->rcv_nxt + pcb->rcv_ann_wnd) ) {
    return false;
  }

  zf_log_tcp_rx_trace(tcp, "%s: reject packet %u-%u when expecting %u-%u\n",
                      __func__, seq, seq + tcplen,
                      pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_ann_wnd);
  return true;
}


static inline void
tcp_calculate_rtt_init(struct zf_stack* stack, struct tcp_pcb* pcb)
{
  /* first rtt estimate so follow (2.2) of RFC2988 */
  int16_t m = tcp_calculate_rtt_last(stack, pcb);
  pcb->sa = (m << 3u);
  pcb->sv = (m << 1u);
}

/** \brief Implements the TCP state machine.
 *
 * \param tcp
 *
 * \return true if the packet is valid
 *
 * This takes action based on the current TCP state.  The most interesting
 * action is to call tcp_receive, which is done when in a connected state.
 *
 * TX RX internal
 */
bool tcp_process(struct zf_tcp* tcp, struct tcp_seg* seg, uint8_t* recv_flags)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  struct tcphdr* tcp_hdr = (struct tcphdr*) seg->iov.iov_base;
  uint32_t ackno = ntohl(tcp_hdr->ack_seq);
  uint32_t seqno = ntohl(tcp_hdr->seq);
  uint16_t source = ntohs(tcp_hdr->source);
  uint16_t dest = ntohs(tcp_hdr->dest);
  uint16_t window = ntohs(tcp_hdr->window);

  /* RFC 793 p 68: first check sequence number */
  if( pcb->state != SYN_SENT && tcp_invalid_seqno(tcp, seg) ) {
    if( ! tcp_hdr->rst )
      pcb->flags |= TF_ACK_NOW;
    return false;
  }

  /* RFC 793 p 69: second check the RST bit */
  if (tcp_hdr->rst) {
    tcp_process_reset(tcp, recv_flags, seqno, ackno);
    return true;
  }

  /* RFC 793 p 70: third check security and precedence
   * nothing to do here */

  /* RFC 793 p 70: fourth, check the SYN bit
   * we do not implement simultaneous open */
  if( (tcp_hdr->syn) && (pcb->state != SYN_SENT && pcb->state != SYN_RCVD) ) { 
    /* Cope with new connection attempt after remote end crashed */
    pcb->flags |= TF_ACK_NOW;
    return false;
  }
  
  /* Do different things depending on the TCP state. */
  switch (pcb->state) {
  case SYN_SENT:
    zf_log_tcp_conn_trace(tcp,
                          "%s: SYN-SENT: ackno %u pcb->snd_nxt %u unacked %u\n",
                          __func__, ackno, pcb->snd_nxt,
                          tcp_seg_seq(tcp_unacked(&pcb->sendq)));

    /* Common handling for receipt of SYN-ACK (the typical case) and of SYN
     * (simultaneous open). */
    if( tcp_hdr->syn ) {
      pcb->rcv_nxt = seqno + 1;
      pcb->rd_nxt = seqno + 1;
      pcb->rcv_ann_right_edge = pcb->rcv_nxt;
      pcb->snd_wl1 = seqno - 1;/* initialise to seqno-1 to force window update */
      pcb->snd_wnd_max = window;

      /* Set ssthresh again after changing pcb->mss (already set in tcp_connect
       * but for the default value of pcb->mss) */
      pcb->ssthresh = ZF_TCP_INITIAL_SSTHRESH(pcb);
    }

    /* received SYN ACK with expected sequence number? */
    if (tcp_hdr->ack && tcp_hdr->syn
        && (ackno == tcp_seg_seq(tcp_unacked(&pcb->sendq)) + 1) ) {
      tcp_parseopt(pcb, tcp_hdr);

      zf_assert_equal(tcp->tst.path.rc, ZF_PATH_OK);
      /* pcb.mss was set to MSS_MIN, get maximum both us and peer can
       * cope with. */
      pcb->mss = tcp_mtu2mss(tcp->tst.path.mtu);
      if( pcb->mss > pcb->mss_lim )
        pcb->mss = pcb->mss_lim;

      pcb->lastack = ackno;
      pcb->snd_right_edge = pcb->lastack + window;
      tcp_do_transition(tcp, ESTABLISHED);

      tcp_calculate_rtt_init(stack, pcb);
      pcb->cwnd = tcp_calc_initial_cwnd(stack, pcb);

      tcp_seg_mark_acked_and_free(stack, pcb, tcp_unacked(&pcb->sendq));

      /* When recalculating snd_buf take into account:
       *  * new mss value,
       *  * segments already queued on sendq
       */
      pcb->snd_buf = tcp_snd_buf_avail(pcb, &pcb->sendq);
      pcb->snd_buf_advertisement_threshold =
        TCP_SND_BUF_ADVERTISEMENT_THRESHOLD(pcb->snd_buf);
      pcb->ssthresh = ZF_TCP_INITIAL_SSTHRESH(pcb);

      /* FIXME after mss change - coalesce sendq */

      zf_log_tcp_conn_trace(tcp, "%s: SYN-SENT --queuelen %u\n", __func__,
                            tcp_snd_queuelen(&pcb->sendq));

      /* Start or stop RTO timer. */
      tcp_configure_rto_zwin_timers(tcp);

      pcb->flags |= TF_ACK_NOW;
    }
    /* Simultaneous open. */
    else if (tcp_hdr->syn) {
      tcp_parseopt(pcb, tcp_hdr);
      /* Send a SYN|ACK together with the MSS option. */
      int rc = tcp_enqueue_flags(tcp, 1, 0, 1);
      if (rc == 0) {
        zf_log_tcp_conn_trace(tcp, "%s: SYN-SENT->SYN-RCVD: %u -> %u\n",
                              __FUNCTION__, source, dest);
        tcp_do_transition(tcp, SYN_RCVD);
      }
      else {
        zf_log_tcp_conn_trace(tcp,
                              "%s: SYN-SENT: Failed to allocate SYN-ACK segment "
                              "(rc=%d) %u -> %u\n",
                              __FUNCTION__, rc, source, dest);
      }
    }
    /* received ACK? possibly a half-open connection */
    else if (tcp_hdr->ack) {
      /* send a RST to bring the other side in a non-synchronized state. */
      tcp_rst(stack, &tcp->tst, zf_tx_iphdr(&tcp->tst)->daddr, ackno,
              seqno + tcp_seg_len(seg), tcp->pcb.rcv_ann_wnd, dest,
              source, false);
      return false;
    }
    tcp_fix_fast_send(stack, pcb);
    break;
  case SYN_RCVD:
    tcp_parseopt(pcb, tcp_hdr);
    zf_log_tcp_conn_trace(tcp,
                          "%s: SYN-RCVD: ackno %u lastack %u pcb->snd_nxt %u "
                          "unacked %u\n", __func__,
                          ackno, pcb->lastack, pcb->snd_nxt,
                          tcp_seg_seq(tcp_unacked(&pcb->sendq)));

    if( tcp_hdr->ack ) {
      /* Expected ACK number? snd_iss is already one greater than the
       * seqno of the SYN; see comment in tcp_init()
       */
      if( ackno == pcb->snd_iss ) {
        tcp_do_transition(tcp, ESTABLISHED);

        zf_muxer_mark_waitable_ready(&tcp->w, EPOLLOUT);
        tcp_calculate_rtt_init(stack, pcb);

        if( pcb->parent_listener != ZF_ZOCKET_ID_INVALID ) {
          /* Push the new zocket onto the accept queue (which is actually a
           * stack). */
          struct zf_tcp_listen_state* tls;
          tls = &stack->tcp_listen[pcb->parent_listener];
          zftl_listenq_free_entry(&stack->listenq, pcb->listenq_index);
          /* We give the accept queue a reference, as we want this zocket to
           * hang around even if the TCP connection is closed while on the
           * accept queue.  When the application accepts the zocket, the
           * reference will be transferred to the application.
           */
          zf_tcp_acquire(tcp);
          pcb->acceptq_next = tls->acceptq_head;
          tls->acceptq_head = TCP_ID(stack, tcp);
          *recv_flags |= TF_ACCEPTQ;
          zf_muxer_mark_waitable_ready(&tls->w, EPOLLIN);
        }

        /* If there was any data contained within this ACK,
         * we'd better pass it on to the application as well.
         * It should be called after putting the zocket into accept
         * queue, so the zocket does not look like orphaned. */
        tcp_receive(tcp, seg, recv_flags);

        /* passive open: update initial ssthresh now that the correct window is
           known: if the remote side supports window scaling, the window sent
           with the initial SYN can be smaller than the one used later */
        pcb->ssthresh = ZF_TCP_INITIAL_SSTHRESH(pcb);

        pcb->cwnd = tcp_calc_initial_cwnd(stack, pcb);

        zf_log_tcp_conn_trace(tcp, "TCP connection established %u -> %u.\n",
                              source, dest);
        zf_log_tcp_conn_trace(tcp,
                              "%s (SYN_RCVD): cwnd %u ssthresh %u\n",
                              __func__, pcb->cwnd, pcb->ssthresh);

        if( *recv_flags & TF_GOT_FIN ) {
          zf_log_tcp_conn_trace(tcp,
                                "TCP connection got FIN with ACK-for-SYN "
                                "%u -> %u\n",
                                source, dest);
          pcb->flags |= TF_ACK_NOW;
          tcp_do_transition(tcp, CLOSE_WAIT);
        }
      }
      else {
        /* incorrect ACK number, send RST */
        tcp_rst(stack, &tcp->tst, zf_tx_iphdr(&tcp->tst)->daddr, ackno,
                seqno + tcp_seg_len(seg), tcp->pcb.rcv_ann_wnd, dest,
                source, false);
        return false;
      }
    }
    else if( tcp_hdr->syn && seqno == pcb->rcv_nxt - 1 ) {
      /* Looks like another copy of the SYN - retransmit our SYN-ACK */
      tcp_rexmit(pcb);
    }
    tcp_fix_fast_send(stack, pcb);
    break;
  case CLOSE_WAIT:
    /* FALLTHROUGH */
  case ESTABLISHED:
    tcp_receive(tcp, seg, recv_flags);
    if (*recv_flags & TF_GOT_FIN) { /* passive close */
      zf_log_tcp_conn_trace(tcp,
                            "%s: TCP connection closed from net: "
                            "FIN_WAIT_1 %u -> %u\n",
                            __func__, source, dest);
      pcb->flags |= TF_ACK_NOW;
      tcp_do_transition(tcp, CLOSE_WAIT);
    }
    break;
  case FIN_WAIT_1:
    tcp_receive(tcp, seg, recv_flags);
    if (*recv_flags & TF_GOT_FIN) {
      if (!tcp_has_sendq(&pcb->sendq)) {
        zf_log_tcp_conn_trace(tcp,
                              "%s: TCP connection closed: "
                              "FIN_WAIT_1 %u -> %u\n",
                              __func__, source, dest);
        pcb->flags |= TF_ACK_NOW;
        tcp_do_transition(tcp, TIME_WAIT);

      } else {
        pcb->flags |= TF_ACK_NOW;
        tcp_do_transition(tcp, CLOSING);
      }
    } else if (!tcp_has_sendq(&pcb->sendq)) {
      zf_log_tcp_conn_trace(tcp,
                            "%s: FIN ACKed: "
                            "FIN_WAIT_1 %u -> %u\n",
                            __func__, source, dest);
      tcp_do_transition(tcp, FIN_WAIT_2);
    }
    break;
  case FIN_WAIT_2:
    tcp_receive(tcp, seg, recv_flags);
    if (*recv_flags & TF_GOT_FIN) {
      zf_log_tcp_conn_trace(tcp,
                            "%s: TCP connection closed: "
                            "FIN_WAIT_2 %u -> %u\n",
                            __func__, source, dest);
      pcb->flags |= TF_ACK_NOW;
      tcp_do_transition(tcp, TIME_WAIT);
    }
    break;
  case CLOSING:
    tcp_receive(tcp, seg, recv_flags);
    if (!tcp_has_sendq(&pcb->sendq)) {
      zf_log_tcp_conn_trace(tcp, "%s: TCP connection closed: "
                            "CLOSING %u -> %u\n", __func__,
                           source, dest);
      tcp_do_transition(tcp, TIME_WAIT);
    }
    break;
  case LAST_ACK:
    tcp_receive(tcp, seg, recv_flags);
    if (!tcp_has_sendq(&pcb->sendq)) {
      zf_log_tcp_conn_trace(tcp, "%s: TCP connection closed: "
                            "LAST_ACK %u -> %u\n",
                            __func__, source, dest);
      *recv_flags |= TF_CLOSED;
    }
    break;
  case TIME_WAIT:
    tcp_receive_timewait(tcp, seg, recv_flags);
    break;
  default:
    break;
  }

  zf_log_tcp_rx_trace(tcp, "%s: processed, current state 0x%x\n", __func__,
                      pcb->state);
  return true;
}


/* This code path handles the common scenario of processing of pkts
 * in order */
ZF_HOT static inline void
tcp_frequent_sync_path(zf_stack* st, zf_tcp* tcp, struct tcphdr* tcp_hdr,
                       size_t payload_len)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  char* payload = (char*) tcp_hdr + BASE_TCP_HDR_LEN;

  /* ACK flag must be set on this path */
  zf_assert(tcp_hdr->ack);
  zf_assert(zfr_queue_all_packets_processed(&tcp->tsr));

  tcp_frequent_path_common_head(tcp, tcp_hdr);

  zf_assume_gt(payload_len, 0);
  
  /* Notify application that data has been received. */
  struct iovec recv_data;

  /* An initial condition on this path is that the incoming sequence number
   * equals rcv_nxt, so just add the payload length here. */
  zf_assert_ge(TCP_SEQ_SUB(pcb->rcv_nxt, pcb->rd_nxt), 0);
  pcb->rcv_nxt += payload_len;
  zf_assert_lt((uint32_t)TCP_SEQ_SUB(pcb->rcv_nxt, pcb->rd_nxt),
               (uint32_t)(TCP_WND + pcb->mss));

  recv_data.iov_base = payload;
  recv_data.iov_len = payload_len;

  /* It's a condition for the frequent path that we can queue the segment */
  zf_assert(zfr_tcp_queue_has_space(&tcp->tsr.ring));

  zfr_pkt_queue(&tcp->tsr.ring, &recv_data);
  zfr_queue_mark_processed(&tcp->tsr);
  
  zf_muxer_mark_waitable_ready(&tcp->w, EPOLLIN);

  tcp_dack_flags_flick(pcb);

  /* Announced window must be updated after payload has been queued,
   * including if this happened earlier in the cut-through case. */
  tcp_update_rcv_ann_wnd(pcb);

  tcp_rx_common_tail(st, tcp);
}


/** \brief Initial input processing of TCP.
 *
 * \param stack
 * \param tcp
 * \param pkt
 *
 * This sets up a bunch of state before poking the next stage in the
 * RX processing, tcp_process.  That function may result in various
 * flags being set and state being updated.
 *
 * TCP RX Internal
 */
int tcp_input(struct zf_stack* stack, struct zf_tcp* tcp,
              struct tcphdr* tcp_hdr, size_t segment_len)
{
  struct tcp_pcb* pcb;
  int event_occurred = 0;

  TCP_STATS_INC(tcp.recv);

  pcb = &tcp->pcb;

  zf_log_tcp_rx_trace(tcp, "%s: state 0x%x\n", __func__, pcb->state);

  zf_assert(zfr_queue_all_packets_processed(&tcp->tsr));

  if( ZF_LIKELY(tcp_test_frequent_path(pcb, tcp_hdr, ntohl(tcp_hdr->seq),
                                       ntohl(tcp_hdr->ack_seq),
                                       segment_len-BASE_TCP_HDR_LEN,
                                       &tcp->tsr.ring)) ) {
    size_t payload_len = segment_len - BASE_TCP_HDR_LEN;
    zf_assume_ge(payload_len, 0);

    tcp_frequent_sync_path(stack, tcp, tcp_hdr, payload_len);

    /* Rebuild any allocated alternatives which have data queued
     * for this zocket. */
    zf_stack_mark_alternatives_for_rebuild(stack, tcp);

    return 1;
  }

  const size_t tcp_hdr_len = tcp_hdr->doff * 4;
  char* payload = (char*) tcp_hdr + tcp_hdr_len;
  struct tcp_seg inseg;

  inseg.iov.iov_base = (char*) tcp_hdr;
  inseg.iov.iov_len = segment_len;
  inseg.len = segment_len - tcp_hdr_len;

  uint8_t recv_flags = 0;
  if( tcp_process(tcp, &inseg, &recv_flags) )
    event_occurred = tcp_post_process(stack, tcp, &inseg, payload, recv_flags);
  else if( pcb->flags & TF_ACK_NOW )
    tcp_send_empty_ack(tcp);
  /************************************************************************
   * tcp_post_process may result in releasing the zf_tcp, so it must not be
   * touched after this point.
   ************************************************************************/

  /* If the data has not been consumed we need to free the buffer */
  if (inseg.iov.iov_base != NULL)
    zf_pool_free_pkt(&stack->pool,
                     PKT_BUF_ID_FROM_PTR(&stack->pool, inseg.iov.iov_base));

  /* Rebuild any allocated alternatives which have data queued
   * for this zocket. */
  zf_stack_mark_alternatives_for_rebuild(stack, tcp);

  return event_occurred;
}


/** \brief Handle RX when in TIME-WAIT
 *
 * \param tcp        The tcp struct
 * \param seg        The incoming data segment
 * \param recv_flags Flags field to be populated with flags indicating actions
 *                   to occur in post-processing
 *
 * TCP RX internal
 */
ZF_COLD static void
tcp_receive_timewait(struct zf_tcp* tcp, struct tcp_seg* seg,
                     uint8_t* recv_flags)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  struct tcphdr* tcp_hdr = (struct tcphdr*) seg->iov.iov_base;
  uint16_t tcplen = tcp_seg_len(seg);
  uint32_t ackno = ntohl(tcp_hdr->ack_seq);
  uint32_t seqno = ntohl(tcp_hdr->seq);

  /* RFC1337 says that RST should be ignored in TIME_WAIT */
  if( tcp_hdr->rst )
    return;

  if( tcp_hdr->syn ) {
    zf_assert_equal(pcb->snd_delegated, 0);
    /* If the SYN is in the window it is an error, send a reset */
    tcp_rst(stack, &tcp->tst, zf_tx_iphdr(&tcp->tst)->daddr, ackno,
            seqno + tcplen, pcb->rcv_ann_wnd, pcb->local_port,
            pcb->remote_port, false);
    return;
  }
  else if( tcp_hdr->fin ) {
    zf_tcp_timers_timer_start(tcp, ZF_TCP_TIMER_TIMEWAIT,
                              zf_tcp_timers_timewait_timeout(stack));
  }

  /* Always respond with an ACK - this will be based on our pcb state, so will
   * ACK the last data we've actually processed.
   */
  if( tcplen > 0 )
    pcb->flags |= TF_ACK_NOW;
}


/** \brief Handle RX when in a connected state
 *
 * \param tcp
 *
 * TCP RX internal
 */
static void tcp_receive(struct zf_tcp* tcp, struct tcp_seg* seg,
                        uint8_t* recv_flags)
{
  int found_dupack = 0;
  struct tcp_pcb* pcb = &tcp->pcb;
  struct tcphdr* tcp_hdr = (struct tcphdr*) seg->iov.iov_base;
  uint16_t tcplen = tcp_seg_len(seg);
  uint32_t ackno = ntohl(tcp_hdr->ack_seq);
  uint32_t seqno = ntohl(tcp_hdr->seq);

  zf_assert_ge(pcb->state, ESTABLISHED);

  if (tcp_hdr->ack) {
    uint32_t old_snd_right_edge = pcb->snd_right_edge;

    tcp_handle_ack_common(tcp, tcp_hdr);

    /* (From Stevens TCP/IP Illustrated Vol II, p970.) Its only a
     * duplicate ack if:
     * 1) It doesn't ACK new data 
     * 2) length of received packet is zero (i.e. no payload) 
     * 3) the advertised window hasn't changed 
     * 4) There is outstanding unacknowledged data (retransmission timer running)
     * 5) The ACK is == biggest ACK sequence number so far seen (snd_una)
     * 
     * If it passes all five, should process as a dupack: 
     * a) dupacks < 3: do nothing 
     * b) dupacks == 3: fast retransmit 
     * c) dupacks > 3: increase cwnd 
     * 
     * If it only passes 1-3, should reset dupack counter
     *
     * If it only passes 1, should reset dupack counter
     *
     */

    /* Clause 1 */
    if (TCP_SEQ_LEQ(ackno, pcb->lastack)) {
      /* Clause 2 */
      if (tcplen == 0) {
        /* Clause 3 */
        if (pcb->snd_right_edge == old_snd_right_edge) {
          /* Clause 4 */
          if (zf_tcp_timers_timer_is_active(tcp, ZF_TCP_TIMER_RTO) ) {
            /* Clause 5 */
            if (pcb->lastack == ackno) {
              found_dupack = 1;
              if ((uint8_t)(pcb->dupacks + 1) > pcb->dupacks) {
                ++pcb->dupacks;
              }
              if (pcb->dupacks > 3) {
                /* Inflate the congestion window, but not if it means that
                   the value overflows. */
                if ((uint16_t)(pcb->cwnd + pcb->mss) > pcb->cwnd) {
                  pcb->cwnd += pcb->mss;
                  tcp_fix_fast_send_length(pcb);
                }
              }
              else if (pcb->dupacks == 3) {
                /* Do fast retransmit */
                tcp_rexmit_fast(tcp);
              }
            }
          }
        }
      }
      /* If Clause (1) or more is true, but not a duplicate ack, reset
       * count of consecutive duplicate acks */
      if( !found_dupack ) {
        pcb->dupacks = 0;
      }
    }
    else if( TCP_SEQ_BETWEEN(ackno, pcb->lastack+1,
                             pcb->snd_nxt + pcb->snd_delegated) ) {
      tcp_handle_ack_new(tcp, tcp_hdr);
    }
  }

  /* If the incoming segment contains data, we must process it
   * further unless the pcb already received a FIN.
   * (RFC 793, chapeter 3.9, "SEGMENT ARRIVES" in states CLOSE-WAIT, CLOSING,
   * LAST-ACK and TIME-WAIT: "Ignore the segment text.")
   */
  if( (tcplen > 0) && (pcb->state < CLOSE_WAIT) ) {
    /* This code basically does three things:

    +) If the incoming segment contains data that is the next
    in-sequence data, this data is passed to the application. This
    might involve trimming the first edge of the data. The rcv_nxt
    variable and the advertised window are adjusted.

    +) If the incoming segment has data that is above the next
    sequence number expected (->rcv_nxt), the segment is placed on
    the ->ooseq queue. This is done by finding the appropriate
    place in the ->ooseq queue (which is ordered by sequence
    number) and trim the segment in both ends if needed. An
    immediate ACK is sent to indicate that we received an
    out-of-sequence segment.

    +) Finally, we check if the first segment on the ->ooseq queue
    now is in sequence (i.e., if rcv_nxt >= ooseq->seqno). If
    rcv_nxt > ooseq->seqno, we must trim the first edge of the
    segment on ->ooseq before we adjust rcv_nxt. The data in the
    segments that are now on sequence are chained onto the
    incoming segment so that we only need to call the application
    once.
    */

    /* First, we check if we must trim the first edge. We have to do
       this if the sequence number of the incoming segment is less
       than rcv_nxt, and the sequence number plus the length of the
       segment is larger than rcv_nxt. */
    if (TCP_SEQ_BETWEEN(pcb->rcv_nxt, seqno + 1, seqno + tcplen - 1)){
      /* We need to trim bytes up to rcv_nxt, and adjust the payload length
       * accordingly.  We also adjust the seqno and the header sequence, to
       * make further processing treat this as though those bytes didn't
       * exist.  We don't expect to hit this case normally, so we just take
       * the simple approach of copying the data starting at rcv_nxt to the
       * beginning of the segment.  This means we have no impact elsewhere,
       * it's as though this incident never occurred!  An alternative would
       * be to allow the tcp_process handling to convey the alternative
       * payload offset to the rest of the RX path, and to handle the
       * payload not immediately following the header, which would also
       * impact the co-alescing code.
       */
      const size_t tcp_hdr_len = tcp_hdr->doff * 4;
      char* payload = (char*) tcp_hdr + tcp_hdr_len;
      int to_trim = TCP_SEQ_SUB(pcb->rcv_nxt, seqno);
      seg->len -= to_trim;
      tcplen -= to_trim;
      seqno = pcb->rcv_nxt;
      tcp_hdr->seq = htonl(seqno);
      memmove(payload, payload + to_trim, seg->len);
    }
    else {
      if (TCP_SEQ_LT(seqno, pcb->rcv_nxt)){
        /* the whole segment is < rcv_nxt so must be a duplicate of a packet
         * that has already been correctly handled
         */
        zf_log_tcp_rx_trace(tcp, "%s: duplicate seqno %u\n", __func__, seqno);
        pcb->flags |= TF_ACK_NOW;
      }
    }

    /* The sequence number must be within the window (above rcv_nxt
     * and below rd_next + TCP_WND) in order to be further
     * processed.
     */
    if( TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt, pcb->rd_nxt + TCP_WND - 1) ){
      if( ZF_UNLIKELY(tcp_is_orphan(tcp) && seg->len != 0) ) {
        /* The zocket has been closed and we've received in-window payload.  We
         * should respond with a RST. */
        *recv_flags |= TF_ABORT;
        return;
      }

      if( pcb->rcv_nxt == seqno ) {
        /* We might try coalescing, which requires that there's no deferred
         * processing outstanding. */
        zf_assert(zfr_queue_all_packets_processed(&tcp->tsr));

        /* If there are no entries left to queue this, try and make some more */
        if( ! zfr_tcp_queue_has_space(&tcp->tsr.ring) )
          zfr_queue_coalesce(&tcp->tsr, zf_stack_from_zocket(tcp));

        /* If there's a ZC-receive currently in progress, we might have failed
         * to create any room by coalescing, so we need to check again. */
        if( zfr_tcp_queue_has_space(&tcp->tsr.ring) ) {
          /* The incoming segment is the next in sequence. We check if
           * we have to trim the end of the segment and update rcv_nxt
           * and pass the data to the application.
           */
          if( TCP_SEQ_GT(seqno + tcplen, pcb->rd_nxt + TCP_WND) ) {
            zf_log_tcp_rx_trace(tcp,
                                "%s: other end overran receive window"
                                "seqno %u len %u right edge %u\n",
                                __func__,
                                seqno, tcplen, pcb->rd_nxt + TCP_WND);
            pcb->flags |= TF_ACK_NOW;

            /* Currently, we accept entire segment despite partially being
               out of the window, we have entire packet buffer anyway */
          }

          pcb->rcv_nxt = seqno + tcplen;
          tcp_update_rcv_ann_wnd(pcb);

          /* If there is data in the segment, we make preparations to
             pass this up to the application. The ->recv_data variable
             is used for holding the pbuf that goes to the
             application. The code for reassembling out-of-sequence data
             chains its data on this pbuf as well.

             If the segment was a FIN, we set the TF_GOT_FIN flag that will
             be used to indicate to the application that the remote side has
             closed its end of the connection. */
          if (seg->len > 0) {
            /* Since this pbuf now is the responsibility of the
               application, we delete our reference to it so that we won't
               (mistakingly) deallocate it. */
            seg->iov.iov_base = NULL;
          }
          if (tcp_hdr->fin) {
            zf_log_tcp_rx_trace(tcp, "%s: received FIN.\n", __func__);
            *recv_flags |= TF_GOT_FIN;
          }

          tcp_dack_flags_flick(pcb);

          /* Don't fall through to the failure path. */
          return;
        }
        else {
          /* No space after coalescing.  This should only happen if there's a
           * ZC-receive in progress. */
          zf_assert(zft_zc_recv_in_progress(tcp));
        }
      }
      else
        /* Out-of-order sequence number */
        *recv_flags |= TF_OOO;
    }

    /* We get here if the incoming segment is out-of-sequence, or if we're out
     * of receive-queue space. */
    pcb->flags |= TF_ACK_NOW;
  }

  return;
}

/** \brief Parses the options contained in the incoming segment. 
 *
 * \param pcb the tcp_pcb for which a segment arrived
 *
 * Currently, only the MSS option is actively parsed, other options are
 * ignored.
 */
static void
tcp_parseopt(struct tcp_pcb *pcb, const struct tcphdr* tcp_hdr)
{
  uint16_t c, max_c;
  uint16_t mss;
  const uint8_t *opts;
  uint8_t opt;

  opts = (uint8_t *)tcp_hdr + TCP_HLEN;

  /* Parse the TCP MSS option, if present. */
  if(tcp_hdr->doff > 0x5) {
    max_c = (tcp_hdr->doff - 5) << 2;
    for (c = 0; c < max_c; ) {
      opt = opts[c];
      switch (opt) {
      case TCP_OPT_END_KIND:
        /* End of options. */
        return;
      case TCP_OPT_NOP_KIND:
        /* NOP option. */
        ++c;
        break;
      case TCP_OPT_MSS_KIND:
        if (opts[c + 1] != TCP_OPT_MSS_LENGTH || c + TCP_OPT_MSS_LENGTH > max_c)
          /* Bad length */
          return;
        /* An MSS option with the right option length. */
        mss = (opts[c + 2] << 8) | opts[c + 3];
        pcb->mss_lim = tcp_mss_restrict(mss);
        /* Advance to next option */
        c += TCP_OPT_MSS_LENGTH;
        break;
      default:
        if (opts[c + 1] == 0)
          /* If the length field is zero, the options are malformed
             and we don't process them further. */
          return;
        /* All other options have a length field, so that we easily
           can skip past them. */
        c += opts[c + 1];
      }
    }
  }
}

