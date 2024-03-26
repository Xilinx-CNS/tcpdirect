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


void tcp_cut_through(struct zf_tcp* tcp, char* payload, size_t payload_len)
{
  struct tcp_pcb* pcb = &tcp->pcb;

  zf_assert_equal(pcb->state, ESTABLISHED);

  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  struct iovec recv_data;

  recv_data.iov_base = payload;
  recv_data.iov_len = payload_len;
  zfr_pkt_queue(&tcp->tsr.ring, &recv_data);
  zf_muxer_mark_waitable_ready(&tcp->w, EPOLLIN);
  zf_stack_tcp_set_deferred_rx(stack, tcp->zocket_mask);

  zf_assert_ge(TCP_SEQ_SUB(pcb->rcv_nxt, pcb->rd_nxt), 0);
  pcb->rcv_nxt += payload_len;
  zf_assert_lt((uint32_t)TCP_SEQ_SUB(pcb->rcv_nxt, pcb->rd_nxt),
               (uint32_t)(TCP_WND + pcb->mss));
}


/* Undo the processing in tcp_cut_through().  This is only called to rollback
 * TCP processing if tcp_cut_through() returned 1 for the occurrence of a
 * user-visible event. */
void tcp_cut_through_rollback(struct zf_tcp* tcp, size_t payload_len)
{
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  struct zf_rx* rx = &tcp->tsr;

  zf_stack_tcp_clear_deferred_rx(stack, TCP_ID(stack, tcp));

  /* Remove queued packet */
  --rx->ring.end;
  tcp->pcb.rcv_nxt -= payload_len;

  /* Clear muxer if this was the only packet to be read */
  if( zfr_queue_all_packets_read(rx) )
    zf_muxer_mark_waitable_not_ready(&tcp->w, EPOLLIN);
}


ZF_HOT static inline void
tcp_rx_flush_pkt(struct zf_tcp* tcp, struct tcphdr* tcp_hdr,
                 size_t payload_len)
{
  /* ACK flag must be set on this path unless already acked */
  zf_assert(tcp_hdr->ack);
  zf_assert(! zfr_queue_all_packets_processed(&tcp->tsr));

  zf_assert_ge(payload_len, 0);

  tcp_frequent_path_common_head(tcp, tcp_hdr);

  if( tcp->pcb.rcv_ack_sent != tcp->pcb.rcv_nxt )
    tcp_dack_flags_flick(&tcp->pcb);
}


/* \brief Performs all deferred RX processing for a TCP zocket.
 *
 * \param stack
 * \param tcp
 *
 * \return 1 if a user-visible event occurred
 *         0 otherwise
 */
int tcp_rx_flush(struct zf_stack* stack, struct zf_tcp* tcp)
{
  struct iovec* pkts;
  int count;
  int event_occurred = 0;

  zf_log_tcp_rx_trace(tcp, "%s\n", __FUNCTION__);

  /* Push all pending packets through the normal TCP RX processing. */
  while( (count = zfr_ring_peek_unprocessed(&tcp->tsr.ring, &pkts)) != 0 ) {
    zf_log_tcp_rx_trace(tcp, "%s: %p %d\n", __FUNCTION__, pkts, count);

    for( int i = 0; i < count; ++i ) {
      char* start = zf_packet_buffer_start(&stack->pool,
                                           (char*)pkts[i].iov_base);
      char* eth_hdr_base = start + stack->nic[0].rx_prefix_len;

      /* Excavate header locations and TCP payload length from scratch,
       * as pkts[i].iov_len might have been updated due to partial read */
      struct iphdr* ip_hdr = zf_ip_hdr(eth_hdr_base);
      const size_t ip_hdr_len = ip_hdr->ihl * 4;
      struct tcphdr* tcp_hdr = (struct tcphdr*) ((char*) ip_hdr + ip_hdr_len);
      size_t tcp_len = ntohs(ip_hdr->tot_len) - ip_hdr_len;
      size_t payload_len = tcp_len - BASE_TCP_HDR_LEN;

      zf_assume_ge(payload_len, 0);

      /* Make sure that this looks like a TCP header of the sort we're
       * expecting. */
      zf_assert_equal(tcp_hdr->doff, TCP_DOFF_NO_OPTIONS);
      zf_assert(tcp_hdr->ack);

      tcp_rx_flush_pkt(tcp, tcp_hdr, payload_len);
      event_occurred = 1;
    }

    zfr_zc_process_done(&stack->pool, &tcp->tsr, count);
  }

  /* All pending processing has been completed, so update the queue's state
   * accordingly. */
  zf_assert(zfr_queue_all_packets_processed(&tcp->tsr));

  /* Announced window must be updated after payload has been queued,
   * including if this happened earlier in the cut-through case. */
  tcp_update_rcv_ann_wnd(&tcp->pcb);

  event_occurred |= tcp_rx_common_tail(stack, tcp);

  /* Rebuild any allocated alternatives which have data queued
   * for this zocket. */
  zf_stack_mark_alternatives_for_rebuild(stack, tcp);

  zf_stack_tcp_clear_deferred_rx(stack, TCP_ID(stack, tcp));

  return event_occurred;
}


