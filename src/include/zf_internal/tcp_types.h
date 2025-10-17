/* SPDX-License-Identifier: BSD-3-Clause */
/* SPDX-FileCopyrightText: (c) 2016-2020 Advanced Micro Devices, Inc. */
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
#ifndef __ZF_INTERNAL_TCP_TYPES_H__
#define __ZF_INTERNAL_TCP_TYPES_H__

#include <zf_internal/utils.h>
#include <zf_internal/tcp_opt.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/timers.h>
#include <zf_internal/timekeeping_types.h>
#include <zf_internal/rx_types.h>
#include <zf_internal/private/rx_packet.h>

#include <sys/uio.h>
#include <netinet/tcp.h>


/* Flags used on input processing, not on pcb->flags */
#define TF_ABORT     (uint8_t)0x01U   /* Need to call tcp_abort(). */
#define TF_OOO       (uint8_t)0x04U   /* Packet received out-of-order. */
#define TF_RESET     (uint8_t)0x08U   /* Connection was reset. */
#define TF_CLOSED    (uint8_t)0x10U   /* Connection was sucessfully closed. */
#define TF_GOT_FIN   (uint8_t)0x20U   /* Connection was closed by the remote. */
#define TF_ACCEPTQ   (uint8_t)0x40U   /* Zocket entered the acceptq. */

/* Flags to request TCP options */
#define TF_SEG_OPTS_MSS         (uint8_t)0x01U /* Include MSS option. */

#define TCP_SEQ_SUB(a,b)    ((int32_t)((uint32_t)(a) - (uint32_t)(b)))
#define TCP_SEQ_LT(a,b)     ((int32_t)((uint32_t)(a) - (uint32_t)(b)) < 0)
#define TCP_SEQ_LEQ(a,b)    ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <= 0)
#define TCP_SEQ_GT(a,b)     ((int32_t)((uint32_t)(a) - (uint32_t)(b)) > 0)
#define TCP_SEQ_GEQ(a,b)    ((int32_t)((uint32_t)(a) - (uint32_t)(b)) >= 0)
#define TCP_SEQ_BETWEEN(a,b,c) (TCP_SEQ_GEQ(a,b) && TCP_SEQ_LEQ(a,c))


struct tcp_pcb;

enum tcp_state {
  CLOSED      = 1u << TCP_CLOSE,
  LISTEN      = 1u << TCP_LISTEN,
  SYN_SENT    = 1u << TCP_SYN_SENT,
  SYN_RCVD    = 1u << TCP_SYN_RECV,
  ESTABLISHED = 1u << TCP_ESTABLISHED,
  FIN_WAIT_1  = 1u << TCP_FIN_WAIT1,
  FIN_WAIT_2  = 1u << TCP_FIN_WAIT2,
  CLOSE_WAIT  = 1u << TCP_CLOSE_WAIT,
  CLOSING     = 1u << TCP_CLOSING,
  LAST_ACK    = 1u << TCP_LAST_ACK,
  TIME_WAIT   = 1u << TCP_TIME_WAIT,
};
#define SEND_STATE_MASK (SYN_SENT | SYN_RCVD | ESTABLISHED | CLOSE_WAIT)
#define FAST_SEND_STATE_MASK (ESTABLISHED | CLOSE_WAIT)
#define FIN_WAIT_STATE_MASK (FIN_WAIT_1 | FIN_WAIT_2 | CLOSING | LAST_ACK)

#define IP_HLEN  (sizeof(struct iphdr))
#define VLAN_HLEN 4
#define ETH_IP_HLEN (sizeof(struct ethhdr) + sizeof(struct iphdr))
#define TCP_HLEN (sizeof(struct tcphdr))

/* Types of timers */
enum zf_tcp_timer_type {
  ZF_TCP_TIMER_RTO,
  ZF_TCP_TIMER_SYN = ZF_TCP_TIMER_RTO,
  ZF_TCP_TIMER_DACK,
  ZF_TCP_TIMER_ZWIN,
  ZF_TCP_TIMER_TIMEWAIT,
  ZF_TCP_TIMER_FINWAIT = ZF_TCP_TIMER_TIMEWAIT,
  ZF_TCP_TIMER_COUNT,
};
#define ZF_TCP_ALL_TIMERS ( (1u<<ZF_TCP_TIMER_COUNT) - 1)


#define ZF_TCP_INITIAL_SSTHRESH(pcb)   ((uint16_t)-1)


/* This structure represents a TCP segment on the unsent and unacked queues */
struct tcp_seg {
  struct iovec iov;        /* The TCP header and payload */
  uint16_t len;            /* The payload length of this segment (note not the
                            * sequence space length - the tcp_seg_len function
                            * is used to determine the amount of sequence space
                            * used by a segment.
                            */
  bool in_flight;          /* Is the packet in flight? */
};

/* Check that our queue is large enough to contain our full advertised window,
 * after reserving an entry for the EOF marker.
 */
static_assert(TCP_WND <= ((PKT_BUF_SIZE_USABLE - 54) * (SW_RECVQ_MAX - 1)),
              "TCP receive queue not large enough to satisfy window");

static constexpr unsigned TCP_SND_QUEUE_SEG_COUNT = TCP_SND_QUEUELEN;

static_assert((TCP_SND_QUEUE_SEG_COUNT & (TCP_SND_QUEUE_SEG_COUNT - 1)) == 0,
              "TCP_SND_QUEUE_SEG_COUNT must be power of 2");

template<typename T>
constexpr T type_mask() {
  /* Construct the mask carefully to avoid an overflow. We can fill all but the
   * highest bit by setting the highest bit and subtracting 1 from that value.
   * After which we can directly set the highest bit to have all 1s. */
  constexpr T lowest_set = 1;
  constexpr auto t_bits = 8 * sizeof(T);
  constexpr T highest_set = lowest_set << (t_bits - 1);
  constexpr T all_but_highest_set = highest_set - 1;
  constexpr T all_set = all_but_highest_set | highest_set;
  return all_set;
}

struct tcp_send_queue {
  /* Represents send queue.
   * The queue is stored in a ring based on tcp_seg array, and
   * three pointers, which delimit the queue and split it into two parts:
   * * [begin, middle> - sent, but unacked data
   * * [middle, end> - unsent data
   * A new unsent segment is put at the end the end is moved forward.
   * When segments gets sent, the middle pointer is moved to the first unsent one.
   * and making at the same time the segments it moved over as ones blonging to
   * unacked queue now.
   * Finally, when ack arrives the begin pointer is moved, and segments
   * left behind the pointer need to be freed (e.g. pkt buffers released).
   */
  typedef uint16_t idx;
#define TCP_SND_QUEUE_IDX_MASK (type_mask<tcp_send_queue::idx>())
  idx begin;
  idx middle;
  idx end;
  struct tcp_seg segs[TCP_SND_QUEUE_SEG_COUNT];
};

/* Out-of-order packet list contains non-empty, disjoint segments that
 * are ordered by TCP sequence number.
 */
struct tcp_ooo_pkt {
  ci_dllink ooo_pkt_link;
  struct iovec pkt;
};

/* TCP protocol control block
 * All fields are in host byte order.
 */
struct tcp_pcb {
  /* Members used on the cut-through path are placed in the same cache line */
  enum tcp_state state alignas(ZF_CACHE_LINE_SIZE); /* TCP state */
  uint32_t rcv_nxt;   /* next seqno expected */
  uint32_t snd_nxt;   /* next new seqno to be sent */
  uint32_t lastack; /* Highest acknowledged seqno. */
  uint32_t rd_nxt;   /* next seqno to read */

  /* Remaining members are only used off the cut-through path */

  uint32_t snd_iss;      /* initial sequence sent */
  uint32_t rcv_ack_sent; /* highest received sequence for which ack sent */

  uint16_t local_port;
  uint16_t remote_port;
  
  uint16_t flags;
#define TF_ACK_DELAY   ((uint16_t)0x01U)   /* Delayed ACK. */
#define TF_ACK_NOW     ((uint16_t)0x02U)   /* Immediate ACK. */
#define TF_INFR        ((uint16_t)0x04U)   /* In fast recovery. */
#define TF_ACK_NEXT    ((uint16_t)0x08U)   /* ACK next segment immediately. */
/* 0x40u and 0x80u are available for reuse. */
#define TF_ON          ((uint16_t)0x100U) /* hack: flag is always on */
#define TF_FASTSEND_DBG ((uint16_t)0x200U) /* tracks fast send precomputation */

  /* Flags to be used when we want to delay ACK:
   * - if delayed ACK is enabled (default), this is TF_ACK_NEXT;
   * - otherwise, this field is (TF_ACK_NEXT | TF_ON)
   */
  uint16_t flags_ack_delay;

  /* receiver variables */
  uint16_t rcv_ann_wnd; /* receiver window to announce */
  uint32_t rcv_ann_right_edge; /* announced right edge of window */

  uint16_t mss_lim; /* maximum segment size - limit received from peer */
  uint16_t mss;     /* maximum segment size - is use now */
  uint16_t fast_send_len;
  pkt_id   fast_pkt; /* pre-allocated buffer to ensure success on fast send */

  /* RTT (round trip time) estimation variables */
  zf_tick rttest; /* RTT estimate in ticks */
  uint32_t rtseq;  /* sequence number being timed */
  int16_t sa, sv; /* @todo document this */

  struct {
    uint8_t running; /* Bitmask of running timers as in zf_tcp_timer_type */
    /* token the timer was installed with or ZF_WHEEL_EXPIRED_TIMER */
    zf_timer_token token;
    /* Expiry times of all the timers (if running) */
    zf_tick expiry[ZF_TCP_TIMER_COUNT];
  } timers;

  uint8_t nrtx;    /* current number of retransmissions */
  uint8_t persist_backoff; /* number of subsequent zwin probe retries */

  /* fast retransmit/recovery */
  uint8_t dupacks;

  /* congestion avoidance/control variables */
  uint16_t cwnd;
  uint16_t ssthresh;

  /* sender variables */
  uint32_t snd_wl1, snd_wl2; /* Sequence and acknowledgement numbers of last
                                window update. */
  uint32_t snd_lbb;       /* Sequence number of next byte to be buffered. */
  uint32_t snd_right_edge;/* Right edge of sender window */
  int32_t  snd_delegated; /* Bytes reserved by user of delegated send API */
  uint16_t snd_wnd_max;   /* the maximum sender window announced by the peer */

  /* Bytes can be added to send queue: calculated based on send queue
   * depth, TCP_SND_QUEUELEN limit and mss value. */
  uint32_t snd_buf;
  uint32_t snd_buf_advertisement_threshold;

  /* The listening zocket that spawned this one, or ZF_LISTEN_ZOCKET_ID_INVALID
  */
  uint16_t parent_listener;
  union {
    uint16_t listenq_index;
    uint16_t acceptq_next;
  };

  tcp_send_queue sendq;

  uint32_t error; /* error if happened */
  enum tcp_state mediated_state;  /* Detect invalid state transitions - debug only. */

  ci_dllist ooo_pkts;
  uint32_t ooo_added;
  uint32_t ooo_removed;
  uint32_t ooo_replaced;
  uint32_t ooo_dropped_nomem;
  uint32_t ooo_handling_deferred;
  uint32_t ooo_drop_overfilled;
  struct {
    int msg_more_send_delayed;
    int send_nomem;
    uint32_t retransmits;    /* total number of retransmissions */
  } stats;
};


#define TCP_DOFF_NO_OPTIONS 5

/* Header length for packets without options */
static constexpr int BASE_TCP_HDR_LEN = 20;

#endif /* __ZF_INTERNAL_TCP_TYPES_H__ */
