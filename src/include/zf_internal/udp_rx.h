/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INT_UDP_RX_H__
#define __ZF_INT_UDP_RX_H__

#include <zf_internal/udp_rx_types.h>
#include <zf_internal/rx.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/zf_stackdump.h>

/* Note on UDP use of zf_rx_ring
 * The relation between ring pointers is begin_process <= begin_read <= end.
 *  - `end` pointer point to the first free entry (where the next received packet will go)
 *    as expected.
 *  - `begin_read` points to the next buffer user will obtain for reading
      (or == `end` if no such buffer)
 *  - `begin_process` points to the oldest unfreed buffer.
 *    Buffers between `begin_process` and `begin_read` are already read and pending
 *    removal on next \see zf_stack_udp_rx_flush.
 *    \see `zf_udp_rx::release_n` shows how many most recent buffers (after `begin_read`)
 *    user is looking at (obtained through `zfur_zc_recv`) at this moment.
 */

#ifndef NDEBUG
static const zf_logger zf_log_udp_rx_trace(ZF_LC_UDP_RX, ZF_LL_TRACE);
#else
#define zf_log_udp_rx_trace(...) do{}while(0)
#endif


static inline unsigned zf_udp_rx_max_pkt_bufs_usage(zf_stack* st)
  { return SW_RECVQ_MAX;  }


ZF_COLD extern void zfur_dump(SkewPointer<zf_stack>, SkewPointer<zf_udp_rx>);



ZF_HOT static inline void
zfr_zc_read(zf_pool* pool, zf_udp_rx* udp_rx, struct zfur_msg* restrict msg)
{
  struct zf_rx* rx = &udp_rx->rx;

  /* This API call is currently restricted to returning a single
   * datagram.  We don't support fragmenting datagrams across iovecs.
   * The underlying implementation can handle multiple iovecs, so we
   * can achieve the API restriction by pretending the caller only
   * provided a single iovec
   */
  zf_assert_gt(msg->iovcnt, 0);
  unsigned iovcnt = 1;
  zfr_pkts_peek(&rx->ring, msg->iov, &iovcnt);
  /* This is currently returning number of iovecs left, but we don't
   * support fragmenting datagrams, so the two are the same.
   */
  msg->dgrams_left = zfr_queue_packets_unread_n(rx) - iovcnt;

  rx->release_n = iovcnt;
  msg->iovcnt = iovcnt;
}

/* works only when ring's begin_processed <= begin_read < end
 * This is equivalent to:
 *   zfr_zc_read_done(NULL, rx, rx->release_n, ZFR_ZC_KEEP_UNPROCESSED);
 *   rx->release_n = 0;
 * Rewritten due to lack of trust in compiler optimizing out the code.
 */
ZF_HOT static inline void
zfr_zc_read_done_udp(zf_rx* rx)
{
  zf_rx_ring* ring = &rx->ring;
  zf_assume_le(ring->begin_read - ring->begin_process, SW_RECVQ_MAX);
  zf_assume_ge(ring->end - ring->begin_read, rx->release_n);
  zf_assume(rx->release_n);
  ring->begin_read += rx->release_n;
  rx->release_n = 0;
}


#endif /* __ZF_INT_UDP_RX_H__ */
