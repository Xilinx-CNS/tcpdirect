/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF rx - socket rx fast path */

#ifndef __ZF_RX_H__
#define __ZF_RX_H__

#include <zf/zf.h>
#include <zf_internal/rx_types.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/muxer.h>
#include <zf_internal/utils.h>
#include <zf_internal/private/rx_packet.h>

#include <netinet/in.h>


/* Returns the (unmasked) index of the first packet in the ring, whether unread
 * or unprocessed. */
ZF_HOT static inline uint32_t
zfr_tcp_queue_first_packet(struct zf_rx_ring* ring)
{
  /* Note that MIN(begin_read, begin_process) would be wrong: it fails to
   * account for wraparound. */
  if( ring->begin_process - ring->begin_read <= SW_RECVQ_MAX )
    return ring->begin_read;
  return ring->begin_process;
}


/* Returns the (unmasked) index of the 'middle' packet in the ring: that is,
 * of the *newer* of the two of the next unread and the next unprocessed
 * packet.  This is useful as it gives an upper bound on the packets that may
 * be freed. */
ZF_HOT static inline uint32_t
zfr_tcp_queue_middle_packet(struct zf_rx_ring* ring)
{
  /* Note that MAX(begin_read, begin_process) would be wrong: it fails to
   * account for wraparound. */
  if( ring->begin_process - ring->begin_read <= SW_RECVQ_MAX )
    return ring->begin_process;
  return ring->begin_read;
}


ZF_HOT static inline bool
zfr_tcp_queue_has_space(struct zf_rx_ring* ring)
{
  zf_assume_le(ring->end - ring->begin_read, SW_RECVQ_MAX);
  zf_assume_le(ring->end - ring->begin_process, SW_RECVQ_MAX);

  return ring->end - zfr_tcp_queue_first_packet(ring) < SW_RECVQ_MAX;
}


ZF_HOT static inline bool
zfr_udp_queue_has_space(struct zf_rx_ring* ring)
{
  zf_assume_le(ring->end - ring->begin_process, SW_RECVQ_MAX);

  return ring->end - ring->begin_process < SW_RECVQ_MAX;
}


ZF_HOT static inline void
__zfr_pkt_queue(struct zf_rx_ring* ring, uint32_t index,
                struct iovec* restrict pkt)
{
  zf_assume_lt(index, SW_RECVQ_MAX);
  ring->pkts[index] = *pkt;
}


ZF_HOT static inline void
zfr_pkt_queue(struct zf_rx_ring* ring, struct iovec* restrict pkt)
{
  zf_assume_lt(ring->end - ring->begin_read, SW_RECVQ_MAX);
  __zfr_pkt_queue(ring, ring->end & SW_RECVQ_MASK, pkt);
  ++ring->end;
}


/* Returns in *pkts a pointer straight into the RX ring.  The return value is
 * the number of packets that the caller may read.  There is no guarantee that
 * all available packets are returned.  If the caller cares about exhausting
 * the ring, they should keep calling until the return value is zero. */
ZF_HOT static inline int
__zfr_ring_peek(struct zf_rx_ring* ring, struct iovec* restrict * pkts,
                uint32_t start)
{
  zf_assume_le(ring->end - start, SW_RECVQ_MAX);
  *pkts = ring->pkts + (start & SW_RECVQ_MASK);
  /* we need to break at wrap around */
  return MIN(ROUND_UP(start + 1, SW_RECVQ_MAX) - start, ring->end - start);
}


/* Returns a pointer into the RX ring beginning at the first packet in the
 * ring, regardless of whether that packet has been read or processed. */
ZF_HOT static inline int
zfr_ring_peek_all(struct zf_rx_ring* ring, struct iovec* restrict * pkts)
{
  return __zfr_ring_peek(ring, pkts, zfr_tcp_queue_first_packet(ring));
}


/* Returns a pointer into the RX ring beginning at the first unprocessed
 * packet. */
static inline int
zfr_ring_peek_unprocessed(struct zf_rx_ring* ring,
                          struct iovec* restrict * pkts)
{
  return __zfr_ring_peek(ring, pkts, ring->begin_process);
}


/* Returns a pointer into the RX ring beginning at the first unread
 * packet. */
static inline int
zfr_ring_peek_unread(struct zf_rx_ring* ring,
                     struct iovec* restrict * pkts)
{
  return __zfr_ring_peek(ring, pkts, ring->begin_read);
}


/* Copies iovecs out of an RX ring into a linear buffer. */
ZF_HOT static inline void
zf_copy_iovecs_from_rx_ring(struct iovec* linear_dest,
                            struct iovec* restrict ring_src, uint32_t start,
                            uint32_t count)
{
  uint32_t end = start + count;
  while( start != end )
    *linear_dest++ = ring_src[start++ & SW_RECVQ_MASK];
}


/* Copies references to unread packets in the RX ring into an array of iovecs.
 * The packets are not removed from the ring.  Wrap-around is handled. */
ZF_HOT static inline void
zfr_pkts_peek(struct zf_rx_ring* ring, struct iovec* restrict pkts,
              unsigned* count)
{
  zf_assume_le(ring->end - ring->begin_read, SW_RECVQ_MAX);
  *count = MIN(ring->end - ring->begin_read, (uint32_t) *count);
  zf_copy_iovecs_from_rx_ring(pkts, ring->pkts, ring->begin_read, *count);
}


ZF_HOT static inline void
__zfr_zc_free_pkts(zf_pool* pool, zf_rx* rx, uint32_t begin, uint32_t count)
{
  /* zf_pool_free_pkts() requires a linear buffer, so if we wrap around, we'll
   * need to split into two. */
  uint32_t batch = MIN(ROUND_UP(begin + 1, SW_RECVQ_MAX) - begin, count);
  zf_assume_le(batch, count);

  zf_pool_free_pkts(pool, &rx->ring.pkts[begin & SW_RECVQ_MASK], batch);
  zf_pool_free_pkts(pool, &rx->ring.pkts[0], count - batch);
}


/* Don't free packets that are still awaiting protocol processing. */
#define ZFR_ZC_KEEP_UNPROCESSED     0x00000001u

/* Removes packets from the ring after a ZC read operation, and frees them if
 * necessary. */
ZF_HOT static inline void
zfr_zc_read_done(zf_pool* pool, zf_rx* rx, uint32_t release_n, uint32_t flags)
{
  zf_assume(release_n);

  /* If we are keeping unprocessed packets, don't free beyond the beginning of
   * the unprocessed chunk.  Otherwise, we can free right to the end. */
  uint32_t end = (flags & ZFR_ZC_KEEP_UNPROCESSED) ?
                   zfr_tcp_queue_middle_packet(&rx->ring) : rx->ring.end;

  /* In any case, don't free more than we're releasing. */
  uint32_t free_n = MIN((uint32_t) release_n, end - rx->ring.begin_read);

  __zfr_zc_free_pkts(pool, rx, rx->ring.begin_read, free_n);

  /* We always release (i.e. mark as read) all requested packets. */
  zf_assume_le((uint32_t) release_n, rx->ring.end - rx->ring.begin_read);
  rx->ring.begin_read += release_n;
}


/* Removes packets from the ring after a ZC processing operation (i.e. after a
 * call to zfr_ring_peek_unprocessed()), and frees them if necessary. */
static inline void
zfr_zc_process_done(zf_pool* pool, struct zf_rx* rx, uint32_t release_n)
{
  zf_assume(release_n);

  /* Free the lesser of the number to released and the number unread. */
  uint32_t free_n = MIN((uint32_t) release_n,
                        zfr_tcp_queue_middle_packet(&rx->ring) -
                          rx->ring.begin_process);

  __zfr_zc_free_pkts(pool, rx, rx->ring.begin_process, free_n);

  /* We always release (i.e. mark as processed) all requested packets. */
  zf_assume_le((uint32_t) release_n, rx->ring.end - rx->ring.begin_process);
  rx->ring.begin_process += release_n;
}


static inline void
zfr_queue_mark_processed(struct zf_rx* rx)
{
  rx->ring.begin_process = rx->ring.end;
}


static inline bool
zfr_queue_all_packets_processed(struct zf_rx* rx)
{
  return rx->ring.begin_process == rx->ring.end;
}


ZF_HOT static inline bool
zfr_queue_all_packets_read(struct zf_rx* rx)
{
  return rx->ring.begin_read == rx->ring.end;
}

ZF_HOT static inline uint32_t
zfr_queue_packets_unread_n(struct zf_rx* rx)
{
  return rx->ring.end - rx->ring.begin_read;
}


#endif /* __ZF_RX_H__ */
