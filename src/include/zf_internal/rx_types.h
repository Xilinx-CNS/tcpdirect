/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_RX_TYPES_H__
#define __ZF_INTERNAL_RX_TYPES_H__

#include <zf_internal/private/rx_packet.h>

#include <netinet/in.h>

#define SW_RECVQ_MAX  64u
#define SW_RECVQ_MASK (SW_RECVQ_MAX - 1u)
static_assert(ZF_IS_POW2(SW_RECVQ_MAX), "SW_RECVQ_MAX is not a power of two");

#define MAX_PREFIX_LEN 14
#define STANDARD_MTU 1500

/* Offsets for the prefix interpretation in case of RX timestamping. */
#define RX_PREFIX_TSYNC_MINOR_OFST 0
#define RX_PREFIX_TSYNC_MAJOR_OFST 4
#define RX_PREFIX_NICNO_OFST       8
#define RX_PREFIX_TS_FLAGS_OFST   10
#define RX_PREFIX_TS_RESULT_OFST  12

/* Special value to indicate an EFCT NIC. In that case, the timestamp is in
 * the TSYNC fields, and no further access to the NIC or VI is needed. */
#define RX_PREFIX_NICNO_EFCT  0xffff

_Static_assert(MIN_PKT_PAYLOAD >= STANDARD_MTU + MAX_PREFIX_LEN,
               "Standard MTU pkt will not fit into a single pkt buffer");

/* RX rings are truly rings, in that their associated pointers, when
 * dereferenced, are always interpreted modulo the ring-size.  However, the
 * same is not true when they are used in arithmetic expressions.  This allows
 * us to distinguish full rings from empty ones.
 *
 * Three pointers are maintained:
 *
 *   - end:           one beyond last packet in ring
 *   - begin_read:    next packet in ring to be read
 *   - begin_process: next packet in ring to be processed
 *
 * In the way TCP uses begin_process it is always the case that
 *   0 <= end - x <= SW_RECVQ_MAX,
 * where x is either begin_read or (if used) begin_process.  However, there is
 * no ordering restriction on those pointers with respect to one another.
 *
 * In UDP:
 *  * begin_process <= begin_read <= end
 *  * 0 <= begin_process - end <= SW_RECVQ_MAX
 * \see udp_rx.h for more details.
 */
struct zf_rx_ring {
  /* This state being iovec might make things really efficient, as we do not
   * even need to copy metadata - just pass the pointer instead up to the ZF
   * direct client.
  */
  uint32_t begin_read;    /* Equal modulo the ring-size to the index of the
                           * oldest buffer in [pkts] not yet read. */
  uint32_t begin_process; /* Equal modulo the ring-size to the index of the
                           * oldest buffer in [pkts] not yet processed. */
  uint32_t end;           /* Equal to [begin_read] plus the number of packets
                           * in the ring not yet read (and likewise for
                           * [begin_process]. */
  /* TCP Notes.
   * iov_base points to first byte of segment's tcp payload unread by the client,
   * while iov_len reflects number of unread bytes.
   *
   * Note: both iov_base and iov_len initially are derived from
   *       tcp/ip headers.  However, they can be modified in result of user reads
   *       (zft_recv(), zft_zc_recv_done_some()),
   *       making these values not reliable for TCP processing.
   *       Later, these values can be further modified during compacting process
   */
  struct iovec pkts[SW_RECVQ_MAX];
};

/**
 * \brief state needed by fast path to receive packets
 * 
 * Covers sw filter and socket receive queue.
 */
struct zf_rx {
  /* Number of packets starting from [ring.begin_read] owned by the application
   * as part of a zero-copy-receive operation. */
  uint32_t release_n;

  /* ring with rx buffers
   *
   * TODO With single thread we could wrap the buffer
   *      early to keep working set neat.
   *
   * Avoiding lists and state in pkt buffers should optimize working set.
   */
  struct zf_rx_ring ring;
};


#define ZFR_ZC_KEEP_UNPROCESSED     0x00000001u


#endif /* __ZF_INTERNAL_RX_TYPES_H__ */
