/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_RX_PACKET_H__
#define __ZF_RX_PACKET_H__

#include <zf/zf.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/muxer.h>
#include <zf_internal/utils.h>

/*
 * To better utilise cache (limited associativity) the start of the pkt buffer
 * is set to different offsets.
 * On Haswell/Sandybridge both L1 and L2 are 8-way associative. Meaning
 * Cache eviction will happen if handling 8 small consecutive PKT buffers.
 * When varying cache line this might be as much as 64
 * (assuming we use 8 different cache lines as below).
 *
 * PKT_MAX_FREE_CACHE_LINES tells how many cache lines we can spare in pkt
 * buffer and still have space for PKT data */

#if ZF_CACHE_LINE_SIZE == 64
# define PKT_MAX_FREE_CACHE_LINES 7
#elif ZF_CACHE_LINE_SIZE == 128
# define PKT_MAX_FREE_CACHE_LINES 3
#else
# error "Fix PKT_MAX_FREE_CACHE_LINES for this architecture."
#endif

/* PKT_MAX_FREE_CACHE_LINES is power of two - 1 */
_Static_assert((PKT_MAX_FREE_CACHE_LINES & (PKT_MAX_FREE_CACHE_LINES + 1)) == 0,
               "PKT_MAX_FREE_CACHE_LINES + 1 must be power of two");


/* PKT buffers start at different cache lines to better utilise cache */
#define RX_PKT_START_OFS(id) (((id) & PKT_MAX_FREE_CACHE_LINES) * \
                              ZF_CACHE_LINE_SIZE)

#define PKT_BUF_RX_START_BY_ID(pool, id) \
  (PKT_BUF_BY_ID((pool), (id)) + RX_PKT_START_OFS(id))

/* Given a pointer into a packet buffer, return a pointer to the start
 * of the received data within that buffer (taking into account the
 * cache spreading above). */
static inline char* zf_packet_buffer_start(struct zf_pool* pool, char* pktb)
{
  int buf_id = zf_packet_buffer_id(pool, pktb);
  return PKT_BUF_RX_START_BY_ID(pool, buf_id);
}


#define MIN_PKT_PAYLOAD (PKT_BUF_SIZE - \
                         RX_PKT_START_OFS(PKT_MAX_FREE_CACHE_LINES))

#define PKT_BUF_SIZE_USABLE (PKT_BUF_SIZE - (PKT_MAX_FREE_CACHE_LINES + 1) * \
                            ZF_CACHE_LINE_SIZE)

#define UDP_RX_ID(st, rx)      (rx - (st)->udp_rx)
#define UDP_TX_ID(st, tx)      (tx - (st)->udp_tx)
#define TCP_ID(st, rx)         (rx - (st)->tcp)
#define TCP_LISTEN_ID(st, rx)  (rx - (st)->tcp_listen)


/* This must not match the first dword of the packet.  Since we don't do
 * jumbos, anything that does not match our OUI will do.  When we add support
 * for detecting subsequent cache lines, there will be the possibility of
 * deciding falsely that a packet is still poisonous when in fact it is not,
 * but there is very little that we can do about that.  It would not cause a
 * functional problem in any case. */
constexpr uint32_t RX_PACKET_POISON_HEADER = 0xFFA0C09Bu;
constexpr uint64_t RX_PACKET_POISON_QWORD = 0xeddeadedfebfabcbull;

/* In debug builds, we'll also poison a little way into the packet to validate
 * our assumption that cache lines appear atomically. */
constexpr int RX_DEBUG_POISON_OFFSET = 9;

/* Poison an RX buffer so that we can detect when it's arriving from the
 * future.
 * In functions below `packet` refers to the raw packet buffer start,
 * where NIC writes either ethernet header or rx prefix.
 */
ZF_HOT static inline void
zfr_poison_packet_header(char* packet)
{
  /* Poison the first dword of the first cache line of the frame.  This is
   * useful only subject to the assumption that the presence of the first dword
   * of a received packet in host memory implies the presence of the rest of
   * the cache line. */
  *((volatile uint32_t*) packet) = RX_PACKET_POISON_HEADER;

#ifndef NDEBUG
  ((volatile uint32_t*) packet)[RX_DEBUG_POISON_OFFSET] = RX_PACKET_POISON_HEADER;
#endif
}

/* NIC fills in rx buffer up to the end of 64-byte transfer block, often beyond pkt data */
constexpr auto NIC_RX_BUFFER_WRITE_SIZE = 64u;

ZF_HOT static inline void
zfr_poison_packet(char* packet)
{
  /* Poison all the cache lines.
   * Insights:
   *  * this is off critical path,
   *  * NIC sends blocks of 64 byte even at the end of the frame,
   *    that is rounding last block up,
   *  * using a fixed poison value is not foolproof and the potential
   *    false negative can lead to a delay in packet detection. This
   *    should be extremely rare, and
   *  * to alleviate the above in some cases the last qword of NIC write
   *    block is poisoned \see zfr_packet_portion_present.
   */
  zfr_poison_packet_header(packet);
  for( unsigned i = NIC_RX_BUFFER_WRITE_SIZE - sizeof(RX_PACKET_POISON_QWORD);
       i < PKT_BUF_SIZE_USABLE;
       i += NIC_RX_BUFFER_WRITE_SIZE )
    *((volatile uint64_t*)&packet[i]) = RX_PACKET_POISON_QWORD;
}

/* Determine whether at least the first [portion_len] bytes of the given packet
 * have appeared. */
ZF_HOT static inline bool
zfr_packet_header_present(const char* packet)
{
  bool portion_present = *((volatile uint32_t*) packet) != RX_PACKET_POISON_HEADER;

#ifndef NDEBUG
  /* Check that the presence of the first dword implies the presence of a later
   * dword in the cache line. */
  zf_assume_impl(portion_present,
                 ((volatile uint32_t*) packet)[RX_DEBUG_POISON_OFFSET] !=
                   RX_PACKET_POISON_HEADER);
#endif

  return portion_present;
}

/* raw_data_len - lenght of all data in pkt buffer including rx prefix */
ZF_HOT static inline bool
zfr_packet_portion_present(const char* packet, size_t raw_data_len)
{
  uintptr_t end = (uintptr_t)packet + raw_data_len;
  zf_assume(raw_data_len);
  zf_assume_le(raw_data_len, PKT_BUF_SIZE_USABLE);
  /* Check last qword of the NIC transfer block the relevant data resides in
   * if this qword happens to lay beyond packet payload then we avoid false
   * negative as NIC filled trailing data will not match the poison value */
  end = ((end - 1) | (NIC_RX_BUFFER_WRITE_SIZE - 1)) &
                  ~(sizeof(RX_PACKET_POISON_QWORD) - 1);
  return *((volatile uint64_t*) end) != RX_PACKET_POISON_QWORD;
}

#endif /* __ZF_RX_PACKET_H__ */
