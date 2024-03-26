/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** rx/tx hw timestamping */

#ifndef __ZF_TIMESTAMPING_H__
#define __ZF_TIMESTAMPING_H__

#include <time.h>

extern "C" {
#include <etherfabric/internal/internal.h>
}

#include <zf_internal/utils.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/private/rx_packet.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/private/zf_stack_def.h>

#include <ci/driver/efab/hardware/host_ef10_common.h>


static inline int
__zfr_pkt_get_timestamp(struct zf_stack* st, const char* pkt,
                        struct timespec* ts_out, unsigned* flags_out)
{
  uint16_t nicno = *(uint16_t*)(pkt + RX_PREFIX_NICNO_OFST);

  if( nicno == RX_PREFIX_NICNO_EFCT ) {
    ts_out->tv_sec = *(uint32_t*)(pkt + RX_PREFIX_TSYNC_MAJOR_OFST);
    ts_out->tv_nsec = *(uint32_t*)(pkt + RX_PREFIX_TSYNC_MINOR_OFST);
    *flags_out = *(uint16_t*)(pkt + RX_PREFIX_TS_FLAGS_OFST);
    return -(*(uint16_t*)(pkt + RX_PREFIX_TS_RESULT_OFST));
  }

  zf_assume_lt(nicno, st->nics_n);
  zf_assume_equal(st->nic[nicno].rx_prefix_len, ES_DZ_RX_PREFIX_SIZE);

  ef_vi* vi = &st->nic[nicno].vi;

  uint32_t tsync_minor = *(uint32_t*)(pkt + RX_PREFIX_TSYNC_MINOR_OFST);
  uint32_t tsync_major = *(uint32_t*)(pkt + RX_PREFIX_TSYNC_MAJOR_OFST);

  /* Call ..._internal directly as we store the current timesync
   * values in the packet not the evq */
  return ef10_receive_get_timestamp_with_sync_flags_internal
    (vi, pkt, ts_out, flags_out, tsync_minor, tsync_major);
}


template<typename Zocket, typename ZocketMsg>
ZF_HOT static int
zfr_pkt_get_timestamp(Zocket* zfr, const ZocketMsg* restrict msg,
                     struct timespec* ts_out, int pktind, unsigned* flags)
{
  zf_assume(pktind >= 0 && pktind < msg->iovcnt);

  zf_stack* st = zf_stack_from_zocket(zfr);
  /* note below we access appropriate iovec through pointe arithmetic.
   * Using brackets [] would trigger -Warray-bounds. */
  char* pkt = zf_packet_buffer_start(&st->pool,
                                     (char*) (msg->iov + pktind)->iov_base);

  return __zfr_pkt_get_timestamp(st, pkt, ts_out, flags);
}

#endif
