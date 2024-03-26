/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INT_UDP_TX_H__
#define __ZF_INT_UDP_TX_H__

#include <zf_internal/tx_types.h>
#include <zf_internal/zf_stackdump.h>

#include <netinet/tcp.h>

struct zf_udp_tx {
  struct zfut handle;
  struct zf_tx tx;
  struct zf_waitable w;
  ci_sllink pollout_req;
  uint32_t packet_count;
};

#define UDP_HLEN (sizeof(struct udphdr))

static inline unsigned zf_udp_tx_max_pkt_bufs_usage(zf_stack* st)
  { return 0;  }


ZF_COLD extern void zfut_dump(SkewPointer<zf_stack>, SkewPointer<zf_udp_tx>);


#ifndef NDEBUG
static const zf_logger zf_log_udp_tx_trace(ZF_LC_UDP_TX, ZF_LL_TRACE);
#else
#define zf_log_udp_tx_trace(...) do{}while(0)
#endif

#endif /* __ZF_INT_UDP_TX_H__ */
