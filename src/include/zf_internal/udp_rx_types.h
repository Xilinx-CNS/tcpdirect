/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INT_UDP_RX_TYPES_H__
#define __ZF_INT_UDP_RX_TYPES_H__

#include <zf/zf_udp.h>
#include <zf_internal/rx_types.h>
#include <zf_internal/muxer.h>


struct zf_udp_rx {
  struct zfur handle;
  struct zf_rx rx;
  struct zf_waitable w;
  uint64_t zocket_mask;
  struct {
    uint32_t q_drops;
  } counters;
};


#endif /* __ZF_INT_UDP_RX_TYPES_H__ */
