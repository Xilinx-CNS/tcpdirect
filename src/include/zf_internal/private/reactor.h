/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  gd
**  \brief  Multiplexer.
**   \date  2015/11/19
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ZF_INTERNAL_REACTOR_H__
#define __ZF_INTERNAL_REACTOR_H__


#include <zf/zf.h>


constexpr int ZF_REACTOR_PFTF = 2;

extern ZF_HOT int
zf_reactor_wait_for_rx_event(struct zf_stack*, int nic, pkt_id packet_id,
                             uint16_t frame_len);

extern ZF_HOT int zf_pftf_wait(zf_stack* st, unsigned len);

extern ZF_HOT int zf_reactor_process_event(struct zf_stack* st, int nic,
                                           ef_vi* vi, ef_event* ev);

#endif /* __ZF_INTERNAL_REACTOR_H__ */
