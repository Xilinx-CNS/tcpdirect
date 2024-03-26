/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INT_TCP_FAST_H__
#define __ZF_INT_TCP_FAST_H__

/* Interface to rest of ZF */
struct zf_stack;
struct zf_tcp;

extern ZF_HOT void
tcp_cut_through(struct zf_tcp* tcp, char* payload, size_t payload_len);

extern ZF_COLD void tcp_cut_through_rollback(struct zf_tcp* tcp, size_t payload_len);

extern int
tcp_rx_flush(struct zf_stack* stack, struct zf_tcp* tcp);

#endif /* __ZF_INT_TCP_FAST_H__ */
