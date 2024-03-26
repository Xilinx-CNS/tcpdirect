/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_STACK_COMMON_H__
#define __ZF_INTERNAL_STACK_COMMON_H__

#include <zf_internal/stack_params.h>

#define ZF_STACK_NAME_SIZE 20 /* (IF_NAMESIZE + 4) */

typedef uint8_t zf_stack_flag;

struct zf_stack_config {
  int tcp_timewait_ticks;
  int tcp_finwait_ticks;
  int ctpio_threshold;
};


static const zf_logger zf_log_stack_err(ZF_LC_STACK, ZF_LL_ERR);
static const zf_logger zf_log_stack_warn(ZF_LC_STACK, ZF_LL_WARN);
static const zf_logger zf_log_stack_info(ZF_LC_STACK, ZF_LL_INFO);

#ifndef NDEBUG
static const zf_logger zf_log_stack_trace(ZF_LC_STACK, ZF_LL_TRACE);
#else
#define zf_log_stack_trace(...)  do{}while(0)
#endif

/* Only compile the event logging in the debug build */
#ifndef NDEBUG
static const zf_logger zf_log_event_err(ZF_LC_RX, ZF_LL_ERR);
static const zf_logger zf_log_event_warn(ZF_LC_RX, ZF_LL_WARN);
static const zf_logger zf_log_event_trace(ZF_LC_RX, ZF_LL_TRACE);
#else
#define zf_log_event_err(...) do{}while(0)
#define zf_log_event_warn(...) do{}while(0)
#define zf_log_event_trace(...) do{}while(0)
#endif

extern int zf_stack_free_nic_resources(struct zf_stack_impl* sti, int nicno);

#endif /* __ZF_INTERNAL_STACK_COMMON_H__ */
