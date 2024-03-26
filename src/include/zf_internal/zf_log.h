/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_LOG_H__
#define __ZF_LOG_H__

#include <stdarg.h>
#include <stdio.h>

static const uint64_t ZF_LL_ERR = 0x1;
static const uint64_t ZF_LL_WARN = 0x2;
static const uint64_t ZF_LL_INFO = 0x4;
static const uint64_t ZF_LL_TRACE = 0x8;
#define ZF_LL_NUM_LEVELS 4

enum zf_log_fmt_flags {
  ZF_LF_STACK_NAME = 0x1,
  ZF_LF_FRC  = 0x2,
  ZF_LF_TCP_TIME  = 0x4,
  ZF_LF_PROCESS  = 0x8,
};


enum zf_log_comp {
  ZF_LC_STACK,
  ZF_LC_TCP_RX,
  ZF_LC_TCP_TX,
  ZF_LC_TCP_CONN,
  ZF_LC_UDP_RX,
  ZF_LC_UDP_TX,
  ZF_LC_UDP_CONN,
  ZF_LC_MUXER,
  ZF_LC_POOL,
  ZF_LC_EVENT,
  ZF_LC_TIMER,
  ZF_LC_FILTER,
  ZF_LC_CPLANE,
  ZF_LC_RX,
  ZF_LC_SOCKET_SHIM,
  ZF_LC_EMU,
  ZF_LC_NUM_COMPONENTS,
};

/* Attribute default: log component-level for ZF_LL_ERR on all components */
#define ZF_LCL_BIT(level, comp) (level << (comp * ZF_LL_NUM_LEVELS))
#define ZF_LCL_ALL_ERR ( ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_STACK) |       \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_TCP_RX) |      \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_TCP_TX) |      \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_TCP_CONN) |    \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_UDP_RX) |      \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_UDP_TX) |      \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_UDP_CONN) |    \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_MUXER) |       \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_POOL) |        \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_EVENT) |    \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_TIMER) |       \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_FILTER) |      \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_CPLANE) |      \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_RX) |          \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_SOCKET_SHIM) | \
                         ZF_LCL_BIT(ZF_LL_ERR, ZF_LC_EMU) )

_Static_assert(ZF_LC_NUM_COMPONENTS * ZF_LL_NUM_LEVELS <= 64,
               "64-bit mask is not large enough for all components and levels");


extern uint64_t zf_log_level;
extern int zf_log_format;

struct zf_stack;
static constexpr zf_stack* NO_STACK = NULL;

class zf_logger
{
  private:
    const uint64_t log_comp_level;
  public:
    zf_logger(int comp, uint64_t level) :
        log_comp_level(ZF_LCL_BIT(level, comp))
        {}
    template <typename T> ZF_VISIBLE void operator()(T obj, const char* fmt,
                                                     ...) const;
    ZF_VISIBLE void operator()(const char* fmt, va_list v) const;
};

/* Emit message to log unconditionally. */
ZF_LIBENTRY ZF_COLD void zf_log(struct zf_stack*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));

ZF_COLD void zf_dump(const char* fmt, ...);
ZF_COLD int zf_log_replace_stderr(const char* file);
ZF_COLD int zf_log_redirect(const char* file);
ZF_COLD void zf_log_stderr(void);

#ifndef NDEBUG
void zf_backtrace();
#else
#define zf_backtrace() do{}while(0)
#endif

#endif
