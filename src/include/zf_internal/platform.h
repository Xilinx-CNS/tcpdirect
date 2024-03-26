/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_PLATFORM_H__
#define __ZF_INTERNAL_PLATFORM_H__

#include <zf/zf.h>

#if defined(__x86_64__)
# include <zf_internal/x86.h>
#else
# error Unsupported platform.
#endif

#ifdef __cplusplus
#include <type_traits>
/* There differences between C and C++, e.g. these keywords */
#define typeof(x) std::remove_reference<decltype((x))>::type
#define restrict
#define _Static_assert static_assert
#else
#define alignas(x) __attribute__((aligned(x)))
#define static_assert _Static_assert
#endif

#endif /* __ZF_INTERNAL_PLATFORM_H__ */
