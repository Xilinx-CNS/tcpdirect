/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF x86-specific internal definitions. */

#ifndef __ZF_INTERNAL_X86_H__
#define __ZF_INTERNAL_X86_H__

#include <zf/sysdep/x86.h>
#include <x86intrin.h>

static constexpr unsigned HUGE_PAGE_SIZE = 1u << 21;


static inline uint64_t zf_frc64(void)
{
  return __rdtsc();
}


extern ZF_COLD uint64_t zf_frc64_get_frequency(void);

#endif /* __ZF_INTERNAL_X86_H__*/
