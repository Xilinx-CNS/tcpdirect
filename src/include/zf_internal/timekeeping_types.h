/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_TIMEKEEPING_TYPES_H__
#define __ZF_INTERNAL_TIMEKEEPING_TYPES_H__

#include <zf_internal/platform.h>

typedef uint64_t zf_frc;
typedef uint16_t zf_tick;
typedef uint64_t zf_tick_fxp32;

/* state allowing time conversion between frc, tick and ms,
 * Also tracks ticks elapsed maintaining small drift even when
 * zf_timekeeping_check_tick is called irregularly.
 */
struct zf_timekeeping {
    zf_frc frcs_in_tick;
    zf_frc frcs_in_ms;

    /* For quick calculations of FRCs-in-x-nanos, remember the number of FRCs
     * in a mibinanosecond. */
    static constexpr int MIBINANO_TO_NANO_SHIFT = 20;
    zf_frc frcs_in_mibinano;

/* fixed point value (most likely much smaller than 1) */
    zf_tick_fxp32 ticks_in_frc_fxp32;
    zf_frc last_tick_frc;
};
typedef struct zf_timekeeping zf_timekeeping;


#endif /* __ZF_INTERNAL_TIMEKEEPING_TYPES_H__ */
