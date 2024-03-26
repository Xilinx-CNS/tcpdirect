/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/*
 * To measure timing at nsec precision using stable tsc counter
 */
#ifndef ZF_APPS_TIMER_H
#define ZF_APPS_TIMER_H

#include <x86intrin.h>
#include <stdint.h>

inline uint64_t get_frc64_time(void)
{
  return __rdtsc();
}

void init_tsc_frequency(void);

/* Given TSC ticks it will calculate and return number of nano seconds passed for it. 
 * @frc TSC ticks observed on CPU
 * @return nano seconds represented by TSC ticks
 */
uint64_t frc_to_nsec(uint64_t frc);

#endif /* ZF_APPS_TIMER_H */