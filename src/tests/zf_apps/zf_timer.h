/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/*
 * To measure timing at nsec precision using stable tsc counter
 */
#ifndef ZF_APPS_TIMER_H
#define ZF_APPS_TIMER_H

#include <x86intrin.h>
#include <stdint.h>

/* Return measure of free running counter, using rdtsc, so may be reordered with other code */
inline uint64_t get_frc64_time_standard(void)
{
  return __rdtsc();
}

/* Return measure of free running counter, using rdtscp, which gives higher accuracy when measuring 
 * the duration of blocks of code as it can't be reordered, but has slightly higher overhead than
 * get_frc64_time_standard() */
inline uint64_t get_frc64_time_accurate(void)
{
  unsigned int aux;
  return __rdtscp(&aux);
}

/* Default to using the more accurate measure as all current uses of this function are using it to
 * measure ping pong deltas, and hence will benefit from the accuracy */
#define get_frc64_time() get_frc64_time_accurate()

void init_tsc_frequency(void);

/* Given TSC ticks it will calculate and return number of nano seconds passed for it. 
 * @frc TSC ticks observed on CPU
 * @return nano seconds represented by TSC ticks
 */
uint64_t frc_to_nsec(uint64_t frc);

#endif /* ZF_APPS_TIMER_H */