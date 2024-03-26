/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/*
 * To measure timing at nsec precision using stable tsc counter
 */
#include "zf_timer.h"
#include <stdio.h>
#include "zf_utils.h"
#include <strings.h>

/* Read the bogomips from /proc/cpuinfo and returns tsc frequency for the CPU. 
 * For now we use magic numbers for CPUid specific operations.
 * @return TSC frequency for the CPU
 */
static inline uint64_t get_tsc_frequency(void) {
  double frequency;
  char buf[128];
  FILE* f;
  ZF_TEST((f = fopen("/proc/cpuinfo", "r")) != NULL);
  while( 1 ) {
    ZF_TEST(fgets(buf, sizeof(buf), f) != NULL);
    if( sscanf(buf, "bogomips : %lf", &frequency) == 1 ) {
      /* Bogomips is twice CPU speed, in MHz, so multiply by 500000 to get to Hz */
      fclose(f);
      return (uint64_t)(frequency * 500000.0);
    }
  }
}

uint64_t tsc_frequency;

/* Reads /proc/cpuinfo and saves the TSC frequency to be used by frc_to_nsec() */
void init_tsc_frequency(void)
{
  tsc_frequency = get_tsc_frequency();
}

uint64_t frc_to_nsec(uint64_t frc)
{
  double nsec_per_frc = (1000000000LL / (double)tsc_frequency);
  return frc * nsec_per_frc;
}
