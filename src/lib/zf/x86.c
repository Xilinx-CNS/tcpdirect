/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF x86-specific internal definitions. */

#include <zf_internal/zf_stack.h>
#include <zf_internal/utils.h>
#include <zf_internal/x86.h>
#include <stdlib.h>


static inline void cpuid(uint32_t words[], uint32_t mode)
{
  __asm__ ("cpuid"
         : "=a" (words[0]),
           "=b" (words[1]),
           "=c" (words[2]),
           "=d" (words[3])
         : "a" (mode)
         : "memory" );
}


/* For now we use magic numbers for CPUid specific operations */
uint64_t zf_frc64_get_frequency(void)
{
  float frequency = 0;

  /* make sure CPU supports CPU string */
  uint32_t words[4];
  cpuid(words, 0x80000000);
  uint32_t max_extid = words[0];
  if( max_extid < 0x80000004 ) {
    zf_log_stack_err(NO_STACK, "Failed to read CPUID\n");
    return 0;
  }

  char buf[128];

  /* retrieve CPU string */
  memset(&buf[0], 0, 128);
  cpuid(words, 0x80000002);
  memcpy(&buf[0], (const char*)&words[0], 16);
  cpuid(words, 0x80000003);
  memcpy(&buf[16], (const char*)&words[0], 16);
  cpuid(words, 0x80000004);
  memcpy(&buf[32], (const char*)&words[0], 16);
  buf[48] = 0;

  /* Although all supported architectures provide /proc/cpuinfo we still check
   * in case anyone tries to run on another architecture where bogomips aren't
   * tied to the RDTSC frequency */
  if( strcasestr(buf, "AMD") ||
      strcasestr(buf, "Intel") ) {
    FILE* f =
      fopen("/proc/cpuinfo", "r");

    if( ! f ) {
      zf_log_stack_err(NO_STACK, "cannot open /proc/cpuinfo\n");
      return 0;
    }

    while( 1 ) {
      if( !fgets(buf, sizeof(buf), f) ) {
        zf_log_stack_err(NO_STACK, "failed to read bogomips\n");
        fclose(f);
        return 0;
      }

      if( sscanf(buf, "bogomips : %f", &frequency) == 1 ) {
        /* Bogomips is twice CPU speed, in MHz, so multiply by 500000 to get to Hz */
        fclose(f);
        return (uint64_t)(frequency * 500000.0);
      }
    }
  }

  zf_log_stack_err(NO_STACK, "unsupported processor brand: %s\n", buf);
  return 0;
}

