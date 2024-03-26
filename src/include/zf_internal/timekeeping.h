/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** timekeeping for a stack */

#ifndef __ZF_TIME_KEEPING_H__
#define __ZF_TIME_KEEPING_H__

#include <zf_internal/platform.h>
#include <zf_internal/timekeeping_types.h>


ZF_HOT static inline
zf_frc zf_timekeeping_ms2frc(zf_timekeeping* tk, int ms)
{
  return ms * (tk->frcs_in_ms);
}


ZF_HOT static inline
zf_frc zf_timekeeping_ns2frc(zf_timekeeping* tk, __int128 ns)
{
  return (ns * tk->frcs_in_mibinano) >> tk->MIBINANO_TO_NANO_SHIFT;
}


/* Return how many ticks have elapsed since we last bumped the tick counter. */
static inline
zf_frc zf_timekeeping_elapsed_ticks(const zf_timekeeping* tk)
{
  zf_frc now = zf_frc64();
  return ((now - tk->last_tick_frc) * tk->ticks_in_frc_fxp32) >> 32;
}


/* Induce time passage
 * returns number of whole ticks that passed since the last call,
 * updates internal state */
ZF_HOT static inline
int zf_timekeeping_check_tick(zf_timekeeping* tk)
{
  zf_frc passed = zf_timekeeping_elapsed_ticks(tk);
  tk->last_tick_frc += passed * tk->frcs_in_tick;
  return passed;
}


/* TODO add similar function, which takes into account amount of
 * fractional tick that passed, with not_sooner set
 * result will be rounded up*/
ZF_HOT static inline zf_tick
zf_timekeeping_frc2tick(zf_timekeeping* tk, zf_frc t, int not_sooner)
{
  return ((t + (not_sooner ? tk->frcs_in_tick - 1 : 0)) *
          tk->ticks_in_frc_fxp32 + (not_sooner ? (1ull<<32) - 1 : 0)) >> 32;
}


ZF_HOT static inline zf_tick
zf_timekeeping_ms2tick(zf_timekeeping* tk, int ms, int not_sooner)
{
  zf_tick t = zf_timekeeping_ms2frc(tk, ms);
  return zf_timekeeping_frc2tick(tk, t, not_sooner);
}


extern
int zf_timekeeping_init(zf_timekeeping* tk, uint64_t tick_duration_us);

extern
void zf_timekeeping_fini(zf_timekeeping* tk);


#endif /* __ZF_TIME_KEEPING_H__ */
