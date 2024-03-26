/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** zftimers - slow path code */


#include <zf_internal/timers.h>
#include <zf_internal/timekeeping.h>


void zf_timer_wheel_init(zf_wheel* w, zf_tick start_tick)
{
  memset(w, 0, sizeof(*w));
  w->current_tick = start_tick;
}


void zf_timer_wheel_fini(zf_wheel* w)
{
}


int zf_timekeeping_init(zf_timekeeping* tk, uint64_t tick_duration_us)
{
  uint64_t freq = zf_frc64_get_frequency();
  if( freq == 0 )
    return -EIO; /* Probably failed to read something */

  tk->frcs_in_tick = (freq * tick_duration_us + 1000000 - 1) / 1000000;
  tk->frcs_in_ms = freq / 1000;
  tk->frcs_in_mibinano = (freq << tk->MIBINANO_TO_NANO_SHIFT) / 1000000000;
  tk->ticks_in_frc_fxp32 = ((1000000ull << 32) + (tick_duration_us * 1000000 - 1)) /
                           (freq * tick_duration_us);
  tk->last_tick_frc = zf_frc64();
  return 0;
}


void zf_timekeeping_fini(zf_timekeeping* tk)
{
}
