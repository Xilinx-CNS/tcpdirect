/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2020 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mj
**  \brief  zftimers - unit test
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf_internal/timers.h>
#include <zf_internal/timekeeping.h>
#include "../tap/tap.h"
#include <math.h>


zf_wheel wheel;
zf_timer_token tok[ZF_WHEEL_TIMEOUT_ID_COUNT];
int sched[ZF_WHEEL_TIMEOUT_ID_COUNT];

#define TM_BASE 90

int expire_fail(void* a, zf_timer_id id)
{
  ZF_TEST(0);
  return 0;
}

int expire(void* _a, zf_timer_id id)
{
  int* a = (int*) _a;
  diag("Timer %d expired\n", id);
  ZF_TEST(*a == -1);
  *a = id;
  return 0;
}


int expire_multi(void* _a, zf_timer_id id)
{
  int* a = (int*) _a;
  int count = *a;
  ++a;
  diag("Timer %d expired at %d\n", id, wheel.current_tick);
  while(*a != -1) {
    ++a;
    ZF_TEST(--count);
  }
  *a = id;
  return 0;
}

/* Total number of tests that will be run, used as an argument to plan() */
#define ZFTIMER_TEST_COUNT 356

int main(int argc, char* argv[])
{
  uint64_t freq = zf_frc64_get_frequency();
  plan(ZFTIMER_TEST_COUNT);
  diag("Max ticks %d\n", ZF_WHEEL_MAX_TICKS);
  diag("CPU frequency %"SCNu64"\n", freq);
  int wrong = 0;

  /* Just to test we have a reasonable sounding number, there is no requirement
   * that the frc64 value be in this range */
  cmp_ok((int)(freq / 1000), ">", 1000000, "FRC64 frequency greater than 1GHz");
  cmp_ok((int)(freq / 10000), "<", 1000000, "FRC64 frequency less than 10GHz");

  zf_timekeeping timek;
  zf_timekeeping_init(&timek, 1);
  /* bit silly but why since we have got this already */
  double base = timek.frcs_in_ms / 1000.;
  for( unsigned i = 0; i < base * ZF_WHEEL_MAX_TICKS; ++i ) {
    int a = (int)round(i / base);
    int b = zf_timekeeping_frc2tick(&timek, i, 0);
    /* Tolerate out-by-one in each direction due to arithmetic errors */
    int f = a != b && b != a - 1 && b != a + 1;
    wrong += f;
    if( f )
      diag("Time translation: %d -> %d got %d", i, a, b);
  }
  cmp_ok(wrong, "==", 0, "Problem translating time %d", wrong);
  wrong = 0;
  for( unsigned i = 0; i < base * ZF_WHEEL_MAX_TICKS; ++i ) {
    int a = (int)ceil(i  / base);
    int b = zf_timekeeping_frc2tick(&timek, i, 1);
    /* Tolerate out-by-one plus one due to arithmetic errors and rounding up for
     * not_sooner */
    int f = a != b && b != a + 1 && b != a + 2;
    wrong += f;
    if( f )
      diag("Time translation: %d -> %d got %d", i, a, b);
  }
  cmp_ok(wrong, "==", 0, "Problem translating time %d", wrong);

  zf_timer_wheel_init(&wheel, 0);

  /* basic sanity tests */
  tok[10] = zf_timer_add(&wheel, 10, 0, 0);
  /* bucket 0 is always things due now */
  cmp_ok(tok[10], "==", 0, "Timer scheduled correctly 1");
  tok[11] = zf_timer_add(&wheel, 11, 1, 0);
  /* bucket 2 - according to our insight in this state things
   * due after a tick */
  cmp_ok(tok[11], "==", 2, "Timer scheduled correctly 2");
  int expired_timer = -1;
  zf_wheel_tick(&wheel, 0, expire, &expired_timer);
  zf_wheel_flush_expired(&wheel, expire, &expired_timer);
  cmp_ok(expired_timer, "==", 10, "Timer expired as expected 1");
  expired_timer = -1;
  zf_wheel_tick(&wheel, 1, expire, &expired_timer);
  zf_wheel_flush_expired(&wheel, expire, &expired_timer);
  cmp_ok(expired_timer, "==", 11, "Timer expired as expected 2");
  expired_timer = -1;
  zf_wheel_tick(&wheel, 2, expire, &expired_timer);
  zf_wheel_flush_expired(&wheel, expire, &expired_timer);
  cmp_ok(expired_timer, "==", -1, "No timer expired as expected 1");
  expired_timer = -1;

  /* note we wrap around here */
  zf_wheel_tick(&wheel, 0, expire, &expired_timer);
  zf_wheel_flush_expired(&wheel, expire, &expired_timer);
  cmp_ok(expired_timer, "==", -1, "No timer expired as expected 2");

  for( int i = 0; i < ZF_WHEEL_LVL_COUNT; ++i )
    diag("level %d: low bit %d, high bit %d\n", i,
         ZF_WHEEL_LVL_BUCKET_LOW_BIT(i), ZF_WHEEL_LVL_BUCKET_HIGH_BIT(i));

  /* More comprehensive let us put each timer into a different
   * bucket in the timer wheel */
  int time = 1;
  int last_bucket = -1;

  /* no of buckets we can schedule stuff into - bit empirically devised
   * TODO use formula*/
#define MAX_USABLE_BUCKETS 85
  for( int i = 0; i < MAX_USABLE_BUCKETS ; ++i) {
    zf_timer_token ctok = zf_timer_add(&wheel, i, time, 0);
    while( ctok == last_bucket ) {
      ++time;
      ctok = zf_timer_mod(&wheel, i, ctok, time, 0);
    }
    diag("timer %d in bucket %d to fire at %d\n", i, ctok, time);
    tok[i] = ctok;
    sched[i] = time;
    last_bucket = ctok;
    cmp_ok(zf_timer_is_armed(&wheel, i, ctok),
           "==", 1, "Timer %d is considered armed", i);
  }
  cmp_ok(zf_timer_is_armed(&wheel, 1, tok[1] + 1), "==", 0,
         "With invalid token state of timer is different");

  int expired_count = 0;
  int last_timer = -1;
  for( int i = 0; i <= (time + (1 << ZF_WHEEL_LVL_BUCKET_LOW_BIT(ZF_WHEEL_LVL_COUNT))); ++i) {
    int expired_timers[5] = {4, -1, -1, -1, -1};
    zf_wheel_tick(&wheel, i, expire_multi, &expired_timers);
    zf_wheel_flush_expired(&wheel, expire_multi, &expired_timers);
    for( int j = 1; j <= 4; ++j ) {
      if( expired_timers[j] == -1 )
        break;
      cmp_ok(sched[expired_timers[j]], "<=", i,
             "Timer %d expires at the right time", expired_timers[j]);
      cmp_ok(expired_timers[j], "==", last_timer + 1,
             "Timer %d order ok", expired_timers[j]);
      cmp_ok(zf_timer_is_armed(&wheel, expired_timers[j],
                               tok[expired_timers[j]]),
             "==", 0, "Timer %d is not armed anymore",
             expired_timers[j]);
      expired_count++;
      last_timer = expired_timers[j];
    }
  }
  cmp_ok(expired_count,"==", MAX_USABLE_BUCKETS, "All timers expired");


  /* Firing timers from all 3 wheels at once */
  zf_wheel_tick(&wheel, 0, expire_fail, NULL);
  zf_wheel_flush_expired(&wheel, expire_fail, NULL);

  /* level 2 bucket 4 */
  int time2 = (2 << ZF_WHEEL_LVL_BUCKET_HIGH_BIT(1)) - 1;
  diag("L2 token %d\n", zf_timer_add(&wheel, 4, time2, 0) );

  int time1 = (2 << ZF_WHEEL_LVL_BUCKET_HIGH_BIT(0)) - 1;
  zf_wheel_tick(&wheel, time2 - time1, expire_fail, NULL);
  zf_wheel_flush_expired(&wheel, expire_fail, NULL);

  /* level 1 bucket 4 */
  diag("L1 token %d\n", zf_timer_add(&wheel, 3, time1, 0));

  zf_wheel_tick(&wheel, time2 - 1, expire_fail, NULL);
  zf_wheel_flush_expired(&wheel, expire_fail, NULL);

  /* level 1 bucket 1 */
  diag("L0 token %d\n", zf_timer_add(&wheel, 2, 1, 0));
  zf_wheel_flush_expired(&wheel, expire_fail, NULL);
  zf_timer_add(&wheel, 1, 0, 0);

  {
    int expired_timers[5] = {4, -1, -1, -1, -1};
    zf_wheel_tick(&wheel, time2, expire_multi, &expired_timers);
    zf_wheel_flush_expired(&wheel, expire_multi, &expired_timers);
    for( int i = 1; i <= 4; ++i )
      cmp_ok(expired_timers[i],"==", i, "Multi expire: timer %d expired", i);
  }

  zf_timer_wheel_fini(&wheel);
  return 0;
}
