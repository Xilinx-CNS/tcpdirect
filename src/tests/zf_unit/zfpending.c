/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2018-2020 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  kjm
**  \brief  Unit test for ZF zf_stack_has_pending_work()/_has_pending_events()
**   \date  2016/01/07
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include <zf_internal/private/zf_emu.h>
#include "abstract_zocket_pair.h"
#include <zf_internal/private/zf_emu.h>
#include "../tap/tap.h"


static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc;
  rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  rc = zf_stack_alloc(*attr_out, stack_out);
  if( rc != 0 ) {
    zf_attr_free(*attr_out);
    return rc;
  }

  return 0;
}


static int fini(struct zf_stack* stack, struct zf_attr* attr)
{
  int rc;

  rc = zf_stack_free(stack);
  if( rc != 0 )
    return rc;
  zf_attr_free(attr);

  zf_deinit();

  return 0;
}


static int
timeval_msec_difference(const struct timeval* tv1, const struct timeval* tv2)
{
  int usec_delta = tv2->tv_usec - tv1->tv_usec;
  int sec_delta  = tv2->tv_sec  - tv1->tv_sec;

  ZF_TEST(usec_delta <  1000000);
  ZF_TEST(usec_delta > -1000000);

  return sec_delta * 1000 + usec_delta / 1000;
}


static int time_pending_work(struct zf_stack* stack)
{
  struct timeval tv1, tv2;
  int i;
  ZF_TRY(gettimeofday(&tv1, NULL));
  for(i = 0; i < 10000000; ++i)
    zf_stack_has_pending_work(stack);
  ZF_TRY(gettimeofday(&tv2, NULL));
  i = timeval_msec_difference(&tv1, &tv2);
  /* fprintf(stderr, "zf_stack_has_pending_work() loop took %d\n", i); */
  return i;
}


#define NO_WORK_TIMEOUT 1000 /* 1 second */
#define TCP_WORK_TIMEOUT 100

static void check_no_pending_work(int (*pending_fn)(const zf_stack*),
                                  struct zf_stack* stack)
{
  struct timeval tv1, tv2;

  ZF_TRY(gettimeofday(&tv1, NULL));
  do {
    ZF_TRY(gettimeofday(&tv2, NULL));
  } while (!(*pending_fn)(stack) &&
           timeval_msec_difference(&tv1, &tv2) < NO_WORK_TIMEOUT);
  cmp_ok(timeval_msec_difference(&tv1, &tv2), ">=", NO_WORK_TIMEOUT);
}


static void check_pending_work_timeout(struct zf_stack* stack, int max_time_ms,
                                       struct timeval* work_time)
{
  struct timeval start_time;

  ZF_TRY(gettimeofday(&start_time, NULL));
  do {
    ZF_TRY(gettimeofday(work_time, NULL));
  } while (!zf_stack_has_pending_work(stack) &&
           timeval_msec_difference(&start_time, work_time) < max_time_ms);
  cmp_ok(timeval_msec_difference(&start_time, work_time), "<", max_time_ms);
}


static int check_no_pending_work_now(int (*pending_fn)(const zf_stack*),
                                      struct zf_stack* stack,
                                      struct timeval* last_work_time)
{
  int rc = (*pending_fn)(stack);

  /* Careful now.  We can't be sure that the CPU hasn't been off doing
   * other things, so only assert that there is nothing to do if not
   * much wall clock time has passed since last work reported,
   * otherwise the TCP timers could be ready again
   */
  if( last_work_time != NULL ) {
    struct timeval now;
    ZF_TRY(gettimeofday(&now, NULL));
    if( timeval_msec_difference(last_work_time, &now) > TCP_WORK_TIMEOUT/2 )
      return 0;
  }

  cmp_ok(rc, "==", 0);
  return 1;
}


static void check_pending_work_now(int (*pending_fn)(const zf_stack*),
                                   struct zf_stack* stack)
{
  cmp_ok((*pending_fn)(stack), "==", 1);
}


static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  char data[] = "Hi";
  char recv[10];
  int i;
  int num_no_work_tests = 0;

  /* No sockets, so should never have pending work */
  check_no_pending_work(zf_stack_has_pending_work, stack);
  check_no_pending_work(zf_stack_has_pending_events, stack);

  /* Create UDP sockets */
  struct abstract_zocket_pair udp_zockets;
  alloc_udp_pair(stack, attr, &udp_zockets);
  while(zf_reactor_perform(stack) != 0);

  /* Idle UDP sockets, so should never have pending work */
  check_no_pending_work(zf_stack_has_pending_work, stack);
  check_no_pending_work(zf_stack_has_pending_events, stack);

  /* Send data on UDP sockets */
  ZF_TRY(udp_zockets.send(udp_zockets.opaque_tx, data[0]));

  /* Allow time for the events */
  zf_emu_sync();

  /* Non-idle UDP, so should have pending work */
  check_pending_work_now(zf_stack_has_pending_work, stack);
  check_pending_work_now(zf_stack_has_pending_events, stack);

  while(zf_reactor_perform(stack) != 0);
  int rc = udp_zockets.recv(udp_zockets.opaque_rx, recv, 10);
  cmp_ok(rc, "==", 1);

  /* After calling zf_reactor_perform it should all be back to idle */
  check_no_pending_work(zf_stack_has_pending_work, stack);
  check_no_pending_work(zf_stack_has_pending_events, stack);

  int udp_time;
  udp_time = time_pending_work(stack);

  struct abstract_zocket_pair tcp_zockets;
  alloc_tcp_pair(stack, attr, &tcp_zockets);

  /* Check it is now marked for pending work every 100ms for TCP timers */
  i = 10;
  struct timeval work_time;
  do {
    check_pending_work_timeout(stack, TCP_WORK_TIMEOUT, &work_time);
    check_no_pending_work_now(zf_stack_has_pending_events, stack, NULL);
    while(zf_reactor_perform(stack) != 0);

    if( check_no_pending_work_now(zf_stack_has_pending_work, stack,
                                  &work_time) )
      ++num_no_work_tests;
    else
      diag("skipped test due to passage of time\n");
  } while (--i > 0);

  int tcp_time;
  tcp_time = time_pending_work(stack);

  /* Send data on TCP sockets */
  ZF_TRY(tcp_zockets.send(tcp_zockets.opaque_tx, data[1]));

  /* Allow time for the events */
  zf_emu_sync();

  zf_emu_sync(); /* make sure emulator passes the packet to rx */

  /* Non-idle TCP, so should have pending work */
  check_pending_work_now(zf_stack_has_pending_work, stack);
  check_pending_work_now(zf_stack_has_pending_events, stack);

  /* We expect a pure-UDP stack to be quicker than a TCP one as no
   * timers to check
   */
  if( udp_time >= tcp_time )
    diag("UDP test unexpectedly took longer (%d) than TCP test (%d)\n",
         udp_time, tcp_time);


  plan(31 + num_no_work_tests);

  done_testing();

  return 0;
}


int main(void)
{
  int rc;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(init(&stack, &attr));
  rc = test(stack, attr);
  ZF_TRY(fini(stack, attr));

  return rc;
}
