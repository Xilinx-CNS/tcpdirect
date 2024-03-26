/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2019 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  gd
**  \brief  Unit test for ZF multiplexer.
**   \date  2016/01/07
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/muxer.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/attr.h>
#include <zf_internal/private/zf_emu.h>

#include <stdio.h>
#include <sys/epoll.h>
#include <sys/time.h>

#include "../tap/tap.h"


/* Constants representing number of tests in a given section.  Because these are
 * passed to the libtap plan() function to tell it how many tests are to be run,
 * you MUST update the corresponding constant if tests are added to or removed
 * from a section. */
#define ADD_REM_TESTS  8
/* To calculate EVT_LOOP_TESTS: See calculation of "expect_events" in the event
 * loop, work out what this will be for each iteration, and sum the resulting
 * values.  There are also 2 other tests per iteration. */
#define EVT_LOOP_TESTS 48
#define FINAL_TESTS    16

#define OTHER_INTERFACE "otherintf"


static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc;
  rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  /* This test creates two stacks, so we need two interfaces.  It doesn't pass
   * any traffic, though, so we don't care about the wiring. */
  zf_emu_intf_add((*attr_out)->interface, 1, 1, 0, 0, 0, NULL);
  zf_emu_intf_add(OTHER_INTERFACE, 2, 2, 0, 0, 0, NULL);

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


static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  /* Allocate the necessary bits and pieces.  We use a real muxer set with a
   * real stack (because zf_muxer_wait() wants to poll one), but dummy
   * waitables (although we do have to use waitables from the stack in order
   * to satisy zf_muxer_add()). */

  struct zf_muxer_set* muxer;
  ZF_TRY(zf_muxer_alloc(stack, &muxer));

  const int num_waitables = 2;
  struct epoll_event events[num_waitables];

  /* We are slightly devious here.  To satisfy zf_muxer_add(), we must use
   * waitables from the muxer's stack, but we want to manipulate them directly.
   * We grab a couple of waitables from unallocated TCP zockets.  This will be
   * safe as long as those zockets are never allocated. */
  struct zf_waitable& w_in = stack->tcp[0].w;
  struct zf_waitable& w_out = stack->tcp[1].w;
  zf_waitable_init(&w_in);
  zf_waitable_init(&w_out);

  const struct epoll_event in_event  = {
    .events = EPOLLIN,
    .data = { .u32 = EPOLLIN },
  };
  const struct epoll_event out_event = {
    .events = EPOLLOUT,
    .data = { .u32 = EPOLLOUT },
  };

  plan(ADD_REM_TESTS + EVT_LOOP_TESTS + FINAL_TESTS);

  /* Do the actual tests. */

  /* Test section: ADD_REM_TESTS */

  /* Check that we're prevented from adding waitables from a foreign stack. */
  struct zf_stack* foreign_stack;
  ZF_TRY(zf_attr_set_str(attr, "interface", OTHER_INTERFACE));
  ZF_TRY(zf_stack_alloc(attr, &foreign_stack));
  cmp_ok(zf_muxer_add(muxer, &foreign_stack->tcp[0].w, &in_event), "==", -EXDEV,
         "Adding waitable from foreign stack failed.");
  zf_stack_free(foreign_stack);

  cmp_ok(zf_muxer_mod(&w_in, &in_event), "==", -EINVAL,
         "Modifying waitable not in muxer failed.");

  /* Check some add-remove-add sequences. */
  cmp_ok(zf_muxer_add(muxer, &w_in, &in_event), "==", 0, "Add waitable to muxer");
  cmp_ok(zf_muxer_add(muxer, &w_in, &in_event), "==", -EALREADY, "Add waitable "
         "again, expect -EALREADY");
  cmp_ok(zf_muxer_del(&w_in), "==", 0, "Delete waitable from muxer");
  cmp_ok(zf_muxer_del(&w_in), "==", -EINVAL, "Delete waitable again, expect -EINVAL");
  cmp_ok(zf_muxer_add(muxer, &w_in, &in_event), "==", 0, "Add waitable for EPOLLIN"
                      " events");
  cmp_ok(zf_muxer_add(muxer, &w_out, &out_event), "==", 0, "Add waitable for"
         " EPOLLOUT events");

  /* Test section: EVT_LOOP_TESTS */

  /* Start testing event-handling.  Try each combination of IN/OUT on each
   * waitable. */
  uint32_t event_masks[] = {0, EPOLLIN, EPOLLOUT, EPOLLIN | EPOLLOUT};
  const int event_count = sizeof(event_masks) / sizeof(event_masks[0]);
  for( int w_in_index = 0; w_in_index < event_count; ++w_in_index )
    for( int w_out_index = 0; w_out_index < event_count; ++w_out_index ) {

      /* Mark the waitables as ready for only the specified events.  This both
       * sets their masks and ensures that they're on the ready-list. */
      zf_muxer_mark_waitable_not_ready(&w_in,  ~event_masks[w_in_index]);
      zf_muxer_mark_waitable_not_ready(&w_out, ~event_masks[w_out_index]);
      zf_muxer_mark_waitable_ready(&w_in,  event_masks[w_in_index]);
      zf_muxer_mark_waitable_ready(&w_out, event_masks[w_out_index]);

      /* We expect zero, one or two events. */
      int expect_events = !! (event_masks[w_in_index]  & EPOLLIN) +
                          !! (event_masks[w_out_index] & EPOLLOUT);

      /* Poll the muxer. */
      int got_events = zf_muxer_wait(muxer, events, num_waitables, 0);

      /* Ensure that we saw the expected number of events. */
      cmp_ok(got_events, "==", expect_events, "Checking that %d event%s "
             "signalled", expect_events, expect_events == 1 ? " was" : "s were");

      /* Ensure that each returned waitable was expected. */
      for( int i = 0; i < got_events; ++i )
        switch( events[i].data.u32 ) {
        case EPOLLIN:
          cmp_ok(event_masks[w_in_index] & EPOLLIN, ">", 0, "Testing (%x, %x), "
                 "EPOLLIN expected", event_masks[w_in_index],
                 event_masks[w_out_index]);
          break;
        case EPOLLOUT:
          cmp_ok(event_masks[w_out_index] & EPOLLOUT, ">", 0, "Testing (%x, %x),"
                 " EPOLLOUT expected", event_masks[w_in_index],
                 event_masks[w_out_index]);
          break;
        default:
          fail("Event neither EPOLLIN or EPOLLOUT - not expected");
          break;
        }

      /* Edge-triggeredness means that there shouldn't be any ready waitables
       * now. */
      cmp_ok(zf_muxer_wait(muxer, events, num_waitables, 0), "==", 0,
             "No waitables ready");
    }

  /* Test section: FINAL_TESTS */

  /* The rest of the test assumes that the waitables are not ready at this
   * point, so let's enforce this. */
  zf_muxer_mark_waitable_not_ready(&w_in, (uint32_t) -1);
  zf_muxer_mark_waitable_not_ready(&w_out, (uint32_t) -1);
  cmp_ok(zf_muxer_wait(muxer, events, num_waitables, 0), "==", 0, "No waitables"
                       " ready after setting not ready for all events");

  /* Ensure that a waitable that is on the ready-list but that is no longer
   * ready is not returned. */
  zf_muxer_mark_waitable_ready(&w_in, EPOLLIN);
  zf_muxer_mark_waitable_not_ready(&w_in, (uint32_t) -1);
  cmp_ok(zf_muxer_wait(muxer, events, num_waitables, 0), "==", 0, "Previously "
                       "ready waitable no longer ready");


  /* Test non-zero timeouts.  Socket Tester will eventually test these more
   * thoroughly, but this is a quick sanity test.  In particular, we have no
   * easy way here to test waitables becoming ready mid-wait. */

  struct timeval tv1, tv2;

  /* Ready; infinite timeout. */
  zf_muxer_mark_waitable_ready(&w_in, EPOLLIN);
  ZF_TRY(gettimeofday(&tv1, NULL));
  cmp_ok(zf_muxer_wait(muxer, events, num_waitables, -1), "==", 1,
         "Infinite timeout with ready zocket");
  ZF_TRY(gettimeofday(&tv2, NULL));
  cmp_ok(timeval_msec_difference(&tv1, &tv2), "<", 10,
         "Call returned quickly");

  /* Ready; finite timeout.  Block for up to 100 ms, but expect for immediate
   * return, so check that we return in < 10 ms. */
  zf_muxer_mark_waitable_ready(&w_in, EPOLLIN);
  ZF_TRY(gettimeofday(&tv1, NULL));
  cmp_ok(zf_muxer_wait(muxer, events, num_waitables, 100000000), "==", 1,
         "Finite timeout with ready zocket");
  ZF_TRY(gettimeofday(&tv2, NULL));
  cmp_ok(timeval_msec_difference(&tv1, &tv2), "<", 10,
         "Call returned quickly");

  /* Not ready; finite timeout. */
  ZF_TRY(gettimeofday(&tv1, NULL));
  cmp_ok(zf_muxer_wait(muxer, events, num_waitables, 100000000), "==", 0,
         "Finite timeout with not-ready zocket");
  ZF_TRY(gettimeofday(&tv2, NULL));
  cmp_ok(timeval_msec_difference(&tv1, &tv2), ">=", 100,
         "Timeout elapsed");
  /* increased tolerance as seen up to 115, see bug 86636 */
  cmp_ok(timeval_msec_difference(&tv1, &tv2), "<", 150,
         "Timeout not too large");


  /* Test zf_muxer_mod(): ensure that old events are not signalled and that new
   * ones are. */
  cmp_ok(zf_muxer_mod(&w_in, &out_event), "==", 0, "Use zf_muxer_mod to change "
                      "waitable event from EPOLLIN to EPOLLOUT");
  zf_muxer_mark_waitable_ready(&w_in, EPOLLIN);
  cmp_ok(zf_muxer_wait(muxer, events, num_waitables, 0), "==", 0, "Shouldn't "
         "receive EPOLLIN event");
  zf_muxer_mark_waitable_ready(&w_in, EPOLLOUT);
  cmp_ok(zf_muxer_wait(muxer, events, num_waitables, 0), "==", 1, "Should receive"
         " EPOLLOUT event");

  /* Test that deleted waitables are not returned. */
  cmp_ok(zf_muxer_del(&w_out), "==", 0, "Delete one waitable");
  zf_muxer_mark_waitable_ready(&w_out, EPOLLOUT);
  cmp_ok(zf_muxer_wait(muxer, events, num_waitables, 0), "==", 0, "Deleted "
         "waitable should not be signalled");

  /* Remove the other waitable from the set. */
  cmp_ok(zf_muxer_del(&w_in), "==", 0, "Delete the other waitable");

  /* There should only be one reference to the set now that it's empty. */
  cmp_ok(muxer->refcount, "==", 1, "Check empty muxer set has only one reference");

  /* Tests are finished.  Tidy up. */
  zf_muxer_free(muxer);

  done_testing();
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

