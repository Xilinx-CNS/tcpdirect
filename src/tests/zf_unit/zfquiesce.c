/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2017 Advanced Micro Devices, Inc. */
/* Test stack quiescence by querying the quiescece state while zockets exist
 * at various points in their lifetimes. */

#include <zf/zf.h>
#include <zf_internal/attr.h>
#include <zf_internal/timers.h>
#include <zf_internal/tcp.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>

#include <arpa/inet.h>

#include "../tap/tap.h"


#ifndef WAIT_FOR_TIME_WAIT
/* We wish to test with tcp_wait_time_wait on and off.  This is a stack
 * attribute that must be specified when a stack is created.  The loopback shim
 * only supports one stack per process.  We work around this by generating two
 * binaries from this source file, with different values of WAIT_FOR_TIME_WAIT
 * specified in the makefile. */
#error Please define WAIT_FOR_TIME_WAIT.
#endif


/* We create two stacks: one in which TIME_WAIT zockets prevent quiescence, and
 * one in which they don't. */
static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  /* This test requires the loopback shim. */
  ZF_TEST((*attr_out)->emu == ZF_EMU_LOOPBACK);

  ZF_TRY(zf_attr_set_int(*attr_out, "tcp_wait_for_time_wait",
                         WAIT_FOR_TIME_WAIT));
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


#define CHECK_QUIESCENCE_TESTS 2

static void
check_quiescence(struct zf_stack* stack, struct zf_muxer_set* stack_mux,
                 bool expect_quiescence, const char* description)
{
  static bool previously_quiescent = false;

  bool quiescent = !! zf_stack_is_quiescent(stack);

  cmp_ok(quiescent, "==", !! expect_quiescence, description);

  struct epoll_event ev;
  int num_evs = zf_muxer_wait(stack_mux, &ev, 1, 0);

  /* To account for the edge-triggered polling semantics, we must handle the
   * case where we poll twice while the stack is quiescent, at which point the
   * muxer will not indicate an event. */
  bool muxer_indicates_quiescent = num_evs > 0 ||
                                   (quiescent && previously_quiescent);

  cmp_ok(muxer_indicates_quiescent, "==", quiescent,
         "Waitable state is consistent with quiescence state");

  previously_quiescent = quiescent;
}


/* The most important thing about our pairs of connected TCP zockets is which
 * one is closed first. */
struct connected_tcp_pair {
  zft* active_close_zocket;
  zft* passive_close_zocket;
};


#define CLOSE_SOME_ZOCKETS_TESTS (CHECK_QUIESCENCE_TESTS * 2)

static void
close_some_zockets(struct zf_stack* stack, struct zf_muxer_set* stack_mux,
                   struct connected_tcp_pair* zockets, int num_pairs,
                   bool other_zockets_present)
{
  /* Close the first half of the zocket pairs, nudging the state machine along
   * so that we end up with the actively-closed zockets in TIME_WAIT. */
  for( int i = 0; i < num_pairs; ++i )
    zft_shutdown_tx(zockets[i].active_close_zocket);
  while( zft_state(zockets[num_pairs - 1].active_close_zocket) !=
         TCP_FIN_WAIT2 )
    zf_reactor_perform(stack);
  for( int i = 0; i < num_pairs; ++i )
    zft_shutdown_tx(zockets[i].passive_close_zocket);
  /* Touching the state of a closed connection is safe as the application has
   * not freed the zocket. */
  while( zft_state(zockets[num_pairs - 1].passive_close_zocket) != TCP_CLOSE )
    zf_reactor_perform(stack);

  /* The stack should only be quiescent at this point if we're not waiting for
   * TIME_WAITs to go away, and if there are no other connected zockets. */
  check_quiescence(stack, stack_mux, ! (WAIT_FOR_TIME_WAIT ||
                                        other_zockets_present),
                   "Checked quiescence after entering TIME_WAIT");

  /* Wait for TIME_WAIT timer to fire. */
  while( zft_state(zockets[num_pairs - 1].active_close_zocket) !=
         TCP_CLOSE )
    zf_reactor_perform(stack);

  /* All of this tranche of zockets have now gone, so we'll be quiescent unless
   * there are other zockets that we haven't touched. */
  check_quiescence(stack, stack_mux, ! other_zockets_present,
                   "Checked quiescence after leaving TIME_WAIT");
}


#define NUM_TESTS (CHECK_QUIESCENCE_TESTS * 3 + CLOSE_SOME_ZOCKETS_TESTS * 2)

#define MIN_ZOCKETS 4

static void test(struct zf_stack* stack, struct zf_attr* attr)
{
  int rc;

  plan(NUM_TESTS);

  diag("Testing with wait_for_time_wait == %d", WAIT_FOR_TIME_WAIT);

  struct zf_muxer_set* stack_mux;
  struct epoll_event ev = {
    .events = EPOLLSTACKHUP,
    .data = { .u32 = 0 },
  };
  ZF_TRY(zf_muxer_alloc(stack, &stack_mux));
  ZF_TRY(zf_muxer_add(stack_mux, zf_stack_to_waitable(stack), &ev));

  /* Ensure that the stack is quiescent to begin with. */
  check_quiescence(stack, stack_mux, true, "Stack is quiescent initially.");

  /* We need an even number of TCP zockets as they must exist in pairs. */
  int num_zockets = attr->max_tcp_endpoints & ~1;
  int num_zocket_pairs = num_zockets / 2;

  if( num_zockets < MIN_ZOCKETS )
    BAIL_OUT("Too few zockets: got %d, needed at least %d", num_zockets,
             MIN_ZOCKETS);

  /* Create a listening zocket for the purpose of setting up our connected
   * zockets. */
  struct sockaddr_in listen_addr = {
    AF_INET,
    htons(4000),
    { inet_addr("127.0.0.4") },
  };
  struct zftl* listener;
  ZF_TRY(zftl_listen(stack, (struct sockaddr*)&listen_addr,
                     sizeof(listen_addr), attr, &listener));

  /* The listening zocket shouldn't prevent quiescence. */
  check_quiescence(stack, stack_mux, true, "Stack with listener is quiescent.");

  struct connected_tcp_pair zockets[num_zocket_pairs];

  /* Set up pairs of connected zockets. */
  for( int i = 0; i < num_zocket_pairs; ++i ) {
    struct zft_handle* handle;
    struct sockaddr_in connect_laddr = {
      AF_INET,
      htons(3000 + i),
      { inet_addr("127.0.0.3") },
    };

    ZF_TRY(zft_alloc(stack, attr, &handle));
    ZF_TRY(zft_addr_bind(handle, (struct sockaddr*)&connect_laddr,
                         sizeof(connect_laddr), 0));

    ZF_TRY(zft_connect(handle, (struct sockaddr*)&listen_addr,
                       sizeof(listen_addr), &zockets[i].active_close_zocket));

    do {
      zf_reactor_perform(stack);
    } while( rc = zftl_accept(listener, &zockets[i].passive_close_zocket),
             rc == -EAGAIN );
    ZF_TRY(rc);
  }

  /* The stack should definitely not be quiescent after opening a bunch of TCP
   * connections. */
  check_quiescence(stack, stack_mux, false,
                   "Stack not quiescent after connections opened.");

  /* Begin pushing the zockets through the state machine and testing for
   * quiescence at strategic points. */

  /* Divide the zocket pairs roughly in half. */
  int midpoint = num_zocket_pairs / 2;

  /* Close the first half of the zockets, checking that the stack is not
   * quiescent. */
  diag("Close first half of zockets");
  close_some_zockets(stack, stack_mux, zockets, midpoint, true);

  /* Close the remaining zockets, checking for quiescence either when they all
   * enter TIME_WAIT or when they all leave TIME_WAIT, as configured. */
  diag("Close other half of zockets");
  close_some_zockets(stack, stack_mux, zockets + midpoint,
                     num_zocket_pairs - midpoint, false);
}


int main(void)
{
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(init(&stack, &attr));
  test(stack, attr);
  ZF_TRY(fini(stack, attr));

  return 0;
}
