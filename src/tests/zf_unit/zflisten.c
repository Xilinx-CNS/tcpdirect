/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2019 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  gd
**  \brief  Sanity test for listening zockets.
**   \date  2016/02/19
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/private/zf_emu.h>

#include <stdlib.h>
#include <arpa/inet.h>

#include "../tap/tap.h"


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


#define NUM_LISTENERS     4
#define NUM_CONNECTIONS  32
#define NUM_BATCHES       4

#define EXTRA_TESTS_PER_LISTENER      4
#define TESTS_PER_CONNECTION          3 /* Accept; close both ends. */
#define TESTS_PER_LISTENER_PER_BATCH  1
#define EXTRA_TESTS                   2 /* Re-listen. */

static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  plan(EXTRA_TESTS_PER_LISTENER * NUM_LISTENERS +
       TESTS_PER_CONNECTION * NUM_CONNECTIONS +
       TESTS_PER_LISTENER_PER_BATCH * NUM_BATCHES * NUM_LISTENERS +
       EXTRA_TESTS);

  /* We create multiple listening zockets and attempt multiple connections to
   * each at pseudo-random.  We then validate that we accept the correct number
   * of zockets from each listener. */

  unsigned seed = 0x5eed5eed;
  struct zftl* listeners[NUM_LISTENERS];
  struct sockaddr_in listen_addrs[NUM_LISTENERS];
  struct sockaddr_in active_laddrs[NUM_CONNECTIONS];
  struct sockaddr_in* next_active_laddr = active_laddrs;

  for( int i = 0; i < NUM_LISTENERS; ++i ) {
    listen_addrs[i].sin_family = AF_INET;
    listen_addrs[i].sin_addr.s_addr = inet_addr("127.0.0.1");

    /* Make sure one of them doesn't specify a port, but gets one
     * allocated implicitly */
    if( i == 0 )
      listen_addrs[i].sin_port = 0;
    else
      listen_addrs[i].sin_port = htons(0x2000 + i);

    cmp_ok(zftl_listen(stack, (struct sockaddr*)&listen_addrs[i],
                       sizeof(listen_addrs[i]), attr, &listeners[i]), "==", 0,
           "Created listening zocket %d.", i);
    struct zft* ts_passive_dummy;
    cmp_ok(zftl_accept(listeners[i], &ts_passive_dummy), "==", -EAGAIN,
           "Acceptq %d is empty initially.", i);

    struct sockaddr_in local_addr;
    socklen_t laddrlen = sizeof(local_addr);
    zftl_getname(listeners[i], (struct sockaddr*)&local_addr, &laddrlen);
    if( i == 0 ) {
      cmp_ok(local_addr.sin_port, "!=", 0,
             "zftl_getname returns non-zero implicit port");
      listen_addrs[i].sin_port = local_addr.sin_port;
    }
    else {
      cmp_ok(listen_addrs[i].sin_port, "==", local_addr.sin_port,
             "zftl_getname returns matching port");
    }
  }
  for( int i = 0; i < NUM_CONNECTIONS; ++i ) {
    active_laddrs[i].sin_family = AF_INET;
    active_laddrs[i].sin_addr.s_addr = inet_addr("127.0.0.2");
    active_laddrs[i].sin_port = htons(0x1000 + i);
  }

  /* The connections are made in batches, with each batch being pushed through
   * the stack in one go. */
  struct zft* actives[NUM_CONNECTIONS];
  struct zft* passives[NUM_CONNECTIONS];
  struct zft** next_active = actives;
  struct zft** next_passive = passives;
  for( int batch = 0; batch < NUM_BATCHES; ++batch ) {
    diag("Batch %d", batch);

    int expected_queue_len[NUM_LISTENERS] = {};

    for( int active_index = 0;
         active_index < NUM_CONNECTIONS / NUM_BATCHES;
         ++active_index ) {
      struct zft_handle* ts_handle;
      ZF_TRY(zft_alloc(stack, attr, &ts_handle));
      ZF_TRY(zft_addr_bind(ts_handle, (struct sockaddr*)next_active_laddr,
                           sizeof(*next_active_laddr), 0));
      ++next_active_laddr;

      int raddr_index = rand_r(&seed) % NUM_LISTENERS;
      ++expected_queue_len[raddr_index];

      ZF_TRY(zft_connect(ts_handle,
                         (struct sockaddr*)&listen_addrs[raddr_index],
                         sizeof(listen_addrs[raddr_index]), next_active++));
    }

    do {
      zf_reactor_perform(stack);
      zf_emu_sync();
    } while ( zf_stack_has_pending_events(stack) );

    /* Drain the accept queues. */
    for( int listener_index = 0; listener_index < NUM_LISTENERS;
         ++listener_index ) {
      int rc;
      int accepted_zockets = 0;
      while( (rc = zftl_accept(listeners[listener_index], next_passive)) !=
             -EAGAIN ) {
        ++next_passive;
        ++accepted_zockets;
        cmp_ok(rc, "==", 0, "Accepted zocket %d on listener %d",
               accepted_zockets, listener_index);
      }

      cmp_ok(accepted_zockets, "==", expected_queue_len[listener_index],
             "Accepted %d zockets on listener %d.", accepted_zockets,
             listener_index);
    }
  }

  for( int i = 0; i < NUM_CONNECTIONS; ++i ) {
    cmp_ok(zft_free(actives[i]),  "==", 0, "Shut down active-open %d",  i);
    cmp_ok(zft_free(passives[i]), "==", 0, "Shut down passive-open %d", i);
  }

  while( ! zf_stack_is_quiescent(stack) )
    zf_reactor_perform(stack);

  /* Arrange for a connection to end up on listener zero's acceptq. */
  struct zft_handle* ts_handle;
  ZF_TRY(zft_alloc(stack, attr, &ts_handle));
  ZF_TRY(zft_addr_bind(ts_handle, (struct sockaddr*)&active_laddrs[0],
                       sizeof(active_laddrs[0]), 0));
  ZF_TRY(zft_connect(ts_handle, (struct sockaddr*)&listen_addrs[0],
                     sizeof(listen_addrs[0]), &actives[0]));
  while(zf_reactor_perform(stack) == 0);
  while(zf_reactor_perform(stack) != 0);

  for( int i = 0; i < NUM_LISTENERS; ++i )
    cmp_ok(zftl_free(listeners[i]), "==", 0, "Shut down listener %d", i);

  cmp_ok(zftl_listen(stack, (struct sockaddr*)&listen_addrs[0],
                     sizeof(listen_addrs[0]), attr, &listeners[0]), "==", 0,
         "Listen on a previously-used address");
  cmp_ok(zftl_free(listeners[0]), "==", 0,
         "Shut down listener");

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

