/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2018 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  gd
**  \brief  Sanity test for RX demultiplexing.
**   \date  2016/02/03
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

#include <arpa/inet.h>

#include "../tap/tap.h"
#include "abstract_zocket_pair.h"


#define NUM_ZOCKETS_OF_EACH_TYPE 8
_Static_assert(ZF_IS_POW2(NUM_ZOCKETS_OF_EACH_TYPE),
               "Number of zockets not a power of two.");

#define PACKETS_PER_ZOCKET 8
_Static_assert(ZF_IS_POW2(PACKETS_PER_ZOCKET),
               "Packets per zocket not a power of two.");

/* Test three UDP zockets:  all have the same lport, but the raddr:rport is
 * different on each, with one being wild. */
#define NUM_UDP_ZOCKET_TYPES 3

/* One TCP zocket and the UDP zockets described above. */
#define NUM_ZOCKET_TYPES (1 + NUM_UDP_ZOCKET_TYPES)
_Static_assert(ZF_IS_POW2(NUM_ZOCKET_TYPES),
               "Number of zocket types not a power of two.");

#define NUM_ZOCKETS         (NUM_ZOCKETS_OF_EACH_TYPE * NUM_ZOCKET_TYPES)
#define SCRAMBLE_ITERATIONS (NUM_ZOCKETS * PACKETS_PER_ZOCKET)
#define SCRAMBLE_ITER_MASK  (SCRAMBLE_ITERATIONS - 1)
#define SCRAMBLE_MASK       123
#define SCRAMBLE_STRIDE     (SCRAMBLE_ITERATIONS / 2 + 1)
/* The 256 here is the smallest supported ef_vi RXQ, which doesn't seem to be
 * defined symbolically anywhere. */
_Static_assert(SCRAMBLE_ITERATIONS <= 256,          "Too many scramble iters");
_Static_assert(SCRAMBLE_MASK < SCRAMBLE_ITERATIONS, "Scramble mask too big");
_Static_assert(SCRAMBLE_STRIDE % 2 == 1,            "Scramble stride not odd");

#define SINGLE_PKT_TESTS_PER_ZOCKET  2
#define SCRAMBLE_TESTS_PER_ZOCKET    2

/* The test abstracts away the type of the underlying zocket, and actually ends
 * up allocating a good many more UDP zockets than TCP zockets.  To ensure that
 * we exercise high-numbered TCP zockets, we allocate more than we need and
 * leave some unused. */
#define TCP_THROW_AWAY_FACTOR        4

static inline int zfmultizock_test(struct zf_stack* stack,
                                   struct zf_attr* attr)
{
  plan((SINGLE_PKT_TESTS_PER_ZOCKET + SCRAMBLE_TESTS_PER_ZOCKET) * NUM_ZOCKETS);

  /* Make sure that the receive buffer is larger than we expect to need for any
   * single receive operation, so that we can make sure that we never receive
   * more than expected.
   */
  const size_t RECV_BUF_SIZE = PACKETS_PER_ZOCKET + 1;
  char recv_buf[RECV_BUF_SIZE];

  struct abstract_zocket_pair zockets[NUM_ZOCKETS_OF_EACH_TYPE *
                                      NUM_ZOCKET_TYPES];

  /* Allocate TCP zockets */
  for( int i = 0; i < NUM_ZOCKETS_OF_EACH_TYPE; ++i ) {
    /* To inflate the zocket IDs artificially, allocate a bunch of zockets, all
     * but the last of which will be unused. */
    for( int j = 0; j < TCP_THROW_AWAY_FACTOR; ++j )
      alloc_tcp_pair(stack, attr, &zockets[NUM_ZOCKET_TYPES * i]);
  }

  /* Allocate UDP zockets */
  for( int i = 0; i < NUM_ZOCKETS_OF_EACH_TYPE; ++i ) {
    for( int j = 0; j < NUM_UDP_ZOCKET_TYPES ; ++j ) {
      struct sockaddr_in laddr = { AF_INET,
                                   htons(30000 + i),
                                   { inet_addr("127.0.0.2") } };
      struct sockaddr_in raddr = { AF_INET,
                                   htons(40000 + j),
                                   { inet_addr("192.168.0.1") } };
      int zocket_idx = NUM_ZOCKET_TYPES * i + j + 1 /* TCP zocket */;

      alloc_udp_pair_sockaddr_in(stack, stack, attr, &zockets[zocket_idx],
                                 &laddr, &raddr, !(j % NUM_UDP_ZOCKET_TYPES));
    }
  }

  /* Send and receive one message on each pair. */
  for( int i = 0; i < NUM_ZOCKETS; ++i ) {
    ZF_TRY(zockets[i].send(zockets[i].opaque_tx, i));
    while(zf_reactor_perform(stack) == 0);
    while(zf_reactor_perform(stack) != 0);
    cmp_ok(zockets[i].recv(zockets[i].opaque_rx, recv_buf, RECV_BUF_SIZE),
           "==", 1, "Received one packet on zocket %d", i);
    cmp_ok(recv_buf[0], "==", i, "Received correct packet on zocket %d", i);
  }

  /* Give the stack a chance to reclaim packet buffers for RX. */
  zf_reactor_perform(stack);

  /* Send PACKETS_PER_ZOCKET messages on each pair in a scrambled order. */
  for( int iter = 0; iter < SCRAMBLE_ITERATIONS; ++iter ) {
    int scrambled_iter = ((iter * SCRAMBLE_STRIDE) ^ SCRAMBLE_MASK) &
                         SCRAMBLE_ITER_MASK;
    int index = scrambled_iter / PACKETS_PER_ZOCKET;
    ZF_TRY(zockets[index].send(zockets[index].opaque_tx, index));
  }

  /* Move all packets to the appropriate zockets' receive queues.  This assumes
   * that the loopback thread keeps up with us. */
  while(zf_reactor_perform(stack) == 0);
  while(zf_reactor_perform(stack) != 0);

  /* Check that we received the correct packets on each zocket. */
  for( int i = 0; i < NUM_ZOCKETS; ++i ) {
    int len;
    cmp_ok(len = zockets[i].recv(zockets[i].opaque_rx, recv_buf, RECV_BUF_SIZE),
           "==", PACKETS_PER_ZOCKET,
           "Received correct number of packets on zocket %d", i);
    int all_bytes_correct = 1;
    for( int j = 0; j < len; ++j )
      if( recv_buf[j] != i ) {
        all_bytes_correct = 0;
        break;
      }
    ok(all_bytes_correct, "Received correct packets on zocket %d", i);
  }

  done_testing();
}


