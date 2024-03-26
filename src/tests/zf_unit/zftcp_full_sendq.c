/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2018 Advanced Micro Devices, Inc. */
#include <arpa/inet.h>

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/tcp_tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>

#include "../tap/tap.h"
#include "abstract_zocket_pair.h"


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


static int recv_all(struct zf_stack* stack, struct zft* tcp, int len)
{
  int recved = 0;
  struct {
    struct zft_msg header;
    struct iovec iov[SW_RECVQ_MAX];
  } msg;

  /* The timing of running with loopback emulation means that some packets
   * might not be received before the first zft_zc_recv() call, so loop
   * until the required length is received.
   */
  while( recved < len ) {
    unsigned recved1 = 0;

    msg.header.iovcnt = SW_RECVQ_MAX;
    zft_zc_recv(tcp, &msg.header, 0);

    for( int i = 0; i < msg.header.iovcnt; i++ )
      recved1 += msg.iov[i].iov_len;

    if( recved1 == 0 ) {
      while( zf_reactor_perform(stack) == 0 );
      while( zf_reactor_perform(stack) != 0 );

      continue;
    }

    zft_zc_recv_done(tcp, &msg.header);
    recved += recved1;
  }

  return recved;
}


struct tcp_pair {
  struct abstract_zocket_pair zockets;
  struct zft* tx;
  struct zft* rx;
};


static void init_pair(struct zf_stack* stack, struct zf_attr* attr,
                      struct tcp_pair* pair)
{
  struct zftl* listener;
  alloc_tcp_pair_listener(stack, attr, &listener);

  auto nop = [] {}; /* lambda expression doing nothing */
  alloc_tcp_pair_t(stack, stack, attr, &pair->zockets, nop, listener);

  struct zf_tcp* tcp_tx_state = (struct zf_tcp*) pair->zockets.opaque_tx;
  pair->tx = &tcp_tx_state->ts;
  struct zf_tcp* tcp_rx_state = (struct zf_tcp*) pair->zockets.opaque_rx;
  pair->rx = &tcp_rx_state->ts;
}


int max_rand_size(int mss)
{
  return 3 * mss;
}


int rand_size(int mss)
{
  return (random() % max_rand_size(mss)) + 1;
}


#define MSG_MSS -1
#define MSG_RANDOM -2
#define INITIAL_SENDS 256
#define N_TESTS (( 2 * INITIAL_SENDS ) + 4)
static int test(struct zf_stack* stack, struct zf_attr* attr, int msg_size)
{
  struct tcp_pair p1;
  struct tcp_pair p2;
  int rc;
  int mss;

  /* Allocate TCP zockets */
  init_pair(stack, attr, &p1);
  init_pair(stack, attr, &p2);

  mss = zft_get_mss(p1.tx);

  if( msg_size == MSG_MSS )
    msg_size = mss;

  char buf[msg_size > 0 ? msg_size : max_rand_size(mss)] = {0};

  /* Firstly open the TCP window for both zocket pairs */
  for( int i = 0; i < INITIAL_SENDS; ++i ) {
    cmp_ok(zft_send_single(p1.tx, buf, mss, 0), "==", mss,
           "sent %d bytes", mss);
    recv_all(stack, p1.rx, mss);
  }

  for( int i = 0; i < INITIAL_SENDS; ++i ) {
    cmp_ok(zft_send_single(p2.tx, buf, mss, 0), "==", mss,
           "sent %d bytes", mss);
    recv_all(stack, p2.rx, mss);
  }

  /* Now try and fill the TXQ.  We won't be calling zf_reactor_perform,
   * so the HW TXQ should fill, before causing the zocket sendq to fill.
   */
  int bytes_sent = 0;
  while( (rc = zft_send_single(p1.tx, buf, msg_size > 0 ?
                               msg_size : rand_size(mss), 0)) > 0 )
    bytes_sent += rc;

  /* Sendq should now have filled, so send should fail with EAGAIN */
  cmp_ok(rc, "==", -EAGAIN, "send on p1 with rc %d", rc);

  /* At this point p2 thinks that things are good to send, but p1 has filled
   * up the common TXQ, so we should try and do a fast send. This should
   * fail, but there's space on the zocket sendq, so the send itself should
   * succeed.
   */
  int send = msg_size > 0 ? msg_size : rand_size(mss);
  rc = zft_send_single(p2.tx, buf, send, 0);
  cmp_ok(rc, "==", send, "send on p2 with rc %d", rc);

  /* recv_all will poll the reactor, which should drain the completions, and
   * cause the queued tcp segment to be posted.
   */
  rc = recv_all(stack, p2.rx, send);
  cmp_ok(rc, "==", send, "received data on p2");

  /* Check that all the data from p1 that we used to stuff the ring, and the
   * subsequent data that got queued on the zocket recvq, is received ok.
   */
  rc = recv_all(stack, p1.rx, bytes_sent);
  cmp_ok(rc, "==", bytes_sent, "received data on p1");

  return 0;
}

static const int msg_sizes[] = { MSG_RANDOM, MSG_MSS, 3, 800, 1459, 3000 };
const int n_msg_sizes = sizeof(msg_sizes)/sizeof(msg_sizes[0]);

int main(void)
{
  int rc;
  struct zf_stack* stack;
  struct zf_attr* attr;

  int seed = zf_frc64();
  srandom(seed);
  diag("Using seed %d", seed);

  plan(N_TESTS * n_msg_sizes);

  for( int i = 0; i < n_msg_sizes; i++ ) {
    ZF_TRY(init(&stack, &attr));
    rc = test(stack, attr, msg_sizes[i]);
    ZF_TRY(fini(stack, attr));
  }

  done_testing();

  return rc;
}

