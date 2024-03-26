/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2023 Advanced Micro Devices, Inc. */
#include <arpa/inet.h>

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/private/zf_emu.h>
#include <zf_internal/rx_res.h>

#include <zf_internal/private/tcp_fast.h>
#include <zf_internal/zf_stack.h>

#include "../tap/tap.h"

#include "abstract_zocket_pair.h"

#include "dataverifier.h"

static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  /* Request the default allocation of buffers explicitly. */
  zf_attr_set_int(*attr_out, "n_bufs", 0);

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


enum {
  RECV_MODE_ZC_RECV_PLANE,
  RECV_MODE_ZC_RECV_SOME,
  RECV_MODE_ZC_RECV_SOME_IN_HALVES,
  RECV_MODE_COUNT,
};



static int recv_all(struct zf_stack* stack, struct zft* tcp, int recv_mode,
                    int len)
{
  int recved = 0;
  struct {
    struct zft_msg header;
    struct iovec iov[SW_RECVQ_MAX];
  } msg;
  bool passed = true;

  /* The timing of running with loopback emulation means that some packets
   * might not be received before the first zft_zc_recv() call, so loop
   * until the required length is received.
   */
  while( recved < len ) {

    while( zf_reactor_perform(stack) != 0 );

    msg.header.iovcnt = SW_RECVQ_MAX;
    zft_zc_recv(tcp, &msg.header, 0);

    int recved1 = verify_msg(msg);

    if( recved1 == 0 )
      continue;

    passed &= recved1 > 0;

    switch( recv_mode ) {
    case RECV_MODE_ZC_RECV_PLANE:
      zft_zc_recv_done(tcp, &msg.header);
      break;
    case RECV_MODE_ZC_RECV_SOME:
      zft_zc_recv_done_some(tcp, &msg.header, recved1);
      break;
    case RECV_MODE_ZC_RECV_SOME_IN_HALVES:
      {
        /* undo verifier as we only going to mark half of the data */
        verifier.accountRead(-recved1);
        /* first we read some bytes */
        recved1 = recved1 / 2;
        ZF_TRY(zft_zc_recv_done_some(tcp, &msg.header, recved1));
        verifier.accountRead(recved1);

        /* And then we read the rest */
        zft_zc_recv(tcp, &msg.header, 0);
        if( ! verify_msg(msg) ) {
          diag("msg validation failed");
          passed = false;
        }

        unsigned recved2 = 0;
        for( int i = 0; i < msg.header.iovcnt; i++ )
          recved2 += msg.iov[i].iov_len;
        ZF_TRY(zft_zc_recv_done_some(tcp, &msg.header, recved2));
        /* In total we should have read all */
        recved1 += recved2;
      }
      break;
    }

    recved += recved1;
  }

  return !passed ? -1 : recved;
}


#define BIGGEST_SEND 150000
static char big_buf[BIGGEST_SEND];

static void send_big(struct zf_stack* stack, struct zft* tcp, int n, size_t len)
{
  int mss = zft_get_mss(tcp);

  for( int i = 0; i < n; i++ ) {
    struct iovec iov = { &big_buf[i%127], len };

    verifier.fillWBuf((char*) iov.iov_base, iov.iov_len);

    do {
      size_t send_space;
      ZF_TRY(zft_send_space(tcp, &send_space));

      int rc = zft_send(tcp, &iov, 1, 0);
      if( rc > 0 )
        verifier.accountWritten(rc);
      verify_txq(tcp);

      diag("send_big zft_send returned %d of len %d, iovlen %d mss %d spc %zu",
           rc, (int)len, (int)iov.iov_len, mss, send_space);
      /* If the send will fit into the send buffer, we expect it to go all in
       * one go.  */
      if( iov.iov_len <= send_space )
        zf_assert_equal(rc, (int) iov.iov_len);

      if( rc > 0 ) {
        iov.iov_len -= rc;
        iov.iov_base = (char*)iov.iov_base + rc;
      }
      else {
        diag("error from zft_send: %d", rc);
        zf_assert_equal(rc, -EAGAIN);
      }

      /* Poll until a user-visible event is seen:
       *  - in EAGAIN case, space will be freed on the sender
       *  - in successful case with payload, the payload is queued for receive
       * A successful send of a zero-length payload won't result in a
       * user-visible event for the receiver, so no need to wait in that case.
       */
      if( (rc == 0 && iov.iov_len != 0) || rc == -EAGAIN ) {
        /* TODO If this happens we may be stuck waiting for receiver
         * to drain, which we don't do until we've completed the
         * send.  For current settings of BIGGEST_SEND we are OK
         */
        diag("Waiting for space");
        while(zf_reactor_perform(stack) == 0);
      }

     /* Then poll until everything has been handled. */
      while(zf_reactor_perform(stack) != 0);
    } while( iov.iov_len );
  }
  verify_txq(tcp);
}


static void send_n(struct zf_stack* stack, struct zft* tcp, int n, size_t len)
{
  char _buf[TCP_MAX_MSS + 1000];

  for( int i = 0; i < n; i++ ) {
    struct iovec iov = { &_buf[i%1000], len };
    verifier.fillWBuf((char*)iov.iov_base, iov.iov_len);
    int rc = zft_send(tcp, &iov, 1, 0);
    if( rc > 0 )
      verifier.accountWritten(rc);
    verify_txq(tcp);

    if( rc == -EAGAIN )
      /* Retry iteration after polling below */
      i--;

    /* Poll until a user-visible event is seen:
     *  - in EAGAIN case, space will be freed on the sender
     *  - in successful case with payload, the payload is queued for receive
     * A successful send of a zero-length payload won't result in a
     * user-visible event for the receiver, so no need to wait in that case.
     */
    if( (rc == 0 && len != 0) || rc == -EAGAIN )
      while(zf_reactor_perform(stack) == 0);

    /* Then poll until everything has been handled. */
    while(zf_reactor_perform(stack) != 0);
  }
  verify_txq(tcp);
}


static const int fixed_segs[] = { 1, 2, 3, 20, 40, 50, 162, 355, 701, 741, 1460,
                                  TCP_MAX_MSS };
const int fixed_seg_n = sizeof(fixed_segs)/sizeof(fixed_segs[0]);

enum ring_start {
  DONT_CHANGE,
  SET_RANDOM,
  RING_END,
  RING_START_TYPE_MAX
};

/* We dodgily poke around inside the RX ring, so that we can test the
 * index wrapping without having to send billions of packets.
 */
static void set_ring_start(struct zf_tcp* tcp, unsigned val)
{
  /* We can only safely furtle this if everything's the same value */
  zf_assert_equal(tcp->tsr.ring.begin_read, tcp->tsr.ring.begin_process);
  zf_assert_equal(tcp->tsr.ring.begin_read, tcp->tsr.ring.end);

  tcp->tsr.ring.begin_read = val;
  tcp->tsr.ring.begin_process = val;
  tcp->tsr.ring.end = val;
}


static void select_ring_start(struct zft* tcp_rx, int start)
{
  switch( start ) {
    case DONT_CHANGE:
      break;
    case SET_RANDOM:
      set_ring_start((struct zf_tcp*)tcp_rx, random());
      break;
    case RING_END:
      set_ring_start((struct zf_tcp*)tcp_rx, UINT32_MAX - 4);
      break;
  }
}


static void fixed_tests(struct zf_stack* stack, struct zft* tcp_tx,
                        struct zft* tcp_rx, int ring_start, int recv_mode)
{
  for( int i = 0; i < fixed_seg_n; i++ ) {
    select_ring_start(tcp_rx, ring_start);
    (void) select_ring_start;

    int n = TCP_WND/fixed_segs[i];
    int len = n * fixed_segs[i];
    send_n(stack, tcp_tx, n, fixed_segs[i]);
    cmp_ok(recv_all(stack, tcp_rx, recv_mode, len), "==", len,
           "mode %d, send size %d ring %d fill with %d",
           recv_mode, fixed_segs[i], ring_start, n);
  }
}


#define big_n 3
static void big_tests(struct zf_stack* stack, struct zft* tcp_tx,
                      struct zft* tcp_rx, int ring_start, int random_n,
                      int recv_mode)
{
  const int small_size = 1000;

  select_ring_start(tcp_rx, ring_start);

  for( int i = 0; i < random_n; i++ ) {
    int big_size = (random() % (30000)) + 65535;
    send_n(stack, tcp_tx, 1, small_size);
    cmp_ok(recv_all(stack, tcp_rx, recv_mode, small_size), "==", small_size,
           "initial small send: mode %d, send size %d ring %d fill",
           recv_mode, small_size, ring_start);
    send_big(stack, tcp_tx, 1, big_size);
    cmp_ok(recv_all(stack, tcp_rx, recv_mode, big_size), "==", big_size,
           "big send: mode %d, send size %d ring %d fill with %x",
           recv_mode, big_size, ring_start);
    send_n(stack, tcp_tx, 1, small_size);
    cmp_ok(recv_all(stack, tcp_rx, recv_mode, small_size), "==", small_size,
           "final small send: mode %d, send size %d ring %d fill with %x",
           recv_mode, small_size, ring_start);
  }
}


static void random_tests(struct zf_stack* stack, struct zft* tcp_tx,
                         struct zft* tcp_rx, int ring_start, int random_n,
                         int recv_mode)
{
  for( int i = 0; i < random_n; i++ ) {
    select_ring_start(tcp_rx, ring_start);

    int bytes_sent = 0;
    while( bytes_sent < TCP_WND ) {
      int this_send = random() % TCP_MAX_MSS;
      /* Increment this_send to:
       * - avoid 0 byte sends, which are invalid in ZF and not policed
       * - allow sends to actually reach TCP_MAX_MSS
       */
      this_send++;
      this_send = MIN( this_send, TCP_WND - bytes_sent );
      if( this_send / 10 )
        send_n(stack, tcp_tx, 10, this_send / 10);
      bytes_sent += this_send / 10 * 10;
      if( this_send % 10 )
        send_n(stack, tcp_tx, 1, this_send % 10);
      bytes_sent += this_send % 10;

    }
    cmp_ok(recv_all(stack, tcp_rx, recv_mode, TCP_WND), "==", bytes_sent,
           "mode %d, random send ring %d",
           recv_mode, ring_start);
  }
}


#define ZC_RECV_TEST_COUNT (SW_RECVQ_MAX * 3 + 3)

/* Test coalescing while ZC-receive operations of different sizes are in
 * progress. */
static void
zc_recv_tests(struct zf_stack* stack, struct zft* ts_tx, struct zft* ts_rx)
{
  struct zf_tcp* tcp_rx = ZF_CONTAINER(struct zf_tcp, ts, ts_rx);

  struct {
    struct zft_msg header;
    struct iovec iov[SW_RECVQ_MAX];
  } msg;

  for( uint32_t zc_pkts = 0; zc_pkts <= SW_RECVQ_MAX; ++zc_pkts ) {
    zf_assert_equal(zfr_queue_packets_unread_n(&tcp_rx->tsr), 0);

    /* Refill the recvq. */
    char c;
    struct iovec vec = {&c, 1};
    tcp_rx_flush(stack, tcp_rx);
    for( uint32_t i = 0; i < SW_RECVQ_MAX; ++i ) {
      int rc;
      verifier.fillWBuf(&c, 1);
      ZF_TRY(rc = zft_send(ts_tx, &vec, 1, 0));
      verifier.accountWritten(rc);
      while( zf_reactor_perform(stack) == 0 );
      while( zf_reactor_perform(stack) == 1 );
    }

    zf_assert_equal(zfr_queue_packets_unread_n(&tcp_rx->tsr), SW_RECVQ_MAX);

    /* Start a ZC receive. */
    msg.header.iovcnt = zc_pkts;
    zft_zc_recv(ts_rx, &msg.header, 0);
    zf_assert_equal((uint32_t) msg.header.iovcnt, zc_pkts);
    cmp_ok(verify_msg(msg), ">=", 0, "msg validation");

    /* Coalesce. */
    zfr_queue_coalesce(&tcp_rx->tsr, stack);

    /* Make sure that we didn't attempt to coalesce the ZC packets. */
    cmp_ok(zfr_queue_packets_unread_n(&tcp_rx->tsr), ">=", zc_pkts,
           "Didn't coalesce %d ZC packets.", zc_pkts);

    if( zc_pkts < SW_RECVQ_MAX ) {
      /* If we're going to loop around again, finish the ZC read and empty the
       * ring in preparation for the next iteration. */

      if( zc_pkts > 0 )
        zft_zc_recv_done(ts_rx, &msg.header);

      msg.header.iovcnt = SW_RECVQ_MAX;
      zft_zc_recv(ts_rx, &msg.header, 0);
      cmp_ok(verify_msg(msg), ">=", 0, "msg validation");
      if( msg.header.iovcnt > 0 )
        zft_zc_recv_done(ts_rx, &msg.header);
    }
    else {
      /* On the last iteration, where the ring is still full after attempting
       * to coalesce, we try sending another packet and making sure that we
       * don't trip any assertions. */
      int rc;
      verifier.fillWBuf(&c, 1);
      ZF_TRY(rc = zft_send(ts_tx, &vec, 1, 0));
      verifier.accountWritten(rc);
      zf_reactor_perform(stack);
      pass("Survived sending to un-coalescable queue.");
    }
  }
}


static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  const int random_n = 10;
  struct abstract_zocket_pair zockets;
  int seed = zf_frc64();
  srandom(seed);
  diag("Using seed %d", seed);


  /* Allocate TCP zockets */
  alloc_tcp_pair(stack, attr, &zockets);
  struct zft* tcp_tx = (struct zft*)zockets.opaque_tx;
  struct zft* tcp_rx = (struct zft*)zockets.opaque_rx;

  DataVerifier::Guard dv(verifier, 5, tcp_tx, tcp_rx);

  for( int j = 0; j < RECV_MODE_COUNT; j++ ) {
    for( int i = 0; i < RING_START_TYPE_MAX; i++ ) {
      /* let's make sure no baggage from previous iteration */
      quiesce_sender(stack, tcp_tx);
      fixed_tests(stack, tcp_tx, tcp_rx, i, j);
      quiesce_sender(stack, tcp_tx);
      big_tests(stack, tcp_tx, tcp_rx, i, random_n, j);
      quiesce_sender(stack, tcp_tx);
      random_tests(stack, tcp_tx, tcp_rx, i, random_n, j);
      quiesce_sender(stack, tcp_tx);

      SegmentDropper::Guard d(dropper, (zf_tcp*)tcp_rx, 2);
      random_tests(stack, tcp_tx, tcp_rx, i, random_n, j);
    }
  }

  zc_recv_tests(stack, tcp_tx, tcp_rx);

  zockets.close(&zockets);
  while( !zf_stack_is_quiescent(stack) )
    zf_reactor_perform(stack);

  return RECV_MODE_COUNT * RING_START_TYPE_MAX *
       (fixed_seg_n + 2 * random_n + (big_n * random_n)) +
       ZC_RECV_TEST_COUNT;
}

 /* Test whether using two sockets, one with vlan and one without
  * leads to corruption.
  * It uses a force_switch_vlan_on_connect hack to achieve this.
  * Before ON-13385 fixes the test would hit assertion in ef_vi.
  */
static int test_ON_13385(struct zf_stack* stack, struct zf_attr* attr)
{
  struct abstract_zocket_pair z1;
  /* select vlan or no vlan - opposite of default */
  int want_vlan = attr->emu_vlan == ZF_NO_VLAN ? 1 : ZF_NO_VLAN;

  zf_emu_set_vlan_override(true, z1.default_listen_addr, want_vlan);

  /* Allocate TCP zockets, tx zocket will get a tx path with changed vlan
  * while rx zocket will get tx path with original vlan */
  alloc_tcp_pair(stack, attr, &z1);
  /* just sanity checks so that we know we got what we wanted */
  cmp_ok(((zf_tcp*)z1.opaque_tx)->tst.path.vlan, "==", want_vlan, "tx zock switched vlan");
  cmp_ok(((zf_tcp*)z1.opaque_rx)->tst.path.vlan, "==", attr->emu_vlan, "rx zock keeps original vlan");

  constexpr int send_size = 1600; // >MTU
  char buf[send_size];
  iovec iov[1] = { {buf, send_size} };

  for( int i = 0; i < 4; ++i ) {
    auto tx = (zft*) (i & 1 ? z1.opaque_tx : z1.opaque_rx);
    auto rx = (zft*) (i & 1 ? z1.opaque_rx : z1.opaque_tx);
    /* Do slow send (>MTU) alternating directions that is use of vlan for tx */
    DataVerifier::Guard dv(verifier, 5, tx, rx);
    verifier.fillWBuf(&buf[0], send_size);
    ZF_TRY(zft_send(tx, iov, 1, 0));
    verifier.accountWritten(send_size);
    cmp_ok(recv_all(stack, rx, 0, send_size), "==", send_size,
          "passed vlan traffic on slow path %i", i);
    quiesce_sender(stack, tx);
  }

  z1.close(&z1);
  while( !zf_stack_is_quiescent(stack) )
    zf_reactor_perform(stack);

  zf_emu_set_vlan_override(false, 0, 0);
  return 6;
}


int main(void)
{
  int test_count = 0;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(init(&stack, &attr));
  test_count += test(stack, attr);
  test_count += test_ON_13385(stack, attr);
  ZF_TRY(fini(stack, attr));

  plan(test_count);

  done_testing();
}

