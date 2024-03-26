/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2022 Advanced Micro Devices, Inc. */
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
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/tcp.h>
#include <zf_internal/private/zf_emu.h>

#include <arpa/inet.h>
#include <unistd.h>

#include "abstract_zocket_pair.h"
#include "../tap/tap.h"


#define MAX_PACKETS_IN_PIPE 32

/* TODO: set it to 10~400 once it is clear problems are flushed */
#define TEST_SPEEDUP 100
#define FINWAIT_MS 3700
#define TIMEWAIT_MS 4700

static int init(struct zf_stack** stack_out, struct zf_attr** attr_out,
                const char* interface, int timeout_factor)
{
  int rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  /* This test requires the back 2 back shim. */
  ZF_TEST((*attr_out)->emu == 1);

  /* For TCP FINWAIT test rx ztack needs to have timeouts much longer than
   * tx ztack.  This is to allow in this ztack state progression based on packets
   * not timeouts (while tx ztack states are progressed based on timeouts). */
  (*attr_out)->tcp_finwait_ms = FINWAIT_MS * timeout_factor;
  (*attr_out)->tcp_timewait_ms = TIMEWAIT_MS * timeout_factor;

  ZF_TRY(zf_attr_set_str(*attr_out, "interface", interface));

  rc = zf_stack_alloc(*attr_out, stack_out);
  if( rc != 0 ) {
    zf_attr_free(*attr_out);
    return rc;
  }

#if TEST_SPEEDUP != 1
  /* Using insight into zf_timekeeping we make stack tick x times faster
   * to speed the tests */
  #define ZF_TICK_DURATION_US (TCP_TMR_INTERVAL * 1000)
  zf_timekeeping_init(&(*stack_out)->times.time, ZF_TICK_DURATION_US / TEST_SPEEDUP);
#endif

  return 0;
}


static int fini(struct zf_stack* stack, struct zf_attr* attr)
{
  int rc;

  rc = zf_stack_free(stack);
  if( rc != 0 )
    return rc;
  zf_attr_free(attr);

  return 0;
}


static const int RESULTS_PER_RETRY_RTO = 10;
static const int MAX_RETRY_COUNT_RTO = 3;

static const int RESULTS_PER_RETRY_ZWIN = 9;
static const int MAX_RETRY_COUNT_ZWIN = 5;

static const int RESULTS_PER_RETRY_FIN = 7;
static const int MAX_ITER_COUNT_FIN = 4;

static int test_step_rto(struct zf_stack* stacks[], struct zf_attr* attr[], int retries);
static int test_step_zwin(struct zf_stack* stacks[], struct zf_attr* attr[], int retries);
static int test_step_fin(struct zf_stack* stacks[], struct zf_attr* attr[], int retries);

static int test(struct zf_stack* stacks[], struct zf_attr* attr[])
 {
  plan(RESULTS_PER_RETRY_RTO * MAX_RETRY_COUNT_RTO +
       RESULTS_PER_RETRY_ZWIN * (MAX_RETRY_COUNT_ZWIN + 1) +
       RESULTS_PER_RETRY_FIN * MAX_ITER_COUNT_FIN);
  /* TODO without DACK the test for retries > 1 will get stuck */
  int rc;
  auto quiesce = [stacks] () {
    while( ! (zf_stack_is_quiescent(stacks[0]) &&
              zf_stack_is_quiescent(stacks[1])) ) {
      zf_reactor_perform(stacks[0]);
      zf_reactor_perform(stacks[1]);
    }
  };
  for( int retries = 0;  retries < MAX_ITER_COUNT_FIN; ++retries ) {
    rc = test_step_fin(stacks, attr, retries);
    if( rc != 0)
      return rc;
    quiesce();
  }
  quiesce();
  for( int retries = 0;  retries <= MAX_RETRY_COUNT_ZWIN; ++retries ) {
    rc = test_step_zwin(stacks, attr, retries);
    if( rc != 0)
      return rc;
    quiesce();
  }
  for( int retries = 1;  retries <= MAX_RETRY_COUNT_RTO; ++retries ) {
    rc = test_step_rto(stacks, attr, retries);
    if( rc != 0)
      return rc;
    quiesce();
  }
  return rc;
}


static int test_step_rto(struct zf_stack* stacks[], struct zf_attr* attr[], int retries)
{
  struct abstract_zocket_pair zocks;

  /* connect with loss of SYN */

  /* lambda function doing purge, it alloc_tcp_pair will call it
   * after connect, before accept */
  auto purge = [stacks, retries] {
    for( int i = 0; i < retries; ++i ) {
      zf_reactor_process_timers(stacks[1]);
      while( zf_reactor_purge(stacks[1]) != ZF_REACTOR_PURGE_STATUS_RX ) {
       zf_reactor_perform(stacks[0]);
       zf_reactor_process_timers(stacks[1]);
      }
    }
  };

  alloc_tcp_pair_t(stacks[0], stacks[1], attr[0], &zocks, purge);

  ok(1, "Socket connected after %d SYN retries", retries);

  while( (zf_reactor_perform(stacks[1]) | zf_reactor_perform(stacks[0])) != 0 )
    ; /* colon stays here to defeat gcc6 indentation checker */

  {
    int ct1 = zf_wheel_get_current_tick(&stacks[1]->times.wheel);
    /* send one packet without retrans */
    ZF_TRY(zocks.send(zocks.opaque_tx, 'l'));
    while( zf_reactor_perform(stacks[1]) == 0 )
      zf_reactor_perform(stacks[0]);

    char abuf;
    ZF_TRY(zocks.recv(zocks.opaque_rx, &abuf, 1));
    int ct2 = zf_wheel_get_current_tick(&stacks[1]->times.wheel);

    cmp_ok(abuf, "==", 'l',
           "%d: Received one packet on zocket - no retrans", retries);
    cmp_ok(ct1 + 1, ">=", ct2,
           "%d: Received one packet on zocket in time - no retrans", retries);
  }

  uint32_t retrans_before = stacks[0]->stats.tcp_retransmits;
  /* get ACK */
  while( (zf_reactor_perform(stacks[1]) | zf_reactor_perform(stacks[0])) != 0 );

  int ct1 = zf_wheel_get_current_tick(&stacks[0]->times.wheel);

  /* send data to be lost */
  diag("Purging\n");
  ZF_TRY(zocks.send(zocks.opaque_tx, 'a'));

  /* purge rx ring to simulate pkt loss and induce retransmission.
   */
  purge();

  /* Now wait for restranmission, when we have no RTT (SYN was also retransmitted)
   * then the period is really long. And timer resolution happens to decrease
   * about 33 ticks ahead hence we check the result is within bracket rather than
   * precise.
   */

  while( zf_reactor_perform(stacks[1]) == 0 )
    zf_reactor_perform(stacks[0]);

  uint32_t retrans_after = stacks[0]->stats.tcp_retransmits;
  cmp_ok(retrans_after - retrans_before, ">=", 1,  "Retransmission packets received!");

  char recv_buf[1];
  cmp_ok(zocks.recv(zocks.opaque_rx, recv_buf, 1),
         "==", 1, "%d: Received one packet on zocket", retries);
  int ct2 = zf_wheel_get_current_tick(&stacks[0]->times.wheel);
  cmp_ok(recv_buf[0], "==", 'a',
         "%d: Packet content OK", retries);

  auto expected_RTO_duration = [&](int cnt) -> int {
    /* This snippet tries to replicate actual implementation within zf tcp */
    static const uint8_t tcp_backoff[] =
      { 1, 2, 3, 4, 5, 6, 7 };
    int sa = 1 << 3;
    int sv = 1 << 1;
    int base = (sa >> 3) + sv;
    int result = base;
    for( int i = 1; i < cnt; ++i )
      result += base << tcp_backoff[i - 1];
    return result;
  };
  cmp_ok(ct2 - ct1, ">=", expected_RTO_duration(retries),
         "%d: Retransmitted packet received within limit (min)", retries);
  todo("bug65362: System jitter makes this test invalid.");
    cmp_ok(ct2 - ct1, "<=", (expected_RTO_duration(retries) + 1) * 11 / 10,
           "%d: Retransmitted packet received within limit (max)", retries);
  end_todo;
  cmp_ok(zft_state((zft*)zocks.opaque_tx), "==", TCP_ESTABLISHED,
         "%d: tx zocket is still ok", retries);
  cmp_ok(zft_state((zft*)zocks.opaque_rx), "==", TCP_ESTABLISHED,
         "%d: rx zocket is still ok", retries);
  zft_shutdown_tx((zft*)zocks.opaque_rx);
  zft_shutdown_tx((zft*)zocks.opaque_tx);
  zft_free((zft*)zocks.opaque_rx);
  zft_free((zft*)zocks.opaque_tx);
  return 0;
}

static int test_step_zwin(struct zf_stack* stacks[], struct zf_attr* attr[], int retries)
{
  struct abstract_zocket_pair zocks;

  /* purge r purges replies of receive side */
  auto purge_r = [stacks] (int count) {
    for( int i = 0; i < count; ++i ) {
      zf_reactor_process_timers(stacks[0]);
      while( ! (zf_reactor_purge(stacks[0]) & ZF_REACTOR_PURGE_STATUS_RX) ) {
       zf_reactor_perform(stacks[1]);
       zf_reactor_process_timers(stacks[0]);
      }
    }
  };

  auto nop = [] {};
  alloc_tcp_pair_t(stacks[0], stacks[1], attr[0], &zocks, nop);

  ok(1, "zwin %d: Socket connected", retries);

  diag("stuff the pipe");
  /* We are wrting to sender, however
   * receiver is not reading and soon its buffers (window) will get filled up, and
   * it will signal 0 window.
   * Sender's buffer will start to be used and eventually
   * zft_send will stop accepting new data */
  static const unsigned SEND_SIZE = 1460;
  auto send = [&zocks] () -> int{
    char recv_buf[SEND_SIZE] = {};
    return zft_send_single((zft*)zocks.opaque_tx, recv_buf, sizeof(recv_buf), 0);
  };
  int pkts_written = 0;
  for( int i = 0; i < 128; ++i) {
    int rc = send();
    if( rc == -EAGAIN ) {
      for( int j = 0; j < 10 ; ++j ) {
        usleep(100); /* give time emushim to pass events */
        while( (zf_reactor_perform(stacks[1]) | zf_reactor_perform(stacks[0])) != 0 );
      }
      continue;
    }
    ZF_TEST(rc == SEND_SIZE);
    ++pkts_written;

    /* Process TX completion events. Otherwise EFCT will stall when it believes
     * the TX FIFO to be full, causing retransmissions that might upset the
     * remainder of the test. */
    zf_reactor_perform(stacks[0]);
  }

  /* now transmission is stuck only receiver's window update (non zero one)
   * can enable progress. */
  while( (zf_reactor_perform(stacks[1]) | zf_reactor_perform(stacks[0])) != 0 );

  diag("zwin %d: wait some time to see %d zwin probe replies", retries, retries);
  purge_r(retries);
  /* Well, could a delayed ACK be mistaken by zwin probe reply?
   * Nonetheless with multiple retries we should have seen some zwin probe replies
   * for sure */
  ok(1, "zwin %d: seen %d zwin probe retries", retries, retries);


  diag("Read some data");
  /* Reading some data from receiver should trigger
   * sending of window update to the sender.
   * However, being cheeky we purge this update and wait for sender
   * to ask for update explicitely with zero window probe
   * (or even repeated number of zero window probes),
   * If sender fails to do so all gets stuck.
   */
  auto quick_read = [&zocks] () -> int {
    struct {
      struct zft_msg zcr;
      struct iovec iov[2];
    } rd = {};
    rd.zcr.iovcnt = 1;
    zft_zc_recv((zft*)zocks.opaque_rx, &rd.zcr, 0);
    if( rd.zcr.iovcnt ) {
      zft_zc_recv_done((zft*)zocks.opaque_rx, &rd.zcr);
      return rd.iov[0].iov_len;
    }
    return 0;
  };

  /* Read packets to trigger wnd update from receiver.  This in turn allows the
   * sendq to begin draining on the sending side.  We need to make sure to read
   * enough data that the sender's sendq passes the threshold for advertised
   * writability, and also enough to trigger a window update.
   */
  uint32_t read_length = MAX(
    (uint32_t) (2 * TCP_WND_UPDATE_THRESHOLD),
    ((struct zf_tcp*) zocks.opaque_tx)->pcb.snd_buf_advertisement_threshold);
  for( uint32_t i = 0; i < read_length; i += SEND_SIZE ) {
    ZF_TEST(quick_read() == SEND_SIZE);
    --pkts_written;
  }
  ok(1, "zwin %d: read packets to trigger wnd update from receiver", retries);
  diag("Purge window update from receiver");
  purge_r(1);
  ok(1, "zwin %d: Purged window update from receiver", retries);
  purge_r(retries);
  ok(1, "zwin %d: Purged %d zwin probe replies from receiver", retries, retries);

  cmp_ok(send(), "==", -EAGAIN,
         "zwin %d: still no space in zocket", retries);

  /* wait for window update (requires sending another zwin probe) */
  while( zf_reactor_perform(stacks[0]) == 0 ) {
   zf_reactor_perform(stacks[1]);
  }

  ok(1, "zwin %d: Got window update", retries);

  diag("Push some more data as there should be space now");
  cmp_ok(send(), "==", SEND_SIZE,
         "zwin %d: now more space on receiver detected", retries);
  pkts_written++;

  /* Read up all the data - should be a breeze now
   */
  diag("read all data");
  for( int i = 0; i < pkts_written; ++i) {
    int rc;
    do {
      while( (zf_reactor_perform(stacks[1]) | zf_reactor_perform(stacks[0])) != 0 );

      rc = quick_read();
    } while( rc == 0 );
    ZF_TEST(rc == SEND_SIZE);
  }
  ok(1, "zwin %d: read up all data despite all the hurdles", retries);
  zft_shutdown_tx((zft*)zocks.opaque_rx);
  zft_shutdown_tx((zft*)zocks.opaque_tx);
  zft_free((zft*)zocks.opaque_rx);
  zft_free((zft*)zocks.opaque_tx);
  return 0;
}


/* test tests primarily FIN_WAIT and secondary TIME_WAIT timeout expiry
 * test comes in total 4 combinations:
 *  * FIN_WAIT1 or FIN_WAIT2 timeout,
 *  * orphaning at or after entering specific FIN_WAIT state.
 */
static int test_step_fin(struct zf_stack* stacks[], struct zf_attr* attr[], int retries)
{
  struct abstract_zocket_pair zocks;

  auto nop = [] {};
  alloc_tcp_pair_t(stacks[0], stacks[1], attr[0], &zocks, nop);
  bool test_fin_wait2 = retries & 1;
  bool test_shutdown = retries & 2;

  while( (zf_reactor_perform(stacks[1]) | zf_reactor_perform(stacks[0])) != 0 )
    ;

  while(zf_reactor_perform(stacks[0]) != 0);
  if( ! test_shutdown ) {
    /* orphan now */
    zft_free((zft*)zocks.opaque_tx);
  }
  else {
    /* orphan later */
    zft_shutdown_tx((zft*)zocks.opaque_tx);
  }

  int fin_state = TCP_FIN_WAIT1;
  if( test_fin_wait2 ) {
    /* bring socket into FIN_WAIT2 */
    cmp_ok(zft_state((zft*)zocks.opaque_rx), "==", TCP_ESTABLISHED,
           "%d: rx zocket is in ESTABILISHED", retries);
    /* make alien stack to ACK our FIN */
    while( zft_state((zft*)zocks.opaque_tx) == TCP_FIN_WAIT1) {
      zf_reactor_perform(stacks[0]);
      zf_reactor_perform(stacks[1]);
    }
    cmp_ok(zft_state((zft*)zocks.opaque_rx), "==", TCP_CLOSE_WAIT,
           "%d: rx zocket is in CLOSE_WAIT", retries);
    cmp_ok(zft_state((zft*)zocks.opaque_tx), "==", TCP_FIN_WAIT2,
           "%d: tx zocket is in FIN_WAIT2", retries);
    fin_state = TCP_FIN_WAIT2;
  }

  /* we do a bit of excessive checks, but at least we know where we stand */
  cmp_ok(zft_state((zft*)zocks.opaque_tx), "==", fin_state,
         "%d: tx zocket is in FIN_WAITx", retries);

  if( test_shutdown ) {
    /* after shutdown timeout should not be set and thus never expire */
    zf_tick ct1 = zf_wheel_get_current_tick(&stacks[0]->times.wheel);
    zf_tick ct2;
    do {
      zf_reactor_perform(stacks[0]);
      ct2 = zf_wheel_get_current_tick(&stacks[0]->times.wheel);
    } while( ct2 - ct1 <= stacks[0]->config.tcp_finwait_ticks + 5 );
  }
  cmp_ok(zft_state((zft*)zocks.opaque_tx), "==", fin_state,
         "%d: tx zocket is still in FIN_WAITx", retries);

  if( test_shutdown )
    zft_free((zft*)zocks.opaque_tx);

  /* we still use our reference to tx zocket - a bid dodgy but does the job */

  int ct1 = zf_wheel_get_current_tick(&stacks[0]->times.wheel);

  /* skip through fin_waitx */
  while( zft_state((zft*)zocks.opaque_tx) == fin_state) {
    zf_reactor_perform(stacks[0]);
  }

  cmp_ok(zft_state((zft*)zocks.opaque_tx), "==", TCP_CLOSE,
         "%d: tx zocket is finally in TIME_WAIT", retries);

  int ct2 = zf_wheel_get_current_tick(&stacks[0]->times.wheel);

  cmp_ok(ct2 - ct1, ">=", stacks[0]->config.tcp_finwait_ticks,
         "%d: FIN TIMEOUT duration OK", retries);

#if 0
  while( zft_state((zft*)zocks.opaque_tx) == TCP_TIME_WAIT )
    zf_reactor_perform(stacks[0]);

  cmp_ok(zft_state((zft*)zocks.opaque_tx), "==", TCP_CLOSE,
         "%d: tx zocket is finally in CLOSE state", retries);


  int ct3 = zf_wheel_get_current_tick(&stacks[0]->times.wheel);

  cmp_ok(ct3 - ct2, ">=", stacks[0]->config.tcp_timewait_ticks,
         "%d: TIME_WAIT TIMEOUT duration OK", retries);
#endif

  zft_shutdown_tx((zft*)zocks.opaque_rx);
  if( ! test_fin_wait2 ) {
    /* for FIN_WAIT1 tests, as rx zocket stack was not progressed and
     * now tx zocket is gone, the rx zocket will enter CLOSING state, and
     * the only way out is timeouts */
    while( zft_state((zft*)zocks.opaque_rx) != TCP_CLOSING )
      zf_reactor_perform(stacks[1]);
    cmp_ok(zft_state((zft*)zocks.opaque_rx), "==", TCP_CLOSING,
           "%d: rx zocket is in CLOSING state", retries);
    /* if we are stuck below - fin timeout must have failed */
  }
  while( zft_state((zft*)zocks.opaque_rx) != TCP_CLOSE )
    zf_reactor_perform(stacks[1]);
  cmp_ok(zft_state((zft*)zocks.opaque_rx), "==", TCP_CLOSE,
         "%d: rx zocket reached CLOSE state", retries);
  zft_free((zft*)zocks.opaque_rx);
  return 0;
}

int main(void)
{
  int rc;
  struct zf_stack* stacks[2];
  struct zf_attr* attrs[2];

  ZF_TRY(zf_init());

  ZF_TRY(init(&stacks[0], &attrs[0], ZF_EMU_B2B0, 1));
  ZF_TRY(init(&stacks[1], &attrs[1], ZF_EMU_B2B1, 3));
  rc = test(stacks, attrs);
  ZF_TRY(fini(stacks[1], attrs[1]));
  ZF_TRY(fini(stacks[0], attrs[0]));

  zf_deinit();

  return rc;
}

