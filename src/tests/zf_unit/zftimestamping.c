/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2017-2022 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  jjh
**  \brief  Unit test for ZF hw timestamping interface.
**   \date  2017/10/11
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <arpa/inet.h>
#include <stdlib.h>

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/rx_res.h>
#include <zf_internal/attr.h>
#include <zf_internal/timestamping.h>
#include <zf_internal/private/zf_emu.h>
#include <algorithm>

#include "abstract_zocket_pair.h"

#include <../tap/tap.h>

static struct timespec ts_init;

static void expected_report(int i, zf_pkt_report* r)
{
  r->timestamp.tv_sec = 1000 + i;
  r->timestamp.tv_nsec = 2000 + i;
  r->start = 3000 + i;
  r->bytes = 4000 + i;
}

static bool check_report(int i, const zf_pkt_report* r)
{
  return r->timestamp.tv_sec == 1000 + i &&
         r->timestamp.tv_nsec == 2000 + i &&
         r->start == unsigned(3000 + i) &&
         r->bytes == unsigned(4000 + i);
}

/* Test writing and reading a batch of reports.
 * Prepare reports per zocket
 * Complete some or all of them, checking waitable state
 * Read some or all of them, checking values and waitable state
 * Complete the rest, checking waitable state
 * Read the rest, checking values and waitable state.
 */
static void tx_report_batch(struct zf_tx_reports::queue* reports, int capacity,
                            int zocks, int total, int complete, int read)
{
  ZF_TEST(complete <= total);
  ZF_TEST(capacity % zocks == 0);

  /* Current implementation requires that reports complete before dropping */
  if( capacity < zocks * (total - complete) )
    return;

  const int expect_drop = std::max(0, total - capacity / zocks);
  const int expect_read = std::max(0, std::min(read, complete - expect_drop));
  const int remainder = total - expect_drop - expect_read;

  ef_event ev;
  zf_pkt_report r {};

  /* Prepare all the reports, and complete the requested number */
  int count = 0;
  for( int i = 0; i < total; ++i ) {
    for( int z = 0; z < zocks; ++z ) {
      expected_report(count++, &r);
      zf_tx_reports::prepare(reports, z/2, z%2, r.start, r.bytes, 0);
      if( i < complete ) {
        ev.tx_timestamp.type = EF_EVENT_TYPE_TX_WITH_TIMESTAMP;
        ev.tx_timestamp.ts_sec = r.timestamp.tv_sec;
        ev.tx_timestamp.ts_nsec = r.timestamp.tv_nsec;
        ev.tx_timestamp.ts_flags = 0;
        zf_tx_reports::complete(reports, z/2, z%2, &ev);
      }
    }
  }

  /* Read up to the requested number */
  for( int z = 0; z < zocks; ++z ) {
    count = expect_drop * zocks + z;
    zf_pkt_report reports_out[read];
    int got = read;
    bool expect_more = (expect_drop + expect_read < complete);
    bool more = ! expect_more;

    zf_tx_reports::get(reports, z/2, z%2, reports_out, &got, &more);
    ZF_TEST(got == expect_read);
    ZF_TEST(more == expect_more);

    for( int i = 0; i < got; ++i ) {
      ZF_TEST(check_report(count, &reports_out[i]));
      count += zocks;

      if( expect_drop && i == 0 )
        ZF_TEST(reports_out[i].flags & ZF_PKT_REPORT_DROPPED);
      else
        ZF_TEST(~reports_out[i].flags & ZF_PKT_REPORT_DROPPED);
    }
  }

  /* Complete the remaining reports */
  count = complete * zocks;
  for( int i = complete; i < total; ++i ) {
    for( int z = 0; z < zocks; ++z) {
      expected_report(count++, &r);
      ev.tx_timestamp.type = EF_EVENT_TYPE_TX_WITH_TIMESTAMP;
      ev.tx_timestamp.ts_sec = r.timestamp.tv_sec;
      ev.tx_timestamp.ts_nsec = r.timestamp.tv_nsec;
      zf_tx_reports::complete(reports, z/2, z%2, &ev);
    }
  }

  /* Read the remaining reports */
  for( int z = 0; z < zocks; ++z ) {
    count = (expect_drop + expect_read) * zocks + z;
    zf_pkt_report reports_out[remainder];
    int got = remainder;
    bool more = true;

    zf_tx_reports::get(reports, z/2, z%2, reports_out, &got, &more);
    ZF_TEST(got == remainder);
    ZF_TEST(! more);

    for( int i = 0; i < got; ++i ) {
      ZF_TEST(check_report(count, &reports_out[i]));
      count += zocks;

      if( expect_drop && ! expect_read && i == 0 )
        ZF_TEST(reports_out[i].flags & ZF_PKT_REPORT_DROPPED);
      else
        ZF_TEST(~reports_out[i].flags & ZF_PKT_REPORT_DROPPED);
    }
  }
}

static void test_tx_reports()
{
  zf_allocator* alloc = (zf_allocator*)calloc(65536 + ZF_CACHE_LINE_SIZE, 1);
  zf_allocator_init(alloc, 65536);

  struct zf_tx_reports::queue reports {};
  int capacity = 16;
  ZF_TRY(zf_tx_reports::alloc_queue(&reports, alloc, capacity));

  int count = 0;
  for( int zocks = 1; zocks <= capacity; zocks *= 2 )
    for( int total = 0; total <= 3 * capacity; ++total )
      for( int complete = 0; complete <= total; ++complete )
        for( int read = 0; read <= total; ++read, ++count )
          tx_report_batch(&reports, capacity, zocks, total, complete, read);

  cmp_ok(count, "!=", 0, "test_tx_reports ran some tests");
  free(alloc);
}


template <typename ZRx, typename ZTx, typename ZMsg>
struct Test {
  struct zvtbl;

  static int send_n(struct zf_stack* stack, ZTx* zock, size_t pl_len, size_t n)
  {
    char buf[pl_len];
    struct iovec siov = { buf, pl_len };
    memset(buf, n, pl_len);

    int len = 0, rc = 0;
    while( n-- > 0 ) {
      rc = zvtbl::send(zock, &siov, 1, 0);

      len += MAX(rc, 0);

      if( (rc == 0 && len != 0) || rc == -EAGAIN )
        while( zf_reactor_perform(stack) == 0 );

      while( zf_reactor_perform(stack) == 1 );
    }

    return len;
  }

  /*
   * Tests that:
   *   - The timestamps are arriving in order.
   *   - Timestamps are not before sending nor after receiving.
   **/
  static void test_packet_timestamps(struct zf_stack *stack, ZRx* zrx, ZTx* ztx)
  {
    struct {
     ZMsg header;
     struct iovec iov[SW_RECVQ_MAX];
    } msg;

    struct timespec after_time, before_time;
    int ts_valid = 0, ts_monotone = 0, bs_valid = 0;

    unsigned clock_set_sync_flag =
      (EF_VI_SYNC_FLAG_CLOCK_SET | EF_VI_SYNC_FLAG_CLOCK_IN_SYNC);
    unsigned ts_synced = clock_set_sync_flag;

    clock_gettime(CLOCK_MONOTONIC, &before_time);

    /* Send a random number of non-empty packets of random size */
    int pl = rand() % zvtbl::mss(ztx) + 1;
    int n = rand() % SW_RECVQ_MAX;
    int len = send_n(stack, ztx, pl, n);

    struct zf_pkt_report tx_reports[SW_RECVQ_MAX], rx_reports[SW_RECVQ_MAX];

    int tx_packets = 0, rx_packets = 0, tx_bytes = 0, rx_bytes = 0;
    while( tx_bytes < len || rx_bytes < len ) {
      /* Keep it ticking */
      zf_reactor_perform(stack);

      int new_count = SW_RECVQ_MAX - tx_packets;
      ZF_TRY(zvtbl::report(ztx, &tx_reports[tx_packets], &new_count));
      for( int j = 0; j < new_count; j++ )
        tx_bytes += tx_reports[tx_packets++].bytes;

      msg.header.iovcnt = SW_RECVQ_MAX;
      zvtbl::recv(zrx, &msg.header, 0);
      for( int j = 0; j < msg.header.iovcnt; j++ ) {
        zf_pkt_report* r = &rx_reports[rx_packets++];
        unsigned f = 0;
        ZF_TRY(zfr_pkt_get_timestamp(zrx, &msg.header, &r->timestamp, j, &f));
        ts_synced &= f;
        r->start = rx_bytes;
        r->bytes = msg.iov[j].iov_len;
        rx_bytes += r->bytes;
      }
      if( msg.header.iovcnt != 0 )
        zvtbl::recv_done(zrx, &msg.header);
    }

    clock_gettime(CLOCK_MONOTONIC, &after_time);

    bs_valid |= (rx_bytes != len) << 1;
    bs_valid |= (tx_bytes != len) << 2;
    bs_valid |= (rx_packets != tx_packets) << 3;
    if( bs_valid == 0 ) {
      uint64_t tx_start = tx_reports[0].start;
      struct timespec rx_prev_time = before_time;
      struct timespec tx_prev_time = before_time;
      rx_bytes = tx_bytes = tx_packets = 0;

      for( int j = 0; j < rx_packets; ++j ) {
        zf_pkt_report* rxr = &rx_reports[j];
        zf_pkt_report* txr = &tx_reports[j];

        bs_valid |= (rx_bytes != (int)(rxr->start)) << 4;
        bs_valid |= ((zvtbl::is_tcp ? tx_bytes : tx_packets) !=
                    (int)(txr->start - tx_start)) << 5;

        rx_bytes += rxr->bytes;
        tx_bytes += txr->bytes;
        tx_packets++;
        bs_valid |= (rx_bytes != tx_bytes) << 6;
        ts_valid |= (zf_timespec_compare(&before_time, &rxr->timestamp) >= 0) << 1;
        ts_valid |= (zf_timespec_compare(&before_time, &txr->timestamp) >= 0) << 2;
        ts_valid |= (zf_timespec_compare(&after_time, &rxr->timestamp) <= 0) << 3;
        ts_valid |= (zf_timespec_compare(&after_time, &txr->timestamp) <= 0) << 4;

        ts_monotone |=
          (zf_timespec_compare(&rxr->timestamp, &rx_prev_time) <= 0) << 1;
        ts_monotone |=
          (zf_timespec_compare(&txr->timestamp, &tx_prev_time) <= 0) << 2;
        ts_monotone |=
          (zf_timespec_compare(&rxr->timestamp, &txr->timestamp) <= 0) << 3;

        rx_prev_time = rxr->timestamp;
        tx_prev_time = txr->timestamp;
      }
    }

    cmp_ok(bs_valid, "==", 0, "packet byte counts valid");
    cmp_ok(ts_synced, "==", clock_set_sync_flag, "clock remained in sync");
    cmp_ok(ts_valid, "==", 0, "packet timestamps valid");
    cmp_ok(ts_monotone, "==", 0, "timestamps arrived in monotonic order");
  }


  /*
   * Tests that:
   *   - The timestamps are sent in order.
   *   - The timestamps are received in order except for retransmission phase.
   *   - Timestamps are not before sending nor after receiving.   **/
  static void test_packet_retransmission_timestamps
                              (struct zf_stack *stack, ZRx* zrx, ZTx* ztx)
  {
    struct {
     ZMsg header;
     struct iovec iov[SW_RECVQ_MAX];
    } msg;

    struct timespec after_time, before_time;
    int ts_valid = 0, ts_monotone = 0, bs_valid = 0;

    unsigned clock_set_sync_flag =
      (EF_VI_SYNC_FLAG_CLOCK_SET | EF_VI_SYNC_FLAG_CLOCK_IN_SYNC);
    unsigned ts_synced = clock_set_sync_flag;

    clock_gettime(CLOCK_MONOTONIC, &before_time);

    /* Send a random number of non-empty packets of random size */
    unsigned int n = rand() % ( SW_RECVQ_MAX / 2 ) + 5;
    /* Randomly choose sequence number of the dropped packet */
    unsigned int dropped = n > 0 ? rand() % n : 0;

    unsigned int len = 0; /* total tx length, including the dropped packet */
    unsigned int tx_bytes_after_retx = 0;

    for( unsigned int i = 0; i < n; ++i ) {
      if( i == dropped )
        zf_reactor_purge(stack);

      unsigned int pl = rand() % zvtbl::mss(ztx) + 1;
      len += send_n(stack, ztx, pl, 1);
      if( i == dropped ) {
        /* Sleep a bit more than RTO, to prevent repeated retransmissions */
        for( int j = 0; j < 400; ++j ) {
          usleep(1000);
          zf_emu_sync();
          zf_reactor_perform(stack);
        }
      }
      else if( i == dropped + 1 )
        tx_bytes_after_retx = len;
    }

    struct zf_pkt_report tx_reports[SW_RECVQ_MAX], rx_reports[SW_RECVQ_MAX];
    unsigned int tx_packets = 0, rx_packets = 0, tx_bytes = 0, rx_bytes = 0;

    while( tx_bytes < len || rx_bytes < len ) {
      /* Keep it ticking */
      zf_reactor_perform(stack);

      int new_count = SW_RECVQ_MAX - tx_packets;
      ZF_TRY(zvtbl::report(ztx, &tx_reports[tx_packets], &new_count));

      /* Counting bytes in ZF_PKT_REPORT_TCP_RETRANS flagged packets is not
       * enough. Coalescing might put new data in flagged packet. */
      for( int j = 0; j < new_count; j++ ) {
        tx_bytes = std::max(tx_bytes, tx_reports[tx_packets].start
                 + tx_reports[tx_packets].bytes);
        ++tx_packets;
      }

      msg.header.iovcnt = SW_RECVQ_MAX;
      zvtbl::recv(zrx, &msg.header, 0);
      for( int j = 0; j < msg.header.iovcnt; j++ ) {
        zf_pkt_report* r = &rx_reports[rx_packets++];
        unsigned f = 0;
        ZF_TRY(zfr_pkt_get_timestamp(zrx, &msg.header, &r->timestamp, j, &f));
        ts_synced &= f;
        r->start = rx_bytes;
        r->bytes = msg.iov[j].iov_len;
        rx_bytes += r->bytes;
      }
      if( msg.header.iovcnt != 0 )
        zvtbl::recv_done(zrx, &msg.header);
    }

    clock_gettime(CLOCK_MONOTONIC, &after_time);

    bs_valid |= (rx_bytes != len) << 2;
    bs_valid |= (tx_bytes != len) << 3;

    if( bs_valid == 0 ) {
      struct timespec rx_prev_time = before_time;
      struct timespec tx_prev_time = before_time;
      rx_bytes = tx_bytes = 0;

      for( unsigned i = 0, j = 0; tx_bytes < len && rx_bytes < len; ++i, ++j ) {
        zf_pkt_report* rxr = &rx_reports[j];
        zf_pkt_report* txr = &tx_reports[i];

        rx_bytes = std::max(rx_bytes, rx_reports[j].start + rxr->bytes);
        tx_bytes = std::max(tx_bytes, tx_reports[i].start + txr->bytes);

        while( i < tx_packets && txr->flags & ZF_PKT_REPORT_TCP_RETRANS ) {
          tx_prev_time = txr->timestamp;
          txr = &tx_reports[++i];
          tx_bytes = std::max(tx_bytes, tx_reports[i].start + txr->bytes);
        }

        /* tx and rx sides might have different amount of packets during
         * retransmission stage due to coalescence. We should take this into an
         * account to be able to test "tx time" < "rx time" for later packets */
        while( rx_bytes < tx_bytes ) {
          if( rx_bytes < tx_bytes ) {
            rxr = &rx_reports[++j];
            rx_bytes = std::max(rx_bytes, rx_reports[j].start + rxr->bytes);
          }
        }
        while( tx_bytes > tx_bytes_after_retx && rx_bytes > tx_bytes ) {
          tx_prev_time = txr->timestamp;
          txr = &tx_reports[++i];
          ts_monotone |= (zf_timespec_compare(&txr->timestamp, &tx_prev_time) <= 0) << 1;
          tx_bytes = std::max(tx_bytes, tx_reports[i].start + txr->bytes);
        }

        ts_valid |= (zf_timespec_compare(&before_time, &rxr->timestamp) >= 0) << 2;
        ts_valid |= (zf_timespec_compare(&before_time, &txr->timestamp) >= 0) << 3;
        ts_valid |= (zf_timespec_compare(&after_time, &rxr->timestamp) <= 0) << 4;
        ts_valid |= (zf_timespec_compare(&after_time, &txr->timestamp) <= 0) << 5;

        if( rx_bytes > tx_bytes_after_retx )
          ts_monotone |= (zf_timespec_compare(&rxr->timestamp, &rx_prev_time) <= 0) << 2;
        ts_monotone |= (zf_timespec_compare(&txr->timestamp, &tx_prev_time) <= 0) << 3;
        if( rx_bytes == tx_bytes )
          ts_monotone |= (zf_timespec_compare(&rxr->timestamp, &txr->timestamp) <= 0) << 4;

        rx_prev_time = rxr->timestamp;
        tx_prev_time = txr->timestamp;
      }
    }

    cmp_ok(bs_valid, "==", 0, "packet byte counts valid");
    cmp_ok(ts_synced, "==", clock_set_sync_flag, "clock remained in sync");
    cmp_ok(ts_valid, "==", 0, "packet timestamps valid");
    cmp_ok(ts_monotone, "==", 0, "timestamps arrived in monotonic order");
  }


  static void run(struct zf_stack *stack, struct abstract_zocket_pair zockets)
  {
    /* Large enough to (practically) guarantee we coalesce at least once */
#define MONOTONICITY_TEST_ITERATIONS 128

    ZTx *ztx = (ZTx*)zockets.opaque_tx;
    ZRx *zrx = (ZRx*)zockets.opaque_rx;

    for( int i = 0; i < MONOTONICITY_TEST_ITERATIONS; i++ )
      test_packet_timestamps(stack, zrx, ztx);
  }
};


template <>
struct Test<struct zft, struct zft, struct zft_msg>::zvtbl {
  static constexpr auto recv = zft_zc_recv;
  static constexpr auto recv_done = zft_zc_recv_done;
  static constexpr auto send = zft_send;
  static constexpr auto report = zft_get_tx_timestamps;
  static constexpr auto mss = zft_get_mss;

  static constexpr bool is_tcp = true;
};


template <>
struct Test<struct zfur, struct zfut, struct zfur_msg>::zvtbl {
  static constexpr auto recv = zfur_zc_recv;
  static constexpr auto recv_done = zfur_zc_recv_done;
  static constexpr auto send = zfut_send;
  static constexpr auto report = zfut_get_tx_timestamps;
  static constexpr auto mss = zfut_get_mss;

  static constexpr bool is_tcp = false;
};


using UDPParent = Test<struct zfur, struct zfut, struct zfur_msg>;
struct UDPTests: UDPParent {
  static void test_fragmentation(struct zf_stack *st, struct zfut *ztx,
                                 struct zfur *zrx)
  {
    const int n = 3;
    const int mss = zfut_get_mss(ztx);
    const int len[3] = {mss * 2, mss / 2, mss * 3};

    struct timespec time_before, time_after;

    clock_gettime(CLOCK_MONOTONIC, &time_before);
    for( int i = 0; i < n; ++i )
      send_n(st, ztx, len[i], 1);
    clock_gettime(CLOCK_MONOTONIC, &time_after);

    zf_pkt_report reports[n];
    for( int total = 0; total != n; ) {
      zf_reactor_perform(st);
      int count = n - total;
      ZF_TRY(zfut_get_tx_timestamps(ztx, reports + total, &count));
      total += count;
    }

    int start_valid = 1;
    int bytes_valid = 1;
    int flags_valid = 1;
    const unsigned flags = ZF_PKT_REPORT_CLOCK_SET | ZF_PKT_REPORT_IN_SYNC;
    for( int i = 0; i < n; ++i ) {
      start_valid &= reports[i].start == reports[0].start + i;
      bytes_valid &= reports[i].bytes == len[i];
      flags_valid &= reports[i].flags == flags;
    }

    cmp_ok(start_valid, "==", 1, "packet start valid");
    cmp_ok(bytes_valid, "==", 1, "packet bytes valid");
    cmp_ok(flags_valid, "==", 1, "packet flags valid");
  }


  static void run(struct zf_stack *stack, struct abstract_zocket_pair zockets)
  {
    UDPParent::run(stack, zockets);

    struct zfut* ztx = (struct zfut*) zockets.opaque_tx;
    struct zfur* zrx = (struct zfur*) zockets.opaque_rx;
    test_fragmentation(stack, ztx, zrx);
  }
};


using TCPParent = Test<struct zft, struct zft, struct zft_msg>;
struct TCPTests: TCPParent {
  /* Check that the behaviour is correct when we fully coalesce one packet into
   * another and when we only partially do so.
   **/
  static void test_coalesce(struct zf_stack *st, struct zft *ztx,
                            struct zft *zrx)
  {
    struct {
     zft_msg header;
     struct iovec iov[2];
    } msg;
    msg.header.iovcnt = 2;

    struct zf_tcp* tcp_rx = ZF_CONTAINER(struct zf_tcp, ts, zrx);

    struct timespec ts_between, ts_after;
    struct timespec ts_first, ts_second;

    /* We first send a 64 byte pkt to ensure the last buffer in the ring is not
     * the same before and after coalescing.
     **/
    send_n(st, ztx, 64, 1);

    int bhalf = PKT_BUF_SIZE / 2;
    send_n(st, ztx, bhalf, 1);
    clock_gettime(CLOCK_MONOTONIC, &ts_between);
    send_n(st, ztx, bhalf, 1);

    /* There might be a short delay before the emulator loops them all back */
    while( zfr_queue_packets_unread_n(&tcp_rx->tsr) != 3 ||
           ! zfr_queue_all_packets_processed(&tcp_rx->tsr) )
      zf_reactor_perform(st);

    clock_gettime(CLOCK_MONOTONIC, &ts_after);

    /* Queue before coalescing:
     * ---------------- ---------------- ----------------
     * |Pr1|Hdr|#     | |Pr2|Hdr|###   | |Pr3|Hdr|###   |
     * ---------------- ---------------- ----------------
     * */

    zfr_queue_coalesce(&tcp_rx->tsr, st);

    /* Queue after coalescing:
     * ---------------- ----------------
     * |Pr3|Hdr|######| |Pr3|Hdr|#     |
     * ---------------- ----------------
     **/

    zf_assert_equal(zfr_queue_packets_unread_n(&tcp_rx->tsr), 2);

    /* Only two packets in the queue; we should receive both in a read. */
    zft_zc_recv(zrx, &msg.header, 0);
    zf_assert_equal(msg.header.iovcnt, 2);

    unsigned flags;
    ZF_TRY(zfr_pkt_get_timestamp(zrx, &msg.header, &ts_first, 0, &flags));
    ZF_TRY(zfr_pkt_get_timestamp(zrx, &msg.header, &ts_second, 1, &flags));

    zft_zc_recv_done(zrx, &msg.header);

    zf_pkt_report tx_reports[3];
    int tx_count = 3;
    ZF_TRY(zft_get_tx_timestamps(ztx, tx_reports, &tx_count));
    zf_assert_equal(tx_count, 3);

    int ts_correct = 1;

    ts_correct &= zf_timespec_compare(&tx_reports[2].timestamp, &ts_first) < 0;
    ts_correct &= zf_timespec_compare(&ts_first, &ts_second) == 0;
    /* Check that the timestamp corresponds to that of the last packet. */
    ts_correct &= (zf_timespec_compare(&ts_between, &ts_second) < 0 &&
                   zf_timespec_compare(&ts_second, &ts_after) <  0);

    cmp_ok(ts_correct, "==", 1, "Coalesced packets have correct timestamps");
  }

  static void test_flags(struct zf_stack *st,
                         struct zft *ztx, struct zft *zrx, unsigned flags)
  {
    flags |= ZF_PKT_REPORT_CLOCK_SET | ZF_PKT_REPORT_IN_SYNC;

    struct zf_pkt_report txr, rxr;
    for( int got_tx = 0, got_rx = 0; ! (got_tx && got_rx); ) {
      zf_reactor_perform(st);
      if( ! got_tx ) {
        got_tx = 1;
        ZF_TRY(zft_get_tx_timestamps(ztx, &txr, &got_tx));
      }
      if( ! got_rx ) {
        got_rx = 1;
        ZF_TRY(zft_get_tx_timestamps(zrx, &rxr, &got_rx));
      }
    }

    struct timespec ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_now);

    cmp_ok(txr.flags, "==", flags, "Tx socket sent expected TCP flags");
    cmp_ok(rxr.flags, "==", flags, "Rx socket sent expected TCP flags");

    int ts_correct = 1;
    ts_correct &= zf_timespec_compare(&ts_init, &txr.timestamp) < 0;
    ts_correct &= zf_timespec_compare(&txr.timestamp, &ts_now) < 0;
    ts_correct &= zf_timespec_compare(&ts_init, &rxr.timestamp) < 0;
    ts_correct &= zf_timespec_compare(&rxr.timestamp, &ts_now) < 0;
    cmp_ok(ts_correct, "==", 1, "TCP flags have correct timestamps");
  }

  static void run(struct zf_stack *stack, struct abstract_zocket_pair zockets)
  {
    struct zft* ztx = (struct zft*) zockets.opaque_tx;
    struct zft* zrx = (struct zft*) zockets.opaque_rx;

    test_flags(stack, ztx, zrx, ZF_PKT_REPORT_TCP_SYN);
    TCPTests::test_packet_retransmission_timestamps(stack, zrx, ztx);
    TCPParent::run(stack, zockets);
    test_coalesce(stack, ztx, zrx);
    zft_shutdown_tx(ztx);
    zft_shutdown_tx(zrx);
    test_flags(stack, ztx, zrx, ZF_PKT_REPORT_TCP_FIN);
  }
};


static int init(struct zf_stack **stack_out, struct zf_attr **attr_out)
{
  unsigned seed = time(NULL);
  diag("Using seed %u\n", seed);
  srand(seed);

  int rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  /* Request the default allocation of buffers explicitly. */
  zf_attr_set_int(*attr_out, "n_bufs", 0);

  /* Enable timestamping */
  zf_attr_set_int(*attr_out, "rx_timestamping", 1);
  zf_attr_set_int(*attr_out, "tx_timestamping", 1);

  /* This test requires the loopback shim. */
  ZF_TEST((*attr_out)->emu == ZF_EMU_LOOPBACK);

  rc = zf_stack_alloc(*attr_out, stack_out);
  if( rc != 0 ) {
    zf_attr_free(*attr_out);
    return rc;
  }

  clock_gettime(CLOCK_MONOTONIC, &ts_init);
  return rc;
}


static int fini(struct zf_stack *stack, struct zf_attr *attr)
{
  int rc;
  rc = zf_stack_free(stack);
  if( rc != 0 )
    return rc;

  zf_attr_free(attr);
  zf_deinit();

  return rc;
}


int main(void)
{
  /* Unit tests */
  test_tx_reports();

  /* Integration tests */
  struct zf_stack *stack;
  struct zf_attr *attr;

  ZF_TRY(init(&stack, &attr));

  struct abstract_zocket_pair tcp_zockets;
  alloc_tcp_pair(stack, attr, &tcp_zockets, false);

  struct abstract_zocket_pair udp_zockets;
  alloc_udp_pair(stack, attr, &udp_zockets);

  TCPTests::run(stack, tcp_zockets);
  UDPTests::run(stack, udp_zockets);

  tcp_zockets.close(&tcp_zockets);

  /* Run tests with traffic in the reverse direction.  Bug86539
   * exposed that accepted and connected socket had different init
   * paths, so make sure we cover both */
  alloc_tcp_pair(stack, attr, &tcp_zockets, true);
  TCPTests::run(stack, tcp_zockets);

  done_testing();

  ZF_TRY(fini(stack, attr));
}

