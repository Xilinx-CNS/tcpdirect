/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2018-2019 Advanced Micro Devices, Inc. */
/* Timestamping:
 * Every 250 ms, the NIC sends us a timestamp sync event with
 * (tsync_major, tsync_minor) values, which have units of
 * (seconds, sub-second clock ticks).
 *
 * Packets are timestamped with the minor value only, so when
 * computing packet timestamps we end up having to glue a
 * tsync_major and pkt_minor together.
 *
 * These tests verify that we perform the gluing correctly.
 */

#include <initializer_list>
#include <tuple>
#include <vector>

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <zf_internal/utils.h>

#include <etherfabric/vi.h>
#include <ci/driver/efab/hardware/host_ef10_common.h>

extern "C" {
#include <etherfabric/internal/internal.h>
}

#include "../tap/tap.h"


#define NSEC_PER_SEC 1000000000L

#define TEST_TS(x, expected)                              \
  do {                                                    \
    auto [rc, a] = x;                                     \
    ef_precisetime b = (ef_precisetime)expected;          \
    if( rc != 0 )                                         \
      ZF_TRY(std::get<0>(x));                             \
    if( cmp(a, b) != 0 ) {                                \
      fail("%s = %ld.%09ld, expected %ld.%09ld",          \
           #x, a.tv_sec, a.tv_nsec, b.tv_sec, b.tv_nsec); \
    } else {                                              \
      pass("%s == %2ld.%09ld", #x, b.tv_sec, b.tv_nsec);  \
    }                                                     \
  } while( 0 )

/* Compare two ef_vi timestamps, throwing away any differences in
 * the fractional nanoseconds part or sync flags. */
static int cmp(ef_precisetime a, ef_precisetime b)
{
  if( a.tv_sec < b.tv_sec )
    return -1;
  if( a.tv_sec > b.tv_sec )
    return 1;

  if( a.tv_nsec < b.tv_nsec )
    return -1;
  if( a.tv_nsec > b.tv_nsec )
    return 1;
  return 0;
}


/* Returns the difference between two ef_vi timestamps, in nanoseconds */
static long long sub(ef_precisetime a, ef_precisetime b)
{
  return (a.tv_sec - b.tv_sec) * (long long)NSEC_PER_SEC +
         a.tv_nsec - b.tv_nsec;
}


static ef_vi_state vi_state = []{
  ef_vi_state vi_state;
  memset(&vi_state, 0, sizeof(vi_state));
  vi_state.evq.sync_flags = 0;
  return vi_state;
}();

static ef_vi vi = []{
  ef_vi vi;
  memset(&vi, 0, sizeof(vi));
  vi.ep_state = &vi_state;
  return vi;
}();

static uint8_t pkt[2048];
static inline int get_timestamp(enum ef_timestamp_format ts_format,
                                int rx_ts_correction,
                                uint32_t tsync_major, uint32_t tsync_minor,
                                uint32_t pkt_minor, ef_precisetime* ts_out)
{
  ef_vi_set_ts_format(&vi, ts_format);
  ef_vi_init_rx_timestamping(&vi, rx_ts_correction);
  *(uint32_t*)(pkt + ES_DZ_RX_PREFIX_TSTAMP_OFST) = pkt_minor;

  return ef10_receive_get_precise_timestamp_internal(
    &vi, pkt, ts_out, tsync_minor, tsync_major);
}


static inline std::tuple<int, ef_precisetime>
get_timestamp_27(int rx_ts_correction,
                 uint32_t tsync_major, uint32_t tsync_minor,
                 uint32_t pkt_minor)
{
  ef_precisetime ts;
  int rc = get_timestamp(TS_FORMAT_SECONDS_27FRACTION, rx_ts_correction,
                         tsync_major, tsync_minor, pkt_minor, &ts);
  return {rc, ts};
}


static inline std::tuple<int, ef_precisetime>
get_timestamp_qns(int rx_ts_correction,
                  uint32_t tsync_major, uint32_t tsync_minor,
                  uint32_t pkt_minor)
{
  ef_precisetime ts;
  int rc = get_timestamp(TS_FORMAT_SECONDS_QTR_NANOSECONDS, rx_ts_correction,
                         tsync_major, tsync_minor, pkt_minor, &ts);
  return {rc, ts};
}


#define TIMESTAMP_27_TESTS 9
static void test_timestamp_27(void)
{
  diag("test_timestamp_27:");

  /*                            tsync_minor, pkt_minor */
  TEST_TS(get_timestamp_27(0, 10, 0x7FFFFFF, 0x7FFFFFF), ((ef_precisetime){ 10, 999999992 }));
  TEST_TS(get_timestamp_27(0, 10, 0x7FFFFFF, 0x0000000), ((ef_precisetime){ 11,         0 }));
  TEST_TS(get_timestamp_27(0, 10, 0x7FFFFFF, 0x0000001), ((ef_precisetime){ 11,         7 }));

  TEST_TS(get_timestamp_27(0, 10, 0, 0x7FFFFFF), ((ef_precisetime){  9, 999999992 }));
  TEST_TS(get_timestamp_27(0, 10, 0, 0x0000000), ((ef_precisetime){ 10,         0 }));
  TEST_TS(get_timestamp_27(0, 10, 0, 0x0000001), ((ef_precisetime){ 10,         7 }));

  TEST_TS(get_timestamp_27(0, 10, 1, 0x7FFFFFF), ((ef_precisetime){  9, 999999992 }));
  TEST_TS(get_timestamp_27(0, 10, 1, 0x0000000), ((ef_precisetime){ 10,         0 }));
  TEST_TS(get_timestamp_27(0, 10, 1, 0x0000001), ((ef_precisetime){ 10,         7 }));
  diag(" ");
}


#define TIMESTAMP_QNS_TESTS 18
static void test_timestamp_qns(void)
{
  /* bug 83129: negative rx_ts_correction */
  diag("test_timestamp_qns:");

  /*                               tsync_minor, pkt_minor */
  TEST_TS(get_timestamp_qns(-3, 10, 3999999999, 3999999997), ((ef_precisetime){ 10, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 3999999999, 3999999998), ((ef_precisetime){ 10, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 3999999999, 3999999999), ((ef_precisetime){ 10, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 3999999999,          0), ((ef_precisetime){ 10, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 3999999999,          1), ((ef_precisetime){ 11,         0 }));
  TEST_TS(get_timestamp_qns(-3, 10, 3999999999,          2), ((ef_precisetime){ 11,         0 }));
  diag(" ");

  TEST_TS(get_timestamp_qns(-3, 10, 0, 3999999997), ((ef_precisetime){  9, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 0, 3999999998), ((ef_precisetime){  9, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 0, 3999999999), ((ef_precisetime){  9, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 0,          0), ((ef_precisetime){  9, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 0,          1), ((ef_precisetime){ 10,         0 }));
  TEST_TS(get_timestamp_qns(-3, 10, 0,          2), ((ef_precisetime){ 10,         0 }));
  diag(" ");

  TEST_TS(get_timestamp_qns(-3, 10, 1, 3999999997), ((ef_precisetime){  9, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 1, 3999999998), ((ef_precisetime){  9, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 1, 3999999999), ((ef_precisetime){  9, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 1,          0), ((ef_precisetime){  9, 999999999 }));
  TEST_TS(get_timestamp_qns(-3, 10, 1,          1), ((ef_precisetime){ 10,         0 }));
  TEST_TS(get_timestamp_qns(-3, 10, 1,          2), ((ef_precisetime){ 10,         0 }));
  diag(" ");
}


/* The following are more exhaustive tests of timestamping,
 * which check for non-monotonic anomalies and off by one second errors. */
static void test_timestamp_extended(
  std::tuple<int, ef_precisetime> (*get_timestamp)(int, uint32_t, uint32_t, uint32_t),
  const char* name, uint32_t one_sec,
  const std::vector<int>& rx_ts_corrections,
  const std::vector<uint32_t>& tsync_minors,
  const std::vector<uint32_t>& pkt_minors)
{
  bool success = true;

  uint32_t tsync_major = 10;

  /* Test a variety of rx_ts_correction and minor values */
  for( int rx_ts_correction : rx_ts_corrections ) {
    for( uint32_t tsync_minor : tsync_minors ) {
      bool has_lastts = false;
      ef_precisetime lastts = {0, 0, 0, 0};

      /* Do the simplest possible conversion from tsync to ef_vi timestamp as a
       * reference */
      ef_precisetime tsync = {
        .tv_sec = tsync_major,
        .tv_nsec = (uint32_t)((uint64_t)tsync_minor * (uint64_t)NSEC_PER_SEC / one_sec),
        .tv_nsec_frac = 0,
        .tv_flags = 0,
      };

      for( uint32_t pkt_minor : pkt_minors ) {
        auto [rc, ts] = get_timestamp(rx_ts_correction,
                                      tsync_major, tsync_minor, pkt_minor);
        if( rc == 0 ) {
          /* Check that the timestamp is within 0.5 seconds of the timesync. */
          /* This should catch the case where tv_sec is off by one. */
          if( abs(sub(ts, tsync)) > 500000000 ) {
            diag("not ok - %s(%d, %2ld, %010ld, %010ld) = %2ld.%09ld, "
                 "incorrect!",
                 name, rx_ts_correction, tsync_major, tsync_minor, pkt_minor,
                 ts.tv_sec, ts.tv_nsec);
            success = false;
          }

          /* Check that the series of timestamps is monotonically increasing */
          /* This catches anomalies like the one in bug 83129 */
          else if( has_lastts &&
                   cmp(lastts, ts) > 0) {
            diag("not ok - %s(%d, %2ld, %010ld, %010ld) = %2ld.%09ld, "
                 "not monotonic, previous value was %2d.%09ld!",
                 name, rx_ts_correction, tsync_major, tsync_minor, pkt_minor,
                 ts.tv_sec, ts.tv_nsec, lastts.tv_sec, lastts.tv_nsec);
            success = false;
          }

          has_lastts = true;
          lastts = ts;
        }
        else {
          /* Only accept EL2NSYNC / timesync errors and nothing else. */
          /* The boundaries of timestamp validity are not checked. */
          if( rc != -EL2NSYNC ) {
            diag("not ok - %s(%d, %2ld, %010ld, %010ld) = %d (%s)",
                 name, rx_ts_correction, tsync_major, tsync_minor, pkt_minor,
                 rc, strerror(-rc));
            success = false;
          }

          has_lastts = false;
        }
      }
    }
  }

  ok(success, "%s extended test", name);
}


/* Generates a monotonic list of minors, with clusters of cluster_size
 * contiguous values, spaced apart by the given spacing. */
static std::vector<uint32_t>
generate_minors(uint32_t one_sec, uint32_t spacing, uint32_t cluster_size)
{
  std::vector<uint32_t> minors;

  /* Cluster of values at the start of the space */
  for( uint32_t i = 0; i < cluster_size / 2; ++i )
    minors.push_back(i);

  /* Clusters in the middle */
  for( uint32_t i = spacing; i < one_sec; i += spacing )
    for( uint32_t j = i - cluster_size;
         j < std::min(one_sec, i + cluster_size); ++j )
      if( j > minors.back() )
        minors.push_back(j);

  /* Cluster of values at the end of the space */
  for( uint32_t i = one_sec - cluster_size / 2; i < one_sec; ++i )
    if( i > minors.back() )
      minors.push_back(i);
  return minors;
}

const uint32_t ONE_SEC_27  = 0x08000000;
const uint32_t ONE_SEC_QNS = 4000000000U;

/* Pick a bunch of rx_ts_correction values to test.  The implementation
 * requires the correction to be <= -2.
 */
static std::vector<int> rx_ts_corrections = { -55, -13, -8, -5, -3, -2 };

/* Pick tsync_minors clustered around quarter-second values */
static std::vector<uint32_t> tsync_minors_27 =
  generate_minors(ONE_SEC_27, ONE_SEC_27 / 4, 20);
static std::vector<uint32_t> tsync_minors_qns =
  generate_minors(ONE_SEC_QNS, ONE_SEC_QNS / 4, 20);

/* Pick pkt_minors clustered around 1/20 second values
 * This ensures that we get good coverage.
 * For the qns case, pkt_minor reported by hw can exceed ONE_SEC - bug 75412 */
static std::vector<uint32_t> pkt_minors_27 =
  generate_minors(ONE_SEC_27, ONE_SEC_27 / 20, 10);
static std::vector<uint32_t> pkt_minors_qns =
  generate_minors(ONE_SEC_QNS + 10, ONE_SEC_QNS / 20, 10);

#define TIMESTAMP_27_EXTENDED_TESTS 1
static void test_timestamp_27_extended(void)
{
  diag("test_timestamp_27_extended:");

  test_timestamp_extended(get_timestamp_27, "get_timestamp_27", ONE_SEC_27,
                          rx_ts_corrections, tsync_minors_27, pkt_minors_27);
}


#define TIMESTAMP_QNS_EXTENDED_TESTS 1
static void test_timestamp_qns_extended(void)
{
  diag("test_timestamp_qns_extended:");

  test_timestamp_extended(get_timestamp_qns, "get_timestamp_qns", ONE_SEC_QNS,
                          rx_ts_corrections, tsync_minors_qns, pkt_minors_qns);
}


int main(int argc, char* argv[])
{
  plan(TIMESTAMP_27_TESTS +
       TIMESTAMP_QNS_TESTS +
       TIMESTAMP_27_EXTENDED_TESTS + TIMESTAMP_QNS_EXTENDED_TESTS);

  /* Quick tests */
  test_timestamp_27();
  test_timestamp_qns();

  /* Slower, more thorough tests */
  test_timestamp_27_extended();
  test_timestamp_qns_extended();

  done_testing();

  return 0;
}
