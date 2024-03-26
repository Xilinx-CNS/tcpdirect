/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

/* Test a more realistic case where applications randomly sleep for small
 * amounts of time */

#include <cstring>
#include <ctime>
#include <initializer_list>
#include <random>
#include "zf_superbuf_helper.h"

static const size_t pkts_per_sbuf = 512;

struct sleep_info {
  int64_t to_skip;
  int64_t skipped;

  bool is_awake() {
    return to_skip == 0;
  }
};

static int64_t total_skipped(struct sleep_info *info, size_t n) {
  int64_t total = 0;
  for(size_t i = 0; i < n; i++) {
    total += info[i].skipped;
  }
  return total;
}

static int test(size_t num_rx_stacks, size_t superbufs_to_use)
{
  zf_assert(superbufs_to_use > 4);
  uint64_t seed = (uint64_t) std::time(nullptr);
  printf("Using seed: %"PRId64"\n", seed);
  std::random_device rd;
  std::mt19937 gen;
  gen.seed(seed);
  std::uniform_real_distribution<> p_sleep(0.0f, 1.0f);
  std::uniform_int_distribution<> sleep_bufs(1, superbufs_to_use - 4);

  const size_t sbufs_to_send = superbufs_to_use * 4;

  int rc = zf_init();
  if( rc != 0 )
    return rc;

  const size_t rxq_size = superbufs_to_use * pkts_per_sbuf;
  zf_assert(num_rx_stacks < 256);

  struct zf_stack* rx_stacks[num_rx_stacks];
  struct zf_attr* rx_attrs[num_rx_stacks];
  struct zfur* urs[num_rx_stacks];
  RD rds[num_rx_stacks];
  struct sleep_info info[num_rx_stacks];
  memset(info, 0x00, sizeof(*info) * num_rx_stacks);

  struct zf_stack *tx_stack;
  struct zf_attr *tx_attr;
  struct zfut* ut;

  init_stacks(rx_stacks, rx_attrs, urs, rds, num_rx_stacks, rxq_size,
              true, &tx_stack, &tx_attr, &ut);


  int tests = 0;
  size_t total_pkts_recv = 0;
  for(size_t sbuf_no = 0; sbuf_no < sbufs_to_send; sbuf_no++) {
    size_t pkts_sent = test_send(pkts_per_sbuf, tx_stack, ut);
    cmp_ok(pkts_sent, "==", pkts_per_sbuf, "");

   for(size_t i = 0; i < num_rx_stacks; i++) {
      /* 30% chance to make an app sleep if its a wake and hasn't just slept */
      if( p_sleep(gen) < 0.3f && info[i].is_awake() && info[i].skipped == 0 ) {
        info[i].to_skip = sleep_bufs(gen) - 1;
        /* We have already skipped at least one sbuf */
        info[i].skipped = 1;
      }
      else {
        /* Catchup on any skipped sbufs */
        if (info[i].is_awake()) {
          size_t pkts_recv = test_receive(&rds[i], rx_stacks[i], urs[i],
                                          pkts_per_sbuf * (1 + info[i].skipped));
          total_pkts_recv += pkts_recv;
          cmp_ok(pkts_recv, "==", pkts_per_sbuf * (1 + info[i].skipped),
                 "expected: %zu recv: %zu pkts", pkts_per_sbuf,  pkts_recv);
          tests++;
          info[i].skipped = 0;
        }
        /* Update how many we have skipped */
        else {
          info[i].to_skip--;
          info[i].skipped++;
        }
      }
    }
  }

  struct emu_stats& stats = emu_stats_update();

  fini_stacks(rx_stacks, rx_attrs, num_rx_stacks, tx_stack, tx_attr);

  cmp_ok(stats.no_desc_drops, "==", 0, "0 no_desc_drops");
  cmp_ok(stats.sbuf_leaked, "==", false, "no sbufs leaked");
  cmp_ok(total_pkts_recv, "==",
         (sbufs_to_send * num_rx_stacks - total_skipped(info, num_rx_stacks))
         * pkts_per_sbuf,
         "received expected number of sbufs");

  zf_deinit();
  return 2 * num_rx_stacks + // tests for rx stack creation
         2 +                 // Stats tests
         tests + 1;          // Receive tests
}

int test_wrapper(size_t n_rx_stacks, size_t n_sbufs)
{
  printf("\t------------Testing %zu stacks each with %zu sbufs------------\n",
         n_rx_stacks, n_sbufs);
  int tests = test(n_rx_stacks, n_sbufs);
  cmp_ok(tests, ">=", 0, "");
  return tests;
}

int main(int argc, char* argv[])
{
  int tests = 0;
  tests += test_wrapper(15, 64);
  plan(tests);
  return 0;
}
