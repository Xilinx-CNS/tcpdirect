/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

/* Test to ensure apps that are awake may still receive sbufs while others are
 * asleep. */

#include <initializer_list>
#include "zf_superbuf_helper.h"

static const size_t pkts_per_sbuf = 512;

static int test(size_t num_rx_stacks, size_t num_sleeping, size_t superbufs_to_use)
{
  zf_assert(num_sleeping < num_rx_stacks);
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

  struct zf_stack *tx_stack;
  struct zf_attr *tx_attr;
  struct zfut* ut;
  
  init_stacks(rx_stacks, rx_attrs, urs, rds, num_rx_stacks, rxq_size,
              true, &tx_stack, &tx_attr, &ut);


  size_t total_recv = 0;
  for(size_t sbuf_no = 0; sbuf_no < sbufs_to_send; sbuf_no++) {
    size_t pkts_sent = test_send(pkts_per_sbuf, tx_stack, ut);
    cmp_ok(pkts_sent, "==", pkts_per_sbuf, "");

   for(size_t i = 0; i < num_rx_stacks - num_sleeping; i++) {
      size_t pkts_recv = test_receive(&rds[i], rx_stacks[i], urs[i], pkts_sent);
      total_recv += pkts_recv;
      cmp_ok(pkts_recv, "==", pkts_per_sbuf, "");
    }
  }

  struct emu_stats& stats = emu_stats_update();

  fini_stacks(rx_stacks, rx_attrs, num_rx_stacks, tx_stack, tx_attr);

  cmp_ok(stats.no_desc_drops, "==", 0, "0 no_desc_drops");
  cmp_ok(stats.sbuf_leaked, "==", false, "no sbufs leaked");
  cmp_ok(total_recv, "==", sbufs_to_send * (num_rx_stacks - num_sleeping)
         * pkts_per_sbuf, "Received expected number of packets");

  zf_deinit();
  return 2 * num_rx_stacks + // tests for rx stack creation
         3;                  // Stats tests
}

int test_wrapper(size_t n_rx_stacks, size_t n_sleeping, size_t n_sbufs)
{
  printf("\t------------Testing %zu stacks %zu of which are sleeping "
         "each with %zu sbufs------------\n",
       n_rx_stacks, n_sleeping, n_sbufs);
  int tests = test(n_rx_stacks, n_sleeping, n_sbufs);
  cmp_ok(tests, ">=", 0, "");
  return tests;
}

int main(int argc, char* argv[])
{
  int tests = 0;
  for(const auto &n_sbufs : {2, 8, 16}) {
    for(const auto &n_rx_stacks : {2, 8, 13, 15}) {
      for(auto n_sleepers = 1; n_sleepers < n_rx_stacks; n_sleepers++) {
        tests += test_wrapper(n_rx_stacks, n_sleepers, n_sbufs);
      }
    }
  }

  plan(tests);
  return 0;
}
