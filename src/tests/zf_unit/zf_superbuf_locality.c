/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

/* Test to see if stacks maintain a small working set of sbufs */

#include <initializer_list>
#include "zf_superbuf_helper.h"

static const size_t pkts_per_sbuf = 512;

static int test(size_t num_rx_stacks, size_t superbufs_to_use)
{
  /* On real hardware, the working set would be of size 4 but in zf_emu, it can be 5.
   * This is because of the concurrent (as opposed to parallel) execution of zf emu stacks.
   * Zf_emu will have already posted 4 sbufs and when it finishes writing to
   * one of them, it will call sbuf end, but the rx stacks won't have
   * finished with it as they haven't consumed it's packets. This means
   * zf_emu must find a 5th sbuf to call efct_buffer_start on.
   * One case where the working set *is* 4 is when only 4 sbufs have been donated. */
  const unsigned working_set_sz = CI_MIN(num_rx_stacks * superbufs_to_use + 2, 5);
  const size_t sbufs_to_send = num_rx_stacks * superbufs_to_use * working_set_sz;

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


  for(size_t sbuf_no = 0; sbuf_no < sbufs_to_send; sbuf_no++) {
    size_t pkts_sent = test_send(pkts_per_sbuf, tx_stack, ut);
    cmp_ok(pkts_sent, "==", pkts_per_sbuf, "");

    for(size_t i = 0; i < num_rx_stacks; i++) {
      size_t pkts_recv = test_receive(&rds[i], rx_stacks[i], urs[i], pkts_sent);
      cmp_ok(pkts_recv, "==", pkts_per_sbuf, "");
    }
  }

  struct emu_stats& stats = emu_stats_update();
  emu_stats_display(stats);

  size_t expected_times_used = sbufs_to_send / working_set_sz;
  size_t total_sbufs = 0;
  for(size_t i = 0; i < sizeof(stats.sbufs) / sizeof(stats.sbufs[0]); i++) {
    /* We discount rollovers */
    size_t ends = stats.sbufs[i].n_ends - stats.sbufs[i].n_rollovers;
    total_sbufs += ends;
    if(ends != expected_times_used && ends != 0) {
      fail("expected times used %zu sbufs, got: %zu", expected_times_used, 
           ends);
    }
  }
  cmp_ok(total_sbufs, "==", sbufs_to_send,
         "Correct number of sbufs were filled and ended");
  cmp_ok(stats.no_desc_drops, "==", 0, "0 no_desc_drops");
  cmp_ok(stats.sbuf_leaked, "==", false, "no sbufs leaked");

  fini_stacks(rx_stacks, rx_attrs, num_rx_stacks, tx_stack, tx_attr);
  zf_deinit();
  return 2 * num_rx_stacks + // tests for rx stack creation
         3;                  // Stats tests
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
  for(const auto &n_sbufs : {2, 8, 32}) {
    for(const auto &n_rx_stacks : {1, 4, 8}) {
      tests += test_wrapper(n_rx_stacks, n_sbufs);
    }
  }

  plan(tests);
  return 0;
}

