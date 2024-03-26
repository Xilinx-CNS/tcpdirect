/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

/* Test to see if applications skip sbufs when stacks are destroyed. */

#include <initializer_list>
#include "zf_superbuf_helper.h"

static const size_t pkts_per_sbuf = 512;

static size_t n_expected_pkts(const size_t num_rx_stacks, 
                                          const size_t superbufs_to_use,
                                          const size_t stack_no)
{
  /* There are i * superbufs_to_use sbufs fewer by this point as stacks_[0..i-1]
   * have been destroyed and their sbufs released. */
  const size_t sbufs_donated = (num_rx_stacks - stack_no) * superbufs_to_use;
  const size_t future_sbufs = 4;
  const size_t shm_q_size = CI_MIN(superbufs_to_use, 16);
  return CI_MAX(shm_q_size, (sbufs_donated - future_sbufs)) * pkts_per_sbuf - 1;
}

static int test(size_t num_rx_stacks, size_t superbufs_to_use)
{
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

  size_t pkts_sent = test_send(rxq_size * num_rx_stacks, tx_stack, ut);
  cmp_ok(pkts_sent, "==", rxq_size * num_rx_stacks,
         "Sent the expected number of pkts.");

  for(size_t i = 0; i < num_rx_stacks; i++) {
    size_t pkts_recv = test_receive(&rds[i], rx_stacks[i], urs[i], pkts_sent);
    printf("pkts_sent: %zu, pkts_received: %zu\n", pkts_sent, pkts_recv);

    size_t expected = n_expected_pkts(num_rx_stacks, superbufs_to_use, i);
    cmp_ok(pkts_recv, "==", expected,
           "Stack received the expected number of packets.");
    fini(rx_stacks[i], rx_attrs[i]);
  }

  struct emu_stats& stats = emu_stats_update();
  cmp_ok(stats.no_desc_drops, "==", 0, "0 no_desc_drops");
  cmp_ok(stats.sbuf_leaked, "==", false, "no sbufs leaked");

  fini(tx_stack, tx_attr);
  zf_deinit();
  return 2 * num_rx_stacks + // tests for rx stack creation
         1 +                 // Test for packets sent
         num_rx_stacks +     // Test for packets recv
         2;                  // Stats tests
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
  for(const auto &n_sbufs : {8, 16, 32}) {
    for(const auto &n_rx_stacks : {2, 4, 8, 15}) {
      tests += test_wrapper(n_rx_stacks, n_sbufs);
    }
  }

  plan(tests);
  return 0;
}

