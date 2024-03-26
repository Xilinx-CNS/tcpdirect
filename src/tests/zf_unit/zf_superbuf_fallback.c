/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

/* Test to see if applications buffer packets properly when sleeping */

#include <initializer_list>
#include "zf_superbuf_helper.h"

static const size_t pkts_per_sbuf = 512;

static size_t n_expected_pkts(size_t num_rx_stacks, size_t superbufs_to_use)
{
  size_t pkts = 0;
  if (num_rx_stacks == 1 && superbufs_to_use <= 16) {
    /* Number of sbufs sent can fit into the shm_q */
    pkts =  num_rx_stacks * superbufs_to_use * pkts_per_sbuf;
  } else {
    /* Driver will try to post 4 (by default but configurable) sbufs it hasn't yet
     * written to; meaning a sleeping app will begin to skip sbufs once more than
     * its rxq size - 4sbufs of packets have been sent.*/
    pkts = pkts_per_sbuf * (num_rx_stacks * superbufs_to_use - 4) - 1;
  }
  return pkts;
}

static size_t n_expected_pkts_no_rollover(const size_t num_rx_stacks, 
                                          const size_t superbufs_to_use,
                                          const size_t stack_no)
{
  const size_t sbufs_donated = num_rx_stacks * superbufs_to_use;
  const size_t sbufs_rolled_over = (num_rx_stacks - 1) * 4;
  return (sbufs_donated - sbufs_rolled_over - 4 * (stack_no + 1))
          * pkts_per_sbuf - 1;
}

static int test(size_t num_rx_stacks, size_t superbufs_to_use, bool do_rollover_initial_sbufs)
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
              do_rollover_initial_sbufs, &tx_stack, &tx_attr, &ut);

  size_t pkts_sent = test_send(rxq_size * num_rx_stacks, tx_stack, ut);
  cmp_ok(pkts_sent, "==", rxq_size * num_rx_stacks,
         "Sent the expected number of pkts.");

  for(size_t i = 0; i < num_rx_stacks; i++) {
    size_t pkts_recv = test_receive(&rds[i], rx_stacks[i], urs[i], pkts_sent);
    printf("pkts_sent: %zu, pkts_received: %zu\n", pkts_sent, pkts_recv);

    size_t expected = do_rollover_initial_sbufs ?
                        n_expected_pkts(num_rx_stacks, superbufs_to_use) :
                        n_expected_pkts_no_rollover(num_rx_stacks, superbufs_to_use, i);
    cmp_ok(pkts_recv, "==", expected,
           "Stack received the expected number of packets.");
  }

  struct emu_stats& stats = emu_stats_update();
  cmp_ok(stats.no_desc_drops, "==", 0, "0 no_desc_drops");
  cmp_ok(stats.sbuf_leaked, "==", false, "no sbufs leaked");

  fini_stacks(rx_stacks, rx_attrs, num_rx_stacks, tx_stack, tx_attr);
  zf_deinit();
  return 2 * num_rx_stacks + // tests for rx stack creation
         1 +                 // Test for packets sent
         num_rx_stacks +     // Test for packets recv
         2;                  // Stats tests
}

int test_wrapper(size_t n_rx_stacks, size_t n_sbufs, bool do_rollover_initial_sbufs)
{
  printf("\t------------Testing %zu stacks each with %zu sbufs------------\n",
       n_rx_stacks, n_sbufs);
  int tests = test(n_rx_stacks, n_sbufs, do_rollover_initial_sbufs);
  cmp_ok(tests, ">=", 0, "");
  return tests;
}

int main(int argc, char* argv[])
{
  int tests = 0;
  for(const auto &do_rollover_initial : {true}) {
    /* We leave out the case where n_sbufs == 1 because a full hugepage
     * will be donated in reality which is equivalent to haveing 2 sbufs. */
    for(const auto &n_sbufs : {2, 4, 8, 16, 32}) {
      for(const auto &n_rx_stacks : {1, 2, 4, 8, 15}) {
        /* It is impractical to test the case where there are fewer than
         * 4 sbufs donated and there are multiple stacks. This is because
         * zf_emu won't be able to post the 2nd stack's 4 initial sbufs
         * since the 1st stack won't have given it's 4 up and there are
         * 6 in total in the pool - it will only be able to post 2 for the
         * later stack. */
        if(n_rx_stacks == 1 || (n_rx_stacks * n_sbufs > 4)) {
          tests += test_wrapper(n_rx_stacks, n_sbufs, do_rollover_initial);
        }
      }
    }
  }
  plan(tests);
  return 0;
}

