/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

/* Basic test to spawn two "applications" that share a queue */

#include "zf_superbuf_helper.h"

int main(int argc, char* argv[])
{
  int pkts_per_superbuf = 512;
  const int superbufs_to_use = 16;
  int rx_ring_max = pkts_per_superbuf * superbufs_to_use;

  struct sockaddr_in laddr = {
    AF_INET,
    1220,
    { inet_addr("127.0.0.1") },
  };

  struct sockaddr_in raddr = {
    AF_INET,
    1221,
    { inet_addr("127.0.0.2") },
  };


  struct zf_stack* stack[3];
  struct zf_attr* attr[3];

  int rc = zf_init();
  if( rc != 0 )
    return rc;

  ZF_TRY(init(&stack[0], &attr[0], ZF_EMU_B2B0, rx_ring_max, 0));
  ZF_TRY(init(&stack[1], &attr[1], ZF_EMU_B2B0, rx_ring_max, 0));
  ZF_TRY(init(&stack[2], &attr[2], ZF_EMU_B2B1, 0, 0));

  struct zfur* ur0 = rx_init(&raddr, &laddr, stack[0], attr[0]);
  struct zfur* ur1 = rx_init(&raddr, &laddr, stack[1], attr[1]);
  struct zfut* ut = tx_init(&laddr, &raddr, stack[2], attr[2]);

  RD rd0 = test_receive_pre_test(ur0, stack[0]);
  RD rd1 = test_receive_pre_test(ur1, stack[1]);

  int pkts_sent = 0;
  int fst_stack_pkts_received = 0;
  int snd_stack_pkts_received = 0;

  for (int i = 0; i < 1; i++) {
    pkts_sent += test_send(8196, stack[2], ut);
    fst_stack_pkts_received += test_receive(&rd0, stack[0], ur0, pkts_sent);
    snd_stack_pkts_received += test_receive(&rd1, stack[1], ur1, pkts_sent);
    printf("pkts_send %d, pkts_received_fst_stack %d, snd_received_snd_stack %d\n", pkts_sent, fst_stack_pkts_received, snd_stack_pkts_received );
  }

  cmp_ok(pkts_sent, "==", fst_stack_pkts_received, "First stack received all pkts");
  cmp_ok(pkts_sent, "==", snd_stack_pkts_received, "Second stack received all pkts");

  struct emu_stats& stats = emu_stats_update();
  cmp_ok(stats.no_desc_drops, "==", 0, "0 no_desc_drops");
  cmp_ok(stats.sbuf_leaked, "==", false, "no sbufs leaked");
  
  fini(stack[0], attr[0]);
  fini(stack[1], attr[1]);
  fini(stack[2], attr[2]);

  plan(8);
  zf_deinit();
  return 0;
}

