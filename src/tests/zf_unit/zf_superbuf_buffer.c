/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

/* This test is designed to send exactly the amount of packets to precisely
 * fill all the usable buffers of an application. */

#include "zf_superbuf_helper.h"


int main(int argc, char* argv[])
{
  int pkts_per_superbuf = 512;
  int superbufs_alloced = 6;
  int superbufs_in_use = superbufs_alloced - 2;
  int to_send = pkts_per_superbuf * superbufs_in_use;
  int rx_ring_max = to_send;
  int n_bufs = 0;


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

  int rc = zf_init();
  if( rc != 0 )
    return rc;

  struct zf_stack* stack[2];
  struct zf_attr* attr[2];

  ZF_TRY(init(&stack[0], &attr[0], ZF_EMU_B2B0, rx_ring_max, n_bufs));
  ZF_TRY(init(&stack[1], &attr[1], ZF_EMU_B2B1, rx_ring_max, n_bufs));

  struct zfur* ur = rx_init(&raddr, &laddr, stack[0], attr[0]);
  struct zfut* ut = tx_init(&laddr, &raddr, stack[1], attr[1]);

  RD rd = test_receive_pre_test(ur, stack[0]);

  int pkts_sent = test_send(to_send, stack[1], ut);
  if ( pkts_sent == to_send ) {
    ok(1, "%d, Packets sent", pkts_sent);
    int pkts_received = test_receive(&rd, stack[0], ur, pkts_sent);
    if ( pkts_received > 0 ) {
      ok(1, "%d Packets received on the other side", pkts_received);
      struct zf_udp_rx* udp_rx = ZF_CONTAINER(struct zf_udp_rx, handle, ur);
      int dropped_packets = udp_rx->counters.q_drops;

      if ( (pkts_received + dropped_packets) == pkts_sent ) {
        ok(1, "Buffer handling behaving adequately! Seen %d, Dropped %d, Received %d",
           pkts_sent, dropped_packets, pkts_received);
      } else {
        ok(0, "Test failed Packets went missing! (S, D, R) - Got (%d, %d, %d)", pkts_sent, dropped_packets, pkts_received);
      }
    } else {
      ok(0, "Test failed, not enough packets received on the other side! %d", pkts_received);
    }
  } else {
    ok(0, "Test failed, not enough packets sent to the other side! %d", pkts_sent);
  }


  plan(5);
  fini(stack[0], attr[0]);
  fini(stack[1], attr[1]);

  zf_deinit();
  return 0;
}

