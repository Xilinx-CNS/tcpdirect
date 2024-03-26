/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

/* unit test that sends enough packets to fill all superbufs */

#include <zf/zf.h>
#include <zf_internal/utils.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <netinet/udp.h>

#include "../tap/tap.h"


#include <zf_internal/attr.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/private/zf_stack_rx.h>

#include <inttypes.h>

#define MAGIC_INIT_VALUE 0xF0F1F2F3F4F50000llu
#define MAGIC_FROM_RX(iov) (*((const uint64_t*)(((const char*)(iov).iov_base))))


struct zf_stack* stack;
struct zf_attr* attr;


void sendpkt_shim(struct zfur*, struct zfut* ut, bool expect_rx,
                  uint64_t my_magic)
{
  /* This uses udp tx to sent to our rx socket over loopback shim
   * This relies on udp send, shim and rx demux working */
  ZF_TRY(zfut_send_single(ut, &my_magic, sizeof(my_magic)));
  if( expect_rx )
    while( zf_reactor_perform(stack) == 0 )
      ;
}


static struct zfut*
alloc_tx(const struct sockaddr_in* saddr, const struct sockaddr_in* daddr)
{
  struct zfut* ut;
  ZF_TRY(zfut_alloc(&ut, stack, (const struct sockaddr*)saddr, sizeof(*saddr),
                    (const struct sockaddr*)daddr, sizeof(*daddr), 0, attr));
  return ut;
}

static struct zfur*
alloc_rx(struct sockaddr_in* laddr, const struct sockaddr_in* raddr)
{
  struct zfur* ur;

  ZF_TRY(zfur_alloc(&ur, stack, attr));
  ok(1, "udp rx socket created");

  ZF_TRY(zfur_addr_bind(ur, (struct sockaddr*)laddr, sizeof(*laddr),
                        (struct sockaddr*)raddr, sizeof(*raddr), 0));
  ok(1, "udp rx socket bound");

  return ur;
}

static void test(void)
{

  struct sockaddr_in laddr = {
    AF_INET,
    1220,
    { inet_addr("127.0.0.1") },
  };

  struct sockaddr_in raddr = {
    AF_INET,
    1221,
    { inet_addr("192.168.0.1") },
  };

  uint64_t magic = MAGIC_INIT_VALUE;

  struct zfur* ur = alloc_rx(&laddr, &raddr);
  struct zfut* ut = alloc_tx(&raddr, &laddr);
  static const unsigned RX_IOVCNT = 1; //we only need 1

  struct {
    struct zfur_msg zcr;
    struct iovec iov[RX_IOVCNT];
  } rd = { { {}, 0, 0, RX_IOVCNT } };

  /* Before sending any packet make sure counter is zero */
  zfur_zc_recv(ur, &rd.zcr, 0);
  cmp_ok(rd.zcr.dgrams_left, "==", 0, "No pkts in recv queue");
  cmp_ok(rd.zcr.iovcnt, "==", 0, "Initially socket is empty(1)");
  ZF_TEST(zf_reactor_perform(stack) == 0);
  cmp_ok(rd.zcr.iovcnt, "==", 0, "Initially socket is empty(2)");

  /* Send enough packets to fill all superbufs to trigger reuse
     Assumptions: 
     (a) 512 pkts/superbuf, 
     (b) 4 superbufs in use, 
     (c) 16 entries in the shared-memory queue
  */
  int pkts_per_superbuf = 512;
  int entries_per_rxq = 16; // this is greater than the number of superbufs in use.
  bool passed = true;
  for( int i = 0; i <= pkts_per_superbuf * entries_per_rxq * 2 + 1; i++ ) {
    sendpkt_shim(ur, ut, true, magic);
    rd.zcr.iovcnt = RX_IOVCNT;
    zfur_zc_recv(ur, &rd.zcr, 0);
    passed &= rd.zcr.iovcnt == 1;
    if(!passed)
      diag("! packet %04d received", i);
    passed &= rd.iov[0].iov_len == sizeof(magic);
    if(!passed)
      diag("! packet %04d size ok", i);
    passed &= MAGIC_FROM_RX(rd.iov[0]) == magic;
    if(!passed)
      diag("! packet %04d payload ok", i);
    zfur_zc_recv_done(ur, &rd.zcr);
    if( !passed )
      break;
    ++magic;
  }
  ok(passed, "Traffic passed");
  plan(
    2 + // alloc_rx
    3 + // before the loop
    1 // the loop outcome
    );
}


void init(void)
{
  ZF_TRY(zf_init());

  ZF_TRY(zf_attr_alloc(&attr));

  /* this test requires loopback shim */
  ZF_TEST(attr->emu == ZF_EMU_LOOPBACK);

  ZF_TRY(zf_stack_alloc(attr, &stack));

}


void fini(void)
{
  zf_stack_free(stack);
  zf_attr_free(attr);
  zf_deinit();
}

int main(int argc, char* argv[])
{
  init();
  test();
  fini();
  return 0;
}
