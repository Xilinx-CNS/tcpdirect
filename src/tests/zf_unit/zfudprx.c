/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2020 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mj
**  \brief  zfpingpong application
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

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


/* we should be able to get up to 63~64
 * but fails in mid forties fail for some reason
 * and hism freezes at 40
 */
#define MAX_BATCH 32
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


void sendpkt_direct(struct zfur* ur, struct zfut*, bool expect_rx,
                    uint64_t my_magic)
{
  if( ! expect_rx )
    return;
  pkt_id id = zf_pool_get_free_pkt(&stack->pool);
  char* pktbuf = PKT_BUF_BY_ID(&stack->pool, id);
  memcpy(pktbuf, &my_magic, sizeof(my_magic));
  struct iovec iov = {
    .iov_base = pktbuf,
    .iov_len = sizeof(my_magic),
  };
  struct zf_udp_rx* udp_rx = ZF_CONTAINER(struct zf_udp_rx, handle, ur);
  struct zf_rx* rx = &udp_rx->rx;
  ZF_TEST(zfr_udp_queue_has_space(&rx->ring));
  zfr_pkt_queue(&rx->ring, &iov);
}


void __test(struct zfur* ur, struct zfut* ut, struct zfut* ut_nomatch,
            void (*sendpkt)(struct zfur*, struct zfut*, bool expect_rx,
                            uint64_t mymagic))
{
  uint64_t magic = MAGIC_INIT_VALUE;
  static const int RX_IOVCNT = MAX_BATCH;
  struct {
    struct zfur_msg zcr;
    struct iovec iov[RX_IOVCNT];
  } rd = { { {}, 0, 0, RX_IOVCNT } };

  zfur_zc_recv(ur, &rd.zcr, 0);

  cmp_ok(rd.zcr.iovcnt, "==", 0, "Initially socket is empty(1)");
  ZF_TEST(zf_reactor_perform(stack) == 0);
  cmp_ok(rd.zcr.iovcnt, "==", 0, "Initially socket is empty(2)");

  rd.zcr.iovcnt = RX_IOVCNT;

  if( ut_nomatch != NULL ) {
    /* Send a packet that should not be received.  We will verify the count of
     * received packets to test this. */
    sendpkt(ur, ut_nomatch, false, magic);
  }

  sendpkt(ur, ut, true, magic);

  zfur_zc_recv(ur, &rd.zcr, 0);
  cmp_ok(rd.zcr.iovcnt, "==", 1, "First packet received");
  cmp_ok(rd.iov[0].iov_len, "==", sizeof(magic), "First packet size ok");
  cmp_ok(MAGIC_FROM_RX(rd.iov[0]), "==", magic, "First packet payload ok");
  zfur_zc_recv_done(ur, &rd.zcr);
  ++magic;

  for(int batch = 2; batch < RX_IOVCNT; ++batch) {
    /* release read packets from time to time */
    zf_stack_udp_rx_flush(stack);
    for( int repeat = 0; repeat < 2; repeat++ ) {
      uint64_t base_magic = magic;
      for( int i = 0; i < batch; ++i) {
        sendpkt(ur, ut, true, magic);
        ++magic;
      }

      int total_count = 0;
      uint64_t fail_len = 0;
      uint64_t fail_payload = 0;

      /* If we ever support returning multiple datagrams in single
       * call to zfur_zc_recv() this check could be tightened, but for
       * now we expect it to take up to batch iterations to find all
       * the packets
       */
      for( int iter = 0; iter < batch; ++iter) {
        rd.zcr.iovcnt = RX_IOVCNT;
        zfur_zc_recv(ur, &rd.zcr, 0);
        for( int i = 0; i < rd.zcr.iovcnt; ++i) {
          uint64_t b = (1ull << i) ;
          fail_len |= (rd.iov[i].iov_len != sizeof(magic)) ? b : 0;
          fail_payload |= (MAGIC_FROM_RX(rd.iov[i]) !=
                           base_magic + i + total_count) ? b : 0;
        }
        if( rd.zcr.iovcnt )
          zfur_zc_recv_done(ur, &rd.zcr);
        total_count += rd.zcr.iovcnt;
      }

      cmp_ok(fail_len, "==", 0, "R %d, B %d: pkts len %llx",
             repeat, batch, fail_len);
      cmp_ok(fail_payload, "==", 0,
             "R %d, B %d: pkts payload %llx", repeat, batch, fail_payload);

      cmp_ok(total_count, "==", batch,
             "R %d, B %d: Received expected packet count", repeat , batch);
    }
  }
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
    0,  /* Port, filled in later. */
    { inet_addr("127.0.0.1") },
  };

  struct sockaddr_in raddr_connected = {
    AF_INET,
    htons(2001),
    { inet_addr("192.168.0.1") },
  };

  struct sockaddr_in raddr_other = {
    AF_INET,
    htons(1234),
    { inet_addr("192.168.0.1") },
  };

  struct sockaddr_in* raddrs[] = {&raddr_connected, NULL};

  /* We don't release resources at the time of writing, so bump the port each
   * time. */
  int port = 2002;
  for( uint32_t i = 0; i < sizeof(raddrs) / sizeof(raddrs[0]); ++i ) {
    laddr.sin_port = htons(port++);
    struct zfur* ur = alloc_rx(&laddr, raddrs[i]);
    struct zfut* ut = alloc_tx(&raddr_connected, &laddr);
    /* For the "connected" case, we also introduce a sender whose packets we
     * should not receive. */
    struct zfut* ut_nomatch = raddrs[i] != NULL ?
                              alloc_tx(&raddr_other, &laddr) : NULL;
    __test(ur, ut, ut_nomatch, sendpkt_direct);
    __test(ur, ut, ut_nomatch, sendpkt_shim);
  }
}

#define BIND_DUP_ADDR_TESTS 13
static void test_dup(void)
{
  struct sockaddr_in laddr = {
    AF_INET,
    0,  /* Port, filled in later. */
    { inet_addr("127.0.0.1") },
  };

  struct sockaddr_in raddr = {
    AF_INET,
    0,  /* Port, filled in later. */
    { inet_addr("192.168.0.1") },
  };

  int lport = 2200;
  int rport = 2201;

  /* update rx table with 10 entries with different port numbers */
  for( uint32_t i = 0; i < 5; ++i ) {
    laddr.sin_port = htons(lport++);
    raddr.sin_port = htons(rport++);
    struct zfur* ur;
    cmp_ok(zfur_alloc(&ur, stack, attr),
    "==", 0, "udp rx socket created");
    cmp_ok(zfur_addr_bind(ur, (struct sockaddr*)&laddr, sizeof(laddr),
                          (struct sockaddr*)&raddr, sizeof(raddr), 0),
    "==", 0, "udp rx socket bound");
  }
  /* Now try to bind new socket to the same address used above */
  laddr.sin_port = htons(--lport);
  raddr.sin_port = htons(--rport);
  struct zfur* ur;
  cmp_ok(zfur_alloc(&ur, stack, attr),
  "==", 0, "udp rx socket created");
  cmp_ok(zfur_addr_bind(ur, (struct sockaddr*)&laddr, sizeof(laddr),
                        (struct sockaddr*)&raddr, sizeof(raddr), 0),
  "==", -EADDRINUSE, "socket not bound, duplicate rx table entry");

  /* Now try to unbind from a different address */
  laddr.sin_port = htons(++lport);
  raddr.sin_port = htons(++rport);
  cmp_ok(zfur_addr_unbind(ur, (struct sockaddr*)&laddr, sizeof(laddr),
                          (struct sockaddr*)&raddr, sizeof(raddr), 0),
         "==", -ENOENT, "socket not unbound, rx table entry does not exist");
}

#define REMAIN_IN_RECV_QUEUE 6
static void test_pkts_remain_in_recv_queue(void)
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
  static const unsigned RX_IOVCNT = MAX_BATCH;
  struct {
    struct zfur_msg zcr;
    struct iovec iov[RX_IOVCNT];
  } rd = { { {}, 0, 0, RX_IOVCNT } };

  /* Before sending any packet make sure counter is zero */
  zfur_zc_recv(ur, &rd.zcr, 0);
  cmp_ok(rd.zcr.dgrams_left, "==", 0, "No pkts in recv queue");

  /* Sends 3 packets */
  for( int i = 0; i <= 2; i++ ) {
    sendpkt_shim(ur, ut, 1, magic);
    ++magic;
  }
  /* Receive 1 packet at time to see that left over packets updated
   *  as expected */
  for( int i = 0; i <= 2; ++i ) {
    rd.zcr.iovcnt = 1;
    zfur_zc_recv(ur, &rd.zcr, 0);
    zfur_zc_recv_done(ur, &rd.zcr);
    cmp_ok(rd.zcr.dgrams_left, "==", 2 - i,
            "%d pkts received, remaining in recv queue are %d",
            rd.zcr.iovcnt, rd.zcr.dgrams_left);
   }
}

#define MULTI_LOCAL_RX 13
void test_multi_local_rx()
{
  struct sockaddr_in laddr[3] = {
    {
      AF_INET,
      2220,
      { inet_addr("127.0.0.1") },
    },
    {
      AF_INET,
      2221,
      { inet_addr("127.0.0.1") },
    },
    {
      AF_INET,
      2220,
      { inet_addr("127.0.0.2") },
    },
  };
  struct sockaddr_in raddr = {
    AF_INET,
    2221,
    { inet_addr("192.168.0.1") },
  };

  uint64_t magic = MAGIC_INIT_VALUE;

  struct zfur* ur = alloc_rx(&laddr[0], &raddr);

  ZF_TRY(zfur_addr_bind(ur, (struct sockaddr*)&laddr[1], sizeof(laddr[1]),
                        (struct sockaddr*)&raddr, sizeof(raddr), 0));
  ok(1, "udp rx socket bound to snd address");

  ZF_TRY(zfur_addr_bind(ur, (struct sockaddr*)&laddr[2], sizeof(laddr[2]),
                        NULL, 0, 0));
  ok(1, "udp rx socket bound to snd address");

  struct zfut* ut[5] {
    alloc_tx(&raddr, laddr + 0),
    alloc_tx(&raddr, laddr + 1),
    alloc_tx(&raddr, laddr + 2),
    alloc_tx(laddr + 0, laddr + 2),
    alloc_tx(laddr + 0, laddr + 1), /* this one will be no match */
  };
  static const unsigned RX_IOVCNT = MAX_BATCH;
  struct {
    struct zfur_msg zcr;
    struct iovec iov[RX_IOVCNT];
  } rd = { { {}, 0, 0, RX_IOVCNT } };

  /* Before sending any packet make sure counter is zero */
  zfur_zc_recv(ur, &rd.zcr, 0);
  cmp_ok(rd.zcr.dgrams_left, "==", 0, "No pkts in recv queue");

  for( int i = 0; i < 5; ++i ) {
    sendpkt_shim(ur, ut[i], i < 4, magic);
    ++magic;
  }

  /* check all expected pkts received properly */
  for( int i = 0; i < 4; ++i ) {
    rd.zcr.iovcnt = 1;
    zfur_zc_recv(ur, &rd.zcr, 0);
    cmp_ok(MAGIC_FROM_RX(rd.iov[0]), "==", MAGIC_INIT_VALUE + i,
           "Payload of pkt %d matches", i);
    zfur_zc_recv_done(ur, &rd.zcr);
    cmp_ok(rd.zcr.dgrams_left, "==", 3 - i,
            "%d pkts received, remaining in recv queue are %d",
            rd.zcr.iovcnt, rd.zcr.dgrams_left);
   }
}


void init(void)
{
  ZF_TRY(zf_init());

  ZF_TRY(zf_attr_alloc(&attr));

  /* this test requires loopback shim */
  ZF_TEST(attr->emu == ZF_EMU_LOOPBACK);

  ZF_TRY(zf_stack_alloc(attr, &stack));

  ZF_TRY(NUM_FREE_PKTS(&stack->pool) >= MAX_BATCH);
}


void fini(void)
{
  zf_stack_free(stack);
  zf_attr_free(attr);
  zf_deinit();
}

#define TESTS_PER_EMU  186
#define NUM_EMUS         2  /* Direct post to recvq, and via shim. */
#define NUM_RECV_TYPES   2  /* Remote-address-bound ("connected") and not. */
int main(int argc, char* argv[])
{
  plan((TESTS_PER_EMU * NUM_EMUS * NUM_RECV_TYPES) + BIND_DUP_ADDR_TESTS +
        REMAIN_IN_RECV_QUEUE + MULTI_LOCAL_RX);
  init();
  test();
  test_dup();
  test_pkts_remain_in_recv_queue();
  test_multi_local_rx();
  fini();
  return 0;
}
