/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

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
#include <zf_internal/private/zf_emu.h>

#include <inttypes.h>



#define MAGIC_INIT_VALUE 0xF0F1F2F3F4F50000llu
#define MAGIC_FROM_RX(iov) (*((const uint64_t*)(((const char*)(iov).iov_base))))

static const unsigned RX_IOVCNT = 1; //we only need 1

typedef struct {
  struct zfur_msg zcr;
  struct iovec iov[RX_IOVCNT];
} RD;


static int sendpkt_shim(struct zfut* ut, uint64_t my_magic, zf_stack* tx_stack)
{
  int rc;
  do {
    rc = zfut_send_single(ut, &my_magic, sizeof(my_magic));
    zf_reactor_perform(tx_stack);
  } while (  rc <= 0 );
  return rc;
}


static struct zfut*
tx_init(const struct sockaddr_in* saddr, const struct sockaddr_in* daddr, zf_stack* tx_stack, zf_attr* tx_attr)
{
  struct zfut* ut;
  ZF_TRY(zfut_alloc(&ut, tx_stack, (const struct sockaddr*)saddr, sizeof(*saddr),
                    (const struct sockaddr*)daddr, sizeof(*daddr), 0, tx_attr));
  return ut;
}

static struct zfur*
rx_init(struct sockaddr_in* laddr, const struct sockaddr_in* raddr, zf_stack* rx_stack, zf_attr* rx_attr)
{
  struct zfur* ur;

  ZF_TRY(zfur_alloc(&ur, rx_stack, rx_attr));
  ok(1, "udp rx socket created");

  ZF_TRY(zfur_addr_bind(ur, (struct sockaddr*)laddr, sizeof(*laddr),
                        (struct sockaddr*)raddr, sizeof(*raddr), 0));
  ok(1, "udp rx socket bound");

  return ur;
}

static RD test_receive_pre_test(zfur* ur, zf_stack* rx_stack)
{

  RD rd = { { {}, 0, 0, RX_IOVCNT } };

  /* Before sending any packet make sure counter is zero */
  zfur_zc_recv(ur, &rd.zcr, 0);
  cmp_ok(rd.zcr.dgrams_left, "==", 0, "");
  cmp_ok(rd.zcr.iovcnt, "==", 0, "");
  ZF_TEST(zf_reactor_perform(rx_stack) == 0);
  cmp_ok(rd.zcr.iovcnt, "==", 0, "");
  return rd;
}

static int test_receive(RD* rd, zf_stack* rx_stack, zfur* ur, int expected_pkts)
{
  uint64_t magic = MAGIC_INIT_VALUE;
  static const unsigned RX_IOVCNT = 1; //we only need 1

  cmp_ok(rd->zcr.iovcnt, "==", 0, "");

  int pkts_received = 0;
  for( int i = 0; i < expected_pkts; i++ ) {
    rd->zcr.iovcnt = RX_IOVCNT;
    zf_reactor_perform(rx_stack);
    while(1){
      zfur_zc_recv(ur, &rd->zcr, 0);
      if ( rd->zcr.iovcnt > 0 ) {
        cmp_ok(rd->iov[0].iov_len, "==", sizeof(magic), "");
        cmp_ok(MAGIC_FROM_RX(rd->iov[0]), "==", magic, "");
        pkts_received += rd->zcr.iovcnt;
        zfur_zc_recv_done(ur, &rd->zcr);
      } else {
        break;
      }
    }
  }

  return pkts_received;
}

static int test_send(int cnt, zf_stack* tx_stack, zfut* ut)
{
  uint64_t magic = MAGIC_INIT_VALUE;
  /* Send enough packets to fill all superbufs to trigger reuse
     Assumptions:
     (a) 512 pkts/superbuf,
     (b) 4 superbufs in use,
     (c) 16 entries in the shared-memory queue
  */
  int pkts_sent = 0;
  for( int i = 0; i < cnt; i++ ) {
    if ( sendpkt_shim(ut, magic, tx_stack) > 0 )
      pkts_sent++;
  }
  return pkts_sent;
}

static int init(struct zf_stack** stack_out, struct zf_attr** attr_out, const char* interface, int rx_ring_max, int n_bufs)
{
  int rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  ZF_TRY(zf_attr_set_str(*attr_out, "interface", interface));
  ZF_TRY(zf_attr_set_int(*attr_out, "rx_ring_max", rx_ring_max));
  ZF_TRY(zf_attr_set_int(*attr_out, "n_bufs", n_bufs));

  rc = zf_stack_alloc(*attr_out, stack_out);
  if( rc != 0 ) {
    zf_attr_free(*attr_out);
    return rc;
  }

  return 0;
}

static int fini(struct zf_stack* stack, struct zf_attr* attr)
{
  int rc;

  rc = zf_stack_free(stack);
  if( rc != 0 )
    return rc;
  zf_attr_free(attr);

  zf_deinit();

  return 0;
}

void init_stacks(struct zf_stack* rx_stacks[],
                        struct zf_attr* rx_attrs[],
                        struct zfur* urs[], RD rds[],
                        size_t num_rx_stacks, size_t rxq_size,
                        bool do_rollover_initial_sbufs,
                        struct zf_stack** tx_stack, zf_attr **tx_attr,
                        struct zfut** ut)
{
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

  for(size_t i = 0; i < num_rx_stacks; i++) {
    ZF_TRY(init(&rx_stacks[i], &rx_attrs[i], ZF_EMU_B2B0, rxq_size, 0));
    urs[i] = rx_init(&raddr, &laddr, rx_stacks[i], rx_attrs[i]);
    /* This will poll each stack which has already been initialised.
     * We need to do this because each stack creation will
     * cause the driver to post 4 new sbufs which will be rolled
     * over once the next set of 4 sbufs are posted. If the rolled
     * over sbufs are not polled, the stack will fall behind on buffers
     * which won't even have any packets sent to them. */
    for(size_t j = do_rollover_initial_sbufs ? 0 : i; j <= i; j++) {
      rds[j] = test_receive_pre_test(urs[j], rx_stacks[j]);
    }
  }

  ZF_TRY(init(tx_stack, tx_attr, ZF_EMU_B2B1, 0, 0));
  *ut = tx_init(&laddr, &raddr, *tx_stack, *tx_attr);
}

void fini_stacks(struct zf_stack* rx_stacks[], struct zf_attr* rx_attrs[],
                 size_t num_rx_stacks, struct zf_stack* tx_stack,
                 struct zf_attr* tx_attr) {
  for(size_t i = 0; i < num_rx_stacks; i++) {
    fini(rx_stacks[i], rx_attrs[i]);
  }
  fini(tx_stack, tx_attr);
}

