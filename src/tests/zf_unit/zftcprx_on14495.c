/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2023-2023 Advanced Micro Devices, Inc. */
#include <arpa/inet.h>

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/private/zf_emu.h>
#include <zf_internal/rx_res.h>

#include <zf_internal/private/tcp_fast.h>
#include <zf_internal/zf_stack.h>

#include "../tap/tap.h"

#include "abstract_zocket_pair.h"

#include "dataverifier.h"

static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  /* Request the default allocation of buffers explicitly. */
  zf_attr_set_int(*attr_out, "n_bufs", 0);

  /* This test requires the loopback shim. */
  ZF_TEST((*attr_out)->emu == ZF_EMU_LOOPBACK);

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


#define MAX_SEND_BYTES 1024
static int send_bytes(struct zf_stack* stack, struct zft* tx, size_t n)
{
  char bytes[MAX_SEND_BYTES];
  struct iovec iov;

  verifier.fillWBuf(bytes,n);

  iov.iov_base = bytes;
  iov.iov_len = n;

  cmp_ok(zft_send(tx, &iov, 1, 0), "==", n, "Done send of size %d", n);
  verifier.accountWritten(n);
  return 0;
}

/* Test whether tcpdirect will successfully drop a packet with a bad tcp header
 * Currently only tests for a too small header size. */
static int test_ON_14495(struct zf_stack* stack, struct zf_attr* attr)
{
  struct abstract_zocket_pair zockets1;
  struct abstract_zocket_pair zockets2;

  alloc_tcp_pair(stack, attr, &zockets1);
  alloc_tcp_pair(stack, attr, &zockets2);
  auto tx1 = (struct zft*) zockets1.opaque_tx;
  auto rx1 = (struct zft*) zockets1.opaque_rx;
  auto tx2 = (struct zft*) zockets2.opaque_tx;
  auto rx2 = (struct zft*) zockets2.opaque_rx;

  /* Get a pointer to a tcphdr used when sending packets */
  struct zf_tcp* tcp_tx = (struct zf_tcp*)tx1;
  struct tcphdr* tcp_hdr = ! zf_tx_do_vlan(&tcp_tx->tst) ?
                              &tcp_tx->tst.pkt.tcp_novlanhdr.tcp :
                              &tcp_tx->tst.pkt.tcp_vlanhdr.tcp;

  /* Decrease the tcp header length below the minimum value (5) */
  tcp_hdr->doff = 4;
  send_bytes(stack, tx1, 50);

  /* This doesn't fully test that an event isn't generated, because we don't
   * know that without waiting forever, but we can at least sanity check. */
  cmp_ok(zf_reactor_perform(stack), "==", 0, "No event for bad packet");

  /* Do a normal send on our other pair. */
  send_bytes(stack, tx2, 24);

  /* We should have an event here, so we can spin until it turns up. */
  while(zf_reactor_perform(stack) == 0);
  while(zf_reactor_perform(stack) != 0);

  char buffer[100];
  struct iovec iov = { buffer, sizeof(buffer) };
  int iovcnt = 1;
  int rc = 0;
  rc = zft_recv(rx1, &iov, iovcnt, 0);

  /* If recv return a negative value then there was nothing to read, so since
   * the expectation is that the packet is dropped with a bad tcp header length
   * a negative value indicates that rx has nothing to read and thus tcpdirect
   * has the expected behaviour. */
  cmp_ok(rc, "<", 0, "Error code on read");

  /* We aren't expecting to pick up the first 50 bytes we wrote, so ignore
   * them when verifying later sends. */
  verifier.accountRead(50);

  rc = zft_recv(rx2, &iov, iovcnt, 0);
  /* We expect that the first 50 byte packet has been dropped, but we should
   * still be able to receive the follow up 24 byte packet. */
  cmp_ok(rc, "==", 24, "Received valid packet");
  ok(verify_iov(&iov, 24), "Valid packet data ok");

  return 6;
}

int main(void)
{
  int test_count = 0;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(init(&stack, &attr));
  test_count += test_ON_14495(stack, attr);
  ZF_TRY(fini(stack, attr));

  plan(test_count);

  done_testing();
}

