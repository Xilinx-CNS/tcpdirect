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

static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  struct abstract_zocket_pair zockets;

  alloc_tcp_pair(stack, attr, &zockets);
  auto tx = (struct zft*) zockets.opaque_tx;
  auto rx = (struct zft*) zockets.opaque_rx;

  struct zf_muxer_set* mux;
  struct epoll_event ev = {
    .events = EPOLLIN | EPOLLRDHUP | EPOLLHUP,
    .data = { .u32 = 0 },
  };
  ZF_TRY(zf_muxer_alloc(stack, &mux));
  ZF_TRY(zf_muxer_add(mux, zft_to_waitable(rx), &ev));

  send_bytes(stack, tx, 50);

  int rc = zf_muxer_wait(mux, &ev, 1, -1);
  cmp_ok(rc, "==", 1, "Received one event from muxer");
  cmp_ok(ev.events, "==", EPOLLIN, "Got EPOLLIN for RX data");

  char buffer[100];
  struct iovec iov = { buffer, sizeof(buffer) };
  int iovcnt = 1;
  rc = zft_recv(rx, &iov, iovcnt, 0);
  cmp_ok(rc, "==", 50, "Received valid packet");
  ok(verify_iov(&iov, 50), "Valid packet data ok");

  rc = zft_shutdown_tx(tx);
  cmp_ok(rc, "==", 0, "Shutdown TX zock for TX ok");

  rc = zf_muxer_wait(mux, &ev, 1, -1);
  cmp_ok(rc, "==", 1, "Received one event from muxer");
  cmp_ok(ev.events, "==", EPOLLIN | EPOLLRDHUP, "Got RDHUP after peer close");

  rc = zft_shutdown_tx(rx);
  rc = zf_muxer_wait(mux, &ev, 1, -1);
  cmp_ok(rc, "==", 1, "Received one event from muxer");
  cmp_ok(ev.events, "==", EPOLLIN | EPOLLRDHUP | EPOLLHUP, "Got HUP + RDHUP after close");

  return 10;
}

int main(void)
{
  int test_count = 0;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(init(&stack, &attr));
  test_count += test(stack, attr);
  ZF_TRY(fini(stack, attr));

  plan(test_count);

  done_testing();
}

