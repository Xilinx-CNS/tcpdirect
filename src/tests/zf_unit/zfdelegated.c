/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2020-2020 Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/tcp.h>
#include <zf_internal/private/zf_emu.h>

#include <arpa/inet.h>
#include <unistd.h>

#include "abstract_zocket_pair.h"
#include "../tap/tap.h"


static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

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

  return 0;
}


static void open_window(struct zf_stack* stack,
                        struct abstract_zocket_pair* zocks)
{
  char send = 'a';
  char recv;

  for( int i = 0; i < 200; i++ ) {
    ZF_TRY(zocks->send(zocks->opaque_tx, send));

    while( zf_reactor_perform(stack) == 0 );
    while( zf_reactor_perform(stack) != 0 );

    ZF_TRY(zocks->recv(zocks->opaque_rx, &recv, 1));
  }
}


static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  struct abstract_zocket_pair zocks;
  struct zf_ds ds;
  size_t send_space;
  char* send_buf;
  char headers[128];

  plan(8);

  auto nop = [] {}; /* lambda expression doing nothing */
  alloc_tcp_pair_t(stack, stack, attr, &zocks, nop);
  struct zft* send_zock = (zft*)zocks.opaque_tx;
  struct zft* recv_zock = (zft*)zocks.opaque_rx;

  ok(1, "Socket connected");

  /* Ensure that we have enough send window that it doesn't limit our
   * delegated sends. */
  open_window(stack, &zocks);

  /* Firstly do a delegated send that fills the send queue */
  ZF_TRY(zft_send_space(send_zock, &send_space));
  ds.headers = headers;
  ds.headers_size = sizeof(headers);

  cmp_ok(zf_delegated_send_prepare(send_zock, send_space, 0, 0, &ds), "==",
         ZF_DELEGATED_SEND_RC_OK, "fill send queue prepare");
  cmp_ok(ds.delegated_wnd, "==", send_space, "full ds window available");

  ZF_TEST(send_buf = (char*)malloc(send_space));
  struct iovec iov = {
    .iov_base = send_buf,
    .iov_len = send_space,
  };
  cmp_ok(zf_delegated_send_complete(send_zock, &iov, 1, 0), "==",
         send_space, "fill send queue complete");

  /* Now we should see that our send queue is full, so any size of prepare
   * should fail.
   */
  ZF_TRY(zft_send_space(send_zock, &send_space));
  cmp_ok(send_space, "==", 0, "check send queue is full");
  cmp_ok(zf_delegated_send_prepare(send_zock, 1, 0, 0, &ds), "==",
         ZF_DELEGATED_SEND_RC_SENDQ_BUSY, "busy send queue prepare");

  cmp_ok(zft_state(send_zock), "==", TCP_ESTABLISHED,
         "tx zocket is still ok");
  cmp_ok(zft_state(recv_zock), "==", TCP_ESTABLISHED,
         "rx zocket is still ok");
  zft_shutdown_tx(recv_zock);
  zft_shutdown_tx(send_zock);
  zft_free(recv_zock);
  zft_free(send_zock);
  return 0;
}

int main(void)
{
  int rc;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(zf_init());

  ZF_TRY(init(&stack, &attr));
  rc = test(stack, attr);
  ZF_TRY(fini(stack, attr));

  zf_deinit();

  return rc;
}

