/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2021 Advanced Micro Devices, Inc. */
/* Tests creation of TX-only and RX-only stacks and that failures occur
gracefully if the disabled direction is used.*/

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
#include <zf_internal/private/zf_stack_def.h>

#include "../tap/tap.h"

#include "abstract_zocket_pair.h"

static int init(struct zf_stack** stack_out, struct zf_attr** attr_out, const char* interface, const char* ring_max)
{

  int rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  ZF_TEST((*attr_out)->emu == ZF_EMU_BACKTOBACK);

  ZF_TRY(zf_attr_set_str(*attr_out, "interface", interface));

  /* Disables the RX or TX path depending on which ring_max is set to 0 */
  ZF_TRY(zf_attr_set_int(*attr_out, ring_max, 0)); 

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

static void send_recv_test(struct zf_stack* tx_stack,struct zf_stack* rx_stack, struct abstract_zocket_pair* zocks) {
  ZF_TRY(zocks->send(zocks->opaque_tx, 'l'));
  while( zf_reactor_perform(rx_stack) == 0 )
    zf_reactor_perform(tx_stack);

  char abuf;
  ZF_TRY(zocks->recv(zocks->opaque_rx, &abuf, 1));

  cmp_ok(abuf, "==", 'l', "Received one packet on RX zocket");
}

static void tcp_alloc_test(struct zf_stack* tx_stack, struct zf_stack* rx_stack, struct zf_attr* attr) {
  
  struct zft_handle* handle;
  cmp_ok(zft_alloc(tx_stack, attr, &handle), "==", -EINVAL, "Fails when trying to create TCP zocket in stack with RX disabled");
  cmp_ok(zft_alloc(rx_stack, attr, &handle), "==", -EINVAL, "Fails when trying to create TCP zocket in stack with TX disabled");

}

static int test(struct zf_stack* stacks[], struct zf_attr* attr[])
{

  plan(5);

  struct abstract_zocket_pair zockets;

  /* Expected to fail as first arg should be RX stack not TX stack */
  dies_ok({alloc_udp_pair(stacks[1], stacks[0], attr[0], &zockets);}, "Fails when trying to create RX zocket in TX stack and vice-versa");

  /* Should work this way round */
  lives_ok({alloc_udp_pair(stacks[0], stacks[1], attr[0], &zockets);}, "Creates RX/TX zocket on RX/TX stack");

  send_recv_test(stacks[1], stacks[0], &zockets);

  tcp_alloc_test(stacks[1], stacks[0], attr[0]);

  return 0;
}

#define NUM_TESTS 1
int main(void)
{
  /* One stack for RX and one for TX */
  struct zf_stack* stacks[2];
  struct zf_attr* attrs[2];

  /* RX only stack */
  ZF_TRY(init(&stacks[0], &attrs[0], ZF_EMU_B2B0, "tx_ring_max"));
  /* TX only stack */
  ZF_TRY(init(&stacks[1], &attrs[1], ZF_EMU_B2B1, "rx_ring_max"));
  int rc = test(stacks, attrs);
  done_testing();
  ZF_TRY(fini(stacks[1], attrs[1]));
  ZF_TRY(fini(stacks[0], attrs[0]));

  return rc;
}
