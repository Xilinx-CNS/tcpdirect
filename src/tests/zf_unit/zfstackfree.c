/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2019 Advanced Micro Devices, Inc. */
/* Tests repeated stack creation and destruction in the presence of zockets. */


#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/attr.h>
#include <zf_internal/private/zf_hal.h>

#include <arpa/inet.h>

#include "abstract_zocket_pair.h"
#include "../tap/tap.h"


static int init(struct zf_attr** attr_out)
{
  int rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  /* This test requires the loopback shim. */
  ZF_TEST((*attr_out)->emu == ZF_EMU_LOOPBACK);

  return 0;
}


static int fini(struct zf_attr* attr)
{
  zf_attr_free(attr);

  zf_deinit();

  return 0;
}

#define NUM_TESTS       1
#define NUM_ITERATIONS  1000

static int test(struct zf_attr* attr)
{
  plan(NUM_TESTS);

  /* Lambda expression doing nothing. */
  auto nop = [] {};

  for( int i = 0; i < NUM_ITERATIONS; ++i ) {
    zf_stack* stack;
    struct zftl* listener;
    struct abstract_zocket_pair tcp_pair;
    struct abstract_zocket_pair udp_pair;

    ZF_TRY(zf_stack_alloc(attr, &stack));

    /* Allocate some zockets so that stack-destruction is non-trivial. */
    alloc_tcp_pair_listener(stack, attr, &listener);
    alloc_tcp_pair_t(stack, stack, attr, &tcp_pair, nop, listener);
    alloc_udp_pair(stack, attr, &udp_pair);

    {
      /* non-connected unbound tcp */
      struct zft_handle* tcp_handle;
      ZF_TRY(zft_alloc(stack, attr, &tcp_handle));
    }

    {
      /* non-connected bound tcp */
      struct zft_handle* tcp_handle;
      struct sockaddr_in laddr = {
        AF_INET,
        /* 1. Use port outside ephemeral port range.
         * 2. Cycle through small number of ip ports/addresses for variety */
        htons(2999 + (i & 1)),
        { inet_addr("127.0.0.3") ^ htonl(i & 2) },
      };
      ZF_TRY(zft_alloc(stack, attr, &tcp_handle));
      ZF_TRY(zft_addr_bind(tcp_handle, (sockaddr*) &laddr, sizeof(laddr), 0));
    }

    ZF_TRY(zf_stack_free(stack));
  }

  ok(1, "Survived!");

  done_testing();
}


int main(void)
{
  int rc;
  struct zf_attr* attr;

  ZF_TRY(init(&attr));
  rc = test(attr);
  ZF_TRY(fini(attr));

  return rc;
}

