/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2018 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  gd
**  \brief  Sanity test for RX demultiplexing.
**   \date  2016/02/03
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>

#include <arpa/inet.h>

#include "../tap/tap.h"
#include "abstract_zocket_pair.h"
#include "zfmultizock.h"


static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
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

  zf_deinit();

  return 0;
}


int main(void)
{
  int rc;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(init(&stack, &attr));
  rc = zfmultizock_test(stack, attr);
  ZF_TRY(fini(stack, attr));

  return rc;
}

