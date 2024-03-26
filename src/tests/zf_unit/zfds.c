/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2018 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  kjm
**  \brief  Unit test for parts of ZF delegated send API
**   \date  2016/01/07
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include "abstract_zocket_pair.h"
#include "../tap/tap.h"

static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc;
  rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

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

static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  char data[] = "Hi";
  char recv[10];
  int i;
  struct zf_ds ds;
  struct abstract_zocket_pair tcp_zockets;
  char headers[128];

  plan(41);

  alloc_tcp_pair(stack, attr, &tcp_zockets);

  /* NB This test doesn't send any data using the delegated send API.
   * It tests that data can be sent using the normal API after the
   * delegated send API has been used to prepare and cancel a ds send
   */

  i = 10;
  do {
    /* Send data on TCP sockets */
    cmp_ok(tcp_zockets.send(tcp_zockets.opaque_tx, data[1]), "==", 0);

    ds.headers = headers;
    ds.headers_size = sizeof(headers);
    cmp_ok(zf_delegated_send_prepare((struct zft*)tcp_zockets.opaque_tx,
                                     10000, 0, 0, &ds), "==",
           ZF_DELEGATED_SEND_RC_OK);

    /* Allow time for the events */
    usleep(100);
    while(zf_reactor_perform(stack) != 0);

    /* Receive the data send before the delegated send was prepared */
    cmp_ok(tcp_zockets.recv(tcp_zockets.opaque_rx, recv, 10), "==", 1);
    /* Cancel the pending delegated send */
    cmp_ok(zf_delegated_send_cancel((struct zft*)tcp_zockets.opaque_tx),
           "==", ZF_DELEGATED_SEND_RC_OK);
  } while (--i > 0);

  /* Bug80929: check that a large requested window doesn't get
   * truncated to zero */
  ds.headers = headers;
  ds.headers_size = sizeof(headers);
  ZF_TRY(zf_delegated_send_prepare((struct zft*)tcp_zockets.opaque_tx,
                                   0x10000000, 1, 0, &ds));
  cmp_ok(ds.delegated_wnd, ">", 0);
  zf_delegated_send_cancel((struct zft*)tcp_zockets.opaque_tx);

  done_testing();

  return 0;

}


int main(void)
{
  int rc;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(init(&stack, &attr));
  rc = test(stack, attr);
  ZF_TRY(fini(stack, attr));

  return rc;
}
